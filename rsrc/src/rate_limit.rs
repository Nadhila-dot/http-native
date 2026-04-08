use dashmap::DashMap;
use std::collections::VecDeque;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

const NAMESPACE_SEPARATOR: char = '\u{1f}';
const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;
const EVICTION_TARGET_RATIO: f64 = 0.8;
const EVICT_STALE_THRESHOLD_MS: u64 = 3_600_000; // 1 hour

#[derive(Debug, Clone)]
pub struct RateLimitDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_at_ms: u64,
    pub retry_after_secs: u64,
    pub now_ms: u64,
}

#[derive(Debug, Default)]
struct SlidingWindowState {
    events: VecDeque<(u64, u32)>,
    total: u32,
    last_seen_ms: u64,
}

impl SlidingWindowState {
    fn prune_expired(&mut self, now_ms: u64, window_ms: u64) {
        let cutoff = now_ms.saturating_sub(window_ms);
        while let Some((ts, count)) = self.events.front().copied() {
            if ts > cutoff {
                break;
            }
            self.events.pop_front();
            self.total = self.total.saturating_sub(count);
        }
    }

    fn push_hit(&mut self, now_ms: u64, cost: u32) {
        if let Some((ts, count)) = self.events.back_mut() {
            if *ts == now_ms {
                *count = count.saturating_add(cost);
                self.total = self.total.saturating_add(cost);
                return;
            }
        }

        self.events.push_back((now_ms, cost));
        self.total = self.total.saturating_add(cost);
    }

    fn reset_at_ms(&self, now_ms: u64, window_ms: u64) -> u64 {
        self.events
            .front()
            .map(|(ts, _)| ts.saturating_add(window_ms))
            .unwrap_or_else(|| now_ms.saturating_add(window_ms))
    }

    fn can_collect(&self, now_ms: u64, window_ms: u64) -> bool {
        self.total == 0 && now_ms.saturating_sub(self.last_seen_ms) > window_ms
    }
}

static RATE_LIMIT_STATE: OnceLock<DashMap<String, SlidingWindowState>> = OnceLock::new();

fn state() -> &'static DashMap<String, SlidingWindowState> {
    RATE_LIMIT_STATE.get_or_init(DashMap::new)
}

fn make_storage_key(namespace: &str, key: &str) -> String {
    let mut output = String::with_capacity(namespace.len() + key.len() + 1);
    output.push_str(namespace);
    output.push(NAMESPACE_SEPARATOR);
    output.push_str(key);
    output
}

fn retry_after_secs(now_ms: u64, reset_at_ms: u64) -> u64 {
    let delta_ms = reset_at_ms.saturating_sub(now_ms);
    if delta_ms == 0 {
        return 1;
    }
    (delta_ms + 999) / 1000
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn maybe_evict(map: &DashMap<String, SlidingWindowState>, now_ms: u64) {
    if map.len() <= MAX_RATE_LIMIT_ENTRIES {
        return;
    }

    let target = (MAX_RATE_LIMIT_ENTRIES as f64 * EVICTION_TARGET_RATIO) as usize;

    // First pass: remove stale entries (not seen in over 1 hour)
    let stale_keys: Vec<String> = map
        .iter()
        .filter(|entry| now_ms.saturating_sub(entry.value().last_seen_ms) > EVICT_STALE_THRESHOLD_MS)
        .map(|entry| entry.key().clone())
        .collect();
    for key in &stale_keys {
        map.remove(key);
    }

    if map.len() <= target {
        return;
    }

    // Second pass: evict oldest entries by last_seen_ms
    let mut entries: Vec<(String, u64)> = map
        .iter()
        .map(|e| (e.key().clone(), e.value().last_seen_ms))
        .collect();
    entries.sort_by_key(|(_, ts)| *ts);

    let to_evict = map.len().saturating_sub(target);
    for (key, _) in entries.into_iter().take(to_evict) {
        map.remove(&key);
    }
}

pub fn check(
    namespace: &str,
    key: &str,
    max: u32,
    window_secs: u32,
    cost: u32,
    now_ms: u64,
) -> RateLimitDecision {
    let max = max.max(1);
    let cost = cost.max(1);
    let window_ms = (window_secs as u64).saturating_mul(1000).max(1);

    let compound = make_storage_key(namespace, key);
    let map = state();

    let (allowed, remaining, reset_at_ms, retry_after_secs, should_collect) = {
        let mut bucket = map.entry(compound.clone()).or_insert_with(SlidingWindowState::default);
        bucket.prune_expired(now_ms, window_ms);
        bucket.last_seen_ms = now_ms;

        let projected = bucket.total.saturating_add(cost);
        if projected > max {
            let reset_at_ms = bucket.reset_at_ms(now_ms, window_ms);
            let retry_after_secs = retry_after_secs(now_ms, reset_at_ms);
            let should_collect = bucket.can_collect(now_ms, window_ms);
            (false, 0, reset_at_ms, retry_after_secs, should_collect)
        } else {
            bucket.push_hit(now_ms, cost);
            let reset_at_ms = bucket.reset_at_ms(now_ms, window_ms);
            let remaining = max.saturating_sub(bucket.total);
            let should_collect = bucket.can_collect(now_ms, window_ms);
            (true, remaining, reset_at_ms, 0, should_collect)
        }
    };

    if should_collect {
        let _ = map.remove(&compound);
    }

    maybe_evict(map, now_ms);

    RateLimitDecision {
        allowed,
        limit: max,
        remaining,
        reset_at_ms,
        retry_after_secs,
        now_ms,
    }
}

pub fn reset(namespace: Option<&str>, key: Option<&str>) -> usize {
    let map = state();

    match (namespace, key) {
        (None, None) => {
            let total = map.len();
            map.clear();
            total
        }
        (Some(ns), None) => {
            let mut prefix = String::with_capacity(ns.len() + 1);
            prefix.push_str(ns);
            prefix.push(NAMESPACE_SEPARATOR);

            let candidates = map
                .iter()
                .filter(|entry| entry.key().starts_with(&prefix))
                .map(|entry| entry.key().clone())
                .collect::<Vec<_>>();

            let mut removed = 0usize;
            for storage_key in candidates {
                if map.remove(&storage_key).is_some() {
                    removed += 1;
                }
            }
            removed
        }
        (Some(ns), Some(k)) => {
            let storage_key = make_storage_key(ns, k);
            if map.remove(&storage_key).is_some() {
                1
            } else {
                0
            }
        }
        (None, Some(_)) => 0,
    }
}
