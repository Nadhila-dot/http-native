use hmac::{Hmac, Mac};
use parking_lot::RwLock;
use sha2::Sha256;
use std::collections::HashMap;
use std::time::{Duration, Instant};

type HmacSha256 = Hmac<Sha256>;

/// Number of shards to reduce lock contention across workers.
const SHARD_COUNT: usize = 64;
/// Default max sessions across all shards.
const DEFAULT_MAX_SESSIONS: usize = 100_000;
/// Default max data size per session (4 KB).
const DEFAULT_MAX_DATA_SIZE: usize = 4096;
/// Session ID: 16 bytes = 128-bit random.
pub const SESSION_ID_BYTES: usize = 16;
/// Hex-encoded session ID length.
pub const SESSION_ID_HEX_LEN: usize = SESSION_ID_BYTES * 2;
/// HMAC signature length (SHA-256 = 32 bytes = 64 hex chars).
const HMAC_HEX_LEN: usize = 64;

// ─── Session Configuration ────────────────

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub secret: Vec<u8>,
    pub max_age_secs: u64,
    pub cookie_name: String,
    pub http_only: bool,
    pub secure: bool,
    pub same_site: SameSite,
    pub path: String,
    pub max_sessions: usize,
    pub max_data_size: usize,
}

#[derive(Debug, Clone, Copy)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

impl SameSite {
    pub fn as_str(&self) -> &'static str {
        match self {
            SameSite::Strict => "Strict",
            SameSite::Lax => "Lax",
            SameSite::None => "None",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_lowercase().as_str() {
            "strict" => SameSite::Strict,
            "none" => SameSite::None,
            _ => SameSite::Lax,
        }
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            secret: Vec::new(),
            max_age_secs: 3600,
            cookie_name: "sid".to_string(),
            http_only: true,
            secure: false,
            same_site: SameSite::Lax,
            path: "/".to_string(),
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_data_size: DEFAULT_MAX_DATA_SIZE,
        }
    }
}

// ─── Session Entry ────────────────────────

#[derive(Debug, Clone)]
pub struct SessionEntry {
    pub data: HashMap<String, Vec<u8>>,
    pub created_at: Instant,
    pub last_accessed: Instant,
    pub expires_at: Instant,
}

impl SessionEntry {
    fn new(max_age: Duration) -> Self {
        let now = Instant::now();
        Self {
            data: HashMap::new(),
            created_at: now,
            last_accessed: now,
            expires_at: now + max_age,
        }
    }

    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }

    fn touch(&mut self, max_age: Duration) {
        let now = Instant::now();
        self.last_accessed = now;
        self.expires_at = now + max_age;
    }

    /// Total size of all stored data in bytes.
    fn data_size(&self) -> usize {
        self.data.iter().map(|(k, v)| k.len() + v.len()).sum()
    }
}

// ─── Session Shard ────────────────────────

struct SessionShard {
    map: HashMap<[u8; SESSION_ID_BYTES], SessionEntry>,
}

impl SessionShard {
    fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }
}

// ─── Session Store ────────────────────────

pub struct SessionStore {
    shards: Box<[RwLock<SessionShard>]>,
    config: SessionConfig,
}

impl SessionStore {
    pub fn new(config: SessionConfig) -> Self {
        let shards: Vec<RwLock<SessionShard>> =
            (0..SHARD_COUNT).map(|_| RwLock::new(SessionShard::new())).collect();

        Self {
            shards: shards.into_boxed_slice(),
            config,
        }
    }

    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Shard index for a given session ID.
    fn shard_index(&self, id: &[u8; SESSION_ID_BYTES]) -> usize {
        // Use the first byte of the session ID as shard selector.
        (id[0] as usize) % SHARD_COUNT
    }

    /// Generate a new cryptographically random session ID.
    pub fn generate_id(&self) -> [u8; SESSION_ID_BYTES] {
        let mut id = [0u8; SESSION_ID_BYTES];
        getrandom::getrandom(&mut id).expect("failed to generate random session ID");
        id
    }

    /// Sign a session ID with HMAC-SHA256. Returns hex-encoded signature.
    pub fn sign(&self, id: &[u8; SESSION_ID_BYTES]) -> String {
        let mut mac =
            HmacSha256::new_from_slice(&self.config.secret).expect("HMAC key should be valid");
        mac.update(id);
        let result = mac.finalize();
        hex_encode(result.into_bytes().as_slice())
    }

    /// Verify a signed cookie value. Returns the raw session ID if valid.
    pub fn verify_cookie(&self, cookie_value: &str) -> Option<[u8; SESSION_ID_BYTES]> {
        // Format: <hex-session-id>.<hex-hmac>
        let dot = cookie_value.find('.')?;
        let id_hex = &cookie_value[..dot];
        let sig_hex = &cookie_value[dot + 1..];

        if id_hex.len() != SESSION_ID_HEX_LEN || sig_hex.len() != HMAC_HEX_LEN {
            return None;
        }

        let id_bytes = hex_decode(id_hex)?;
        if id_bytes.len() != SESSION_ID_BYTES {
            return None;
        }

        let mut id = [0u8; SESSION_ID_BYTES];
        id.copy_from_slice(&id_bytes);

        // Verify HMAC
        let mut mac =
            HmacSha256::new_from_slice(&self.config.secret).expect("HMAC key should be valid");
        mac.update(&id);
        let sig_bytes = hex_decode(sig_hex)?;
        mac.verify_slice(&sig_bytes).ok()?;

        Some(id)
    }

    /// Build the signed cookie value: <hex-id>.<hex-hmac>
    pub fn build_cookie_value(&self, id: &[u8; SESSION_ID_BYTES]) -> String {
        let id_hex = hex_encode(id);
        let sig = self.sign(id);
        format!("{id_hex}.{sig}")
    }

    /// Build the full Set-Cookie header value.
    pub fn build_set_cookie(&self, id: &[u8; SESSION_ID_BYTES]) -> String {
        let value = self.build_cookie_value(id);
        let cfg = &self.config;
        let mut cookie = format!(
            "{}={}; Path={}; Max-Age={}",
            cfg.cookie_name, value, cfg.path, cfg.max_age_secs
        );
        if cfg.http_only {
            cookie.push_str("; HttpOnly");
        }
        if cfg.secure {
            cookie.push_str("; Secure");
        }
        cookie.push_str("; SameSite=");
        cookie.push_str(cfg.same_site.as_str());
        cookie
    }

    /// Build a Set-Cookie header that destroys the session cookie.
    pub fn build_destroy_cookie(&self) -> String {
        let cfg = &self.config;
        let mut cookie = format!(
            "{}=; Path={}; Max-Age=0",
            cfg.cookie_name, cfg.path
        );
        if cfg.http_only {
            cookie.push_str("; HttpOnly");
        }
        if cfg.secure {
            cookie.push_str("; Secure");
        }
        cookie.push_str("; SameSite=");
        cookie.push_str(cfg.same_site.as_str());
        cookie
    }

    /// Look up a session. Returns cloned data if found and not expired.
    pub fn get(&self, id: &[u8; SESSION_ID_BYTES]) -> Option<SessionEntry> {
        let shard_idx = self.shard_index(id);
        let mut shard = self.shards[shard_idx].write();

        if let Some(entry) = shard.map.get_mut(id) {
            if entry.is_expired() {
                shard.map.remove(id);
                return None;
            }
            entry.touch(Duration::from_secs(self.config.max_age_secs));
            return Some(entry.clone());
        }

        None
    }

    /// Create or update a session with the given data mutations.
    /// `mutations` contains only the changed keys. Existing keys not in
    /// `mutations` are preserved.
    pub fn upsert(
        &self,
        id: &[u8; SESSION_ID_BYTES],
        mutations: HashMap<String, Vec<u8>>,
        deleted_keys: &[String],
    ) {
        let shard_idx = self.shard_index(id);
        let mut shard = self.shards[shard_idx].write();
        let max_age = Duration::from_secs(self.config.max_age_secs);

        let entry = shard
            .map
            .entry(*id)
            .or_insert_with(|| SessionEntry::new(max_age));

        // Apply deletions
        for key in deleted_keys {
            entry.data.remove(key);
        }

        // Merge mutations (last-write-wins)
        for (key, value) in mutations {
            entry.data.insert(key, value);
        }

        // Enforce per-session data size limit
        if entry.data_size() > self.config.max_data_size {
            // Truncate by removing oldest entries until under limit.
            // Simple strategy: just clear if over limit.
            entry.data.clear();
        }

        entry.touch(max_age);
    }

    /// Destroy a session.
    pub fn destroy(&self, id: &[u8; SESSION_ID_BYTES]) {
        let shard_idx = self.shard_index(id);
        let mut shard = self.shards[shard_idx].write();
        shard.map.remove(id);
    }

    /// Parse the session cookie from a Cookie header value.
    /// Scans for `cookie_name=<value>` in the header.
    pub fn extract_cookie_value<'a>(&self, cookie_header: &'a str) -> Option<&'a str> {
        let name = &self.config.cookie_name;
        let search = format!("{name}=");

        for part in cookie_header.split(';') {
            let trimmed = part.trim();
            if trimmed.starts_with(&search) {
                let value = &trimmed[search.len()..];
                // Trim whitespace and quotes
                let value = value.trim().trim_matches('"');
                if !value.is_empty() {
                    return Some(value);
                }
            }
        }

        None
    }

    /// Total sessions across all shards (for diagnostics).
    pub fn session_count(&self) -> usize {
        self.shards.iter().map(|s| s.read().map.len()).sum()
    }
}

// ─── Session Action (from JS response trailer) ───

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SessionAction {
    /// Update session data with mutations.
    Update = 1,
    /// Destroy the session entirely.
    Destroy = 2,
    /// Regenerate session ID (destroy old, create new).
    Regenerate = 3,
}

impl SessionAction {
    pub fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Update),
            2 => Some(Self::Destroy),
            3 => Some(Self::Regenerate),
            _ => None,
        }
    }
}

// ─── Hex Encoding Helpers ─────────────────

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX_CHARS[(b >> 4) as usize]);
        s.push(HEX_CHARS[(b & 0xf) as usize]);
    }
    s
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

fn hex_decode(hex: &str) -> Option<Vec<u8>> {
    if hex.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<u8> = hex.bytes().collect();

    for chunk in chars.chunks_exact(2) {
        let high = hex_nibble(chunk[0])?;
        let low = hex_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }

    Some(bytes)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

// ─── Public Hex Helpers for NAPI ──────────

/// Decode a hex session ID string to raw bytes.
pub fn hex_decode_id(hex: &str) -> Option<[u8; SESSION_ID_BYTES]> {
    if hex.len() != SESSION_ID_HEX_LEN {
        return None;
    }
    let bytes = hex_decode(hex)?;
    let mut id = [0u8; SESSION_ID_BYTES];
    id.copy_from_slice(&bytes);
    Some(id)
}

/// Encode raw session ID bytes to hex string.
pub fn hex_encode_id(id: &[u8; SESSION_ID_BYTES]) -> String {
    hex_encode(id)
}
