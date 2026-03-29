//! WebSocket frame protocol implementation (RFC 6455).
//! Handles frame parsing, encoding, masking, and the upgrade handshake.

use sha1::{Sha1, Digest};
use base64::Engine;

const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// WebSocket opcodes
pub const OPCODE_CONTINUATION: u8 = 0x0;
pub const OPCODE_TEXT: u8 = 0x1;
pub const OPCODE_BINARY: u8 = 0x2;
pub const OPCODE_CLOSE: u8 = 0x8;
pub const OPCODE_PING: u8 = 0x9;
pub const OPCODE_PONG: u8 = 0xA;

/// Max frame payload (16 MB)
const MAX_PAYLOAD_SIZE: usize = 16 * 1024 * 1024;

pub struct WsFrame {
    pub fin: bool,
    pub opcode: u8,
    pub payload: Vec<u8>,
}

/// Compute the Sec-WebSocket-Accept value from the client's key.
pub fn compute_accept_key(client_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(client_key.trim().as_bytes());
    hasher.update(WS_GUID);
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

/// Build the 101 Switching Protocols response.
pub fn build_upgrade_response(accept_key: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n\
         \r\n",
        accept_key
    ).into_bytes()
}

/// Try to parse a WebSocket frame from the buffer.
/// Returns Some((frame, bytes_consumed)) if a complete frame is available.
pub fn parse_frame(buf: &[u8]) -> Option<(WsFrame, usize)> {
    if buf.len() < 2 {
        return None;
    }

    let fin = (buf[0] & 0x80) != 0;
    let opcode = buf[0] & 0x0F;
    let masked = (buf[1] & 0x80) != 0;
    let mut payload_len = (buf[1] & 0x7F) as usize;
    let mut offset = 2;

    if payload_len == 126 {
        if buf.len() < 4 { return None; }
        payload_len = ((buf[2] as usize) << 8) | (buf[3] as usize);
        offset = 4;
    } else if payload_len == 127 {
        if buf.len() < 10 { return None; }
        payload_len = u64::from_be_bytes(buf[2..10].try_into().ok()?) as usize;
        offset = 10;
    }

    if payload_len > MAX_PAYLOAD_SIZE {
        return None; // Reject oversized frames
    }

    let mask_key = if masked {
        if buf.len() < offset + 4 { return None; }
        let key = [buf[offset], buf[offset+1], buf[offset+2], buf[offset+3]];
        offset += 4;
        Some(key)
    } else {
        None
    };

    if buf.len() < offset + payload_len {
        return None; // Incomplete frame
    }

    let mut payload = buf[offset..offset + payload_len].to_vec();

    // Unmask if needed (client-to-server frames are always masked)
    if let Some(key) = mask_key {
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= key[i % 4];
        }
    }

    Some((WsFrame { fin, opcode, payload }, offset + payload_len))
}

/// Encode a WebSocket frame for sending (server-to-client, unmasked).
pub fn encode_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(10 + payload.len());

    // FIN + opcode
    frame.push(0x80 | opcode);

    // Payload length (server frames are NOT masked)
    if payload.len() < 126 {
        frame.push(payload.len() as u8);
    } else if payload.len() <= 65535 {
        frame.push(126);
        frame.push((payload.len() >> 8) as u8);
        frame.push((payload.len() & 0xFF) as u8);
    } else {
        frame.push(127);
        frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
    }

    frame.extend_from_slice(payload);
    frame
}

/// Encode a close frame with optional status code and reason.
pub fn encode_close_frame(code: u16, reason: &str) -> Vec<u8> {
    let mut payload = Vec::with_capacity(2 + reason.len());
    payload.push((code >> 8) as u8);
    payload.push((code & 0xFF) as u8);
    payload.extend_from_slice(reason.as_bytes());
    encode_frame(OPCODE_CLOSE, &payload)
}
