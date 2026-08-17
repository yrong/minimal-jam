//! `0x`-prefixed hex helpers shared by the STF modules.

/// 32 zero bytes as a `0x`-prefixed hex string.
pub const ZERO_HASH_HEX: &str = "0x0000000000000000000000000000000000000000000000000000000000000000";

/// Decode a `0x`-prefixed (or bare) hex string into bytes.
pub fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).expect("valid hex")
}

/// Encode bytes as a lowercase `0x`-prefixed hex string.
pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

/// Byte length of a `0x`-prefixed hex blob.
pub fn blob_len(hex: &str) -> u64 {
    (hex.trim_start_matches("0x").len() as u64) / 2
}
