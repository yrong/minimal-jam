//! State-key constructor `C(...)` (GP Appendix D §Serialization).
//!
//! State is a mapping from 31-byte state-keys to octet sequences. Keys are
//! built three ways:
//!
//! - `C(i)` — a top-level component (chapter) `i`: `[i, 0, 0, …]`.
//! - `C(i, s)` — a chapter `i` scoped to service `s`: the 4 service-id bytes
//!   interleaved with zeros after `i`.
//! - `C(s, h)` — an entry inside service `s`'s dictionaries: the service-id
//!   bytes interleaved with `blake2b(h)`, then the rest of that hash.
//!
//! The three per-service dictionaries (storage, preimages, requests) all use
//! `C(s, ·)` with a 4-byte marker prefixed to the inner key/hash.

use crate::crypto::blake2b_256;

/// A 31-byte state-key.
pub type StateKey = [u8; 31];

/// Marker prefixed to a storage key: `2^32 - 1`.
const STORAGE_MARKER: u32 = u32::MAX;
/// Marker prefixed to a preimage hash: `2^32 - 2`.
const PREIMAGE_MARKER: u32 = u32::MAX - 1;

/// `C(i)` — top-level component key.
pub fn chapter(i: u8) -> StateKey {
    let mut k = [0u8; 31];
    k[0] = i;
    k
}

/// `C(i, s)` — chapter `i` scoped to service `s`: `[i, n0, 0, n1, 0, n2, 0, n3, 0, …]`.
pub fn chapter_service(i: u8, s: u32) -> StateKey {
    let n = s.to_le_bytes();
    let mut k = [0u8; 31];
    k[0] = i;
    k[1] = n[0];
    k[3] = n[1];
    k[5] = n[2];
    k[7] = n[3];
    k
}

/// `C(s, h)` — service dictionary entry: service-id bytes interleaved with
/// `a = blake2b(h)` as `[n0, a0, n1, a1, n2, a2, n3, a3, a4, …, a26]`.
pub fn service_hash(s: u32, h: &[u8]) -> StateKey {
    let n = s.to_le_bytes();
    let a = blake2b_256(h);
    let mut k = [0u8; 31];
    k[0] = n[0];
    k[2] = n[1];
    k[4] = n[2];
    k[6] = n[3];
    k[1] = a[0];
    k[3] = a[1];
    k[5] = a[2];
    k[7] = a[3];
    k[8..31].copy_from_slice(&a[4..27]);
    k
}

/// Extract the service id from a `C(s, h)` service-dictionary state-key
/// (service bytes live at positions 0, 2, 4, 6).
pub fn key_service(k: &StateKey) -> u32 {
    u32::from_le_bytes([k[0], k[2], k[4], k[6]])
}

/// Account metadata key `C(255, s)`.
pub fn service_account(s: u32) -> StateKey {
    chapter_service(255, s)
}

/// Storage entry key `C(s, E4(2^32-1) ‖ key)`.
pub fn service_storage(s: u32, key: &[u8]) -> StateKey {
    service_hash(s, &prefixed(STORAGE_MARKER, key))
}

/// Preimage entry key `C(s, E4(2^32-2) ‖ hash)`.
pub fn service_preimage(s: u32, hash: &[u8; 32]) -> StateKey {
    service_hash(s, &prefixed(PREIMAGE_MARKER, hash))
}

/// Request entry key `C(s, E4(length) ‖ hash)`.
pub fn service_request(s: u32, length: u32, hash: &[u8; 32]) -> StateKey {
    service_hash(s, &prefixed(length, hash))
}

/// `E4(marker) ‖ tail` (4-byte little-endian marker prefix).
fn prefixed(marker: u32, tail: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + tail.len());
    v.extend_from_slice(&marker.to_le_bytes());
    v.extend_from_slice(tail);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chapter_layout() {
        assert_eq!(chapter(1)[0], 1);
        assert!(chapter(1)[1..].iter().all(|&b| b == 0));
        assert_eq!(chapter(255), service_account(0));
    }

    #[test]
    fn chapter_service_interleave() {
        // s = 0x04030201 -> little-endian bytes 01 02 03 04 at positions 1,3,5,7.
        let k = chapter_service(7, 0x04030201);
        assert_eq!(k[0], 7);
        assert_eq!([k[1], k[3], k[5], k[7]], [1, 2, 3, 4]);
        assert_eq!([k[2], k[4], k[6]], [0, 0, 0]);
    }

    #[test]
    fn service_hash_interleave() {
        let s = 0x0a0b0c0du32;
        let a = blake2b_256(b"payload");
        let k = service_hash(s, b"payload");
        let n = s.to_le_bytes();
        assert_eq!([k[0], k[2], k[4], k[6]], [n[0], n[1], n[2], n[3]]);
        assert_eq!([k[1], k[3], k[5], k[7]], [a[0], a[1], a[2], a[3]]);
        assert_eq!(&k[8..31], &a[4..27]);
    }
}
