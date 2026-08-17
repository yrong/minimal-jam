//! State Merkle trie (GP Appendix D — Merklization).
//!
//! A binary Merkle trie over 32-byte keys with Blake2b-256. Every node encodes
//! to exactly 64 bytes and is then hashed:
//!
//! - **leaf** — head byte `0b10_xxxxxx` for an embedded value (`|v| ≤ 32`, low 6
//!   bits carry the length) or `0b11000000` for a hashed value; followed by the
//!   first 31 key bytes and the value (zero-padded) or `H(value)`.
//! - **branch** — head byte `left[0] & 0x7f` (top bit cleared marks a branch),
//!   then `left[1..32]` and the full 32-byte `right`.
//!
//! At depth `i` the key set is partitioned by bit `i` (MSB-first within a byte);
//! the empty set is the all-zero root.

use crate::crypto::{blake2b_256, Hash};

/// 32-byte trie key.
pub type Key = [u8; 32];

/// Bit `i` of `k`, most-significant-first within each byte.
fn bit(k: &Key, i: usize) -> bool {
    (k[i >> 3] & (1 << (7 - (i & 7)))) != 0
}

/// Build a 32-byte trie key from a state key of up to 32 bytes.
///
/// GP state keys are 31 bytes; the trie operates on 32-byte keys and a leaf
/// stores only the first 31 (`key[..31]`). The 31→32 mapping appends a trailing
/// zero byte (verified against `traces/` pre/post state roots).
pub fn state_key(bytes: &[u8]) -> Key {
    assert!(bytes.len() <= 32, "state key longer than 32 bytes");
    let mut k = [0u8; 32];
    k[..bytes.len()].copy_from_slice(bytes);
    k
}

/// Encode a leaf node (GP eq. 287).
fn leaf(k: &Key, v: &[u8]) -> [u8; 64] {
    let mut node = [0u8; 64];
    node[1..32].copy_from_slice(&k[..31]);
    if v.len() <= 32 {
        node[0] = 0b1000_0000 | v.len() as u8;
        node[32..32 + v.len()].copy_from_slice(v);
    } else {
        node[0] = 0b1100_0000;
        node[32..64].copy_from_slice(&blake2b_256(v));
    }
    node
}

/// Encode a branch node (GP eq. 286).
fn branch(left: &Hash, right: &Hash) -> [u8; 64] {
    let mut node = [0u8; 64];
    node[0] = left[0] & 0x7f;
    node[1..32].copy_from_slice(&left[1..32]);
    node[32..64].copy_from_slice(right);
    node
}

/// Merklize a key/value set at bit depth `depth` (GP eq. 289).
fn merkle(kvs: &[(Key, Vec<u8>)], depth: usize) -> Hash {
    match kvs {
        [] => [0u8; 32],
        [(k, v)] => blake2b_256(&leaf(k, v)),
        _ => {
            let (mut left, mut right) = (Vec::new(), Vec::new());
            for kv in kvs {
                if bit(&kv.0, depth) {
                    right.push(kv.clone());
                } else {
                    left.push(kv.clone());
                }
            }
            let l = merkle(&left, depth + 1);
            let r = merkle(&right, depth + 1);
            blake2b_256(&branch(&l, &r))
        }
    }
}

/// State root of a key/value set (GP Appendix D). Order-independent.
pub fn state_root(kvs: &[(Key, Vec<u8>)]) -> Hash {
    merkle(kvs, 0)
}
