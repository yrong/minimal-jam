//! Hash primitives used by the JAM state transition (GP Appendix/§7).
//!
//! - `blake2b_256` (H): general JAM hash, e.g. preimage keys.
//! - `keccak_256` (H_K): used by the recent-history Merkle Mountain Range.

use blake2::digest::consts::U32;
use blake2::Blake2b;
use blake2::Digest as _;
use sha3::Keccak256;

pub type Hash = [u8; 32];

type Blake2b256 = Blake2b<U32>;

/// Blake2b-256, the JAM `H` hash function.
pub fn blake2b_256(data: &[u8]) -> Hash {
    let mut h = Blake2b256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Keccak-256, the JAM `H_K` hash function (recent-history MMR).
pub fn keccak_256(data: &[u8]) -> Hash {
    let mut h = Keccak256::new();
    h.update(data);
    let out = h.finalize();
    let mut r = [0u8; 32];
    r.copy_from_slice(&out);
    r
}

/// Append `item` to a Merkle Mountain Range of `peaks` (GP eq. for `A`).
///
/// Peaks are little-endian by height: `peaks[n]` commits to `2^n` leaves.
/// A present peak at height `n` is combined with the carry via
/// `H_K(peaks[n] ++ carry)` and the slot is cleared; the carry then rises.
pub fn mmr_append(peaks: &mut Vec<Option<Hash>>, item: Hash) {
    let mut carry = item;
    let mut n = 0;
    loop {
        if n == peaks.len() {
            peaks.push(Some(carry));
            return;
        }
        match peaks[n] {
            None => {
                peaks[n] = Some(carry);
                return;
            }
            Some(existing) => {
                let mut buf = Vec::with_capacity(64);
                buf.extend_from_slice(&existing);
                buf.extend_from_slice(&carry);
                carry = keccak_256(&buf);
                peaks[n] = None;
                n += 1;
            }
        }
    }
}

/// MMR super-peak `M_R` (GP): commitment collapsing all present peaks.
///
/// `[]` -> zero hash; a single peak returns itself; otherwise fold from the
/// low peaks up with the `$peak$` domain separator:
/// `H_K("peak" ++ M_R(rest) ++ last)`.
pub fn mmr_super_peak(peaks: &[Option<Hash>]) -> Hash {
    let present: Vec<Hash> = peaks.iter().filter_map(|p| *p).collect();
    fn go(items: &[Hash]) -> Hash {
        match items.len() {
            0 => [0u8; 32],
            1 => items[0],
            n => {
                let rest = go(&items[..n - 1]);
                let mut buf = Vec::with_capacity(4 + 64);
                buf.extend_from_slice(b"peak");
                buf.extend_from_slice(&rest);
                buf.extend_from_slice(&items[n - 1]);
                keccak_256(&buf)
            }
        }
    }
    go(&present)
}
