//! Minimal, Gray-Paper-faithful JAM building blocks, verified against
//! `davxy/jam-test-vectors` (tiny).
//!
//! STF subsystems (decoded-JSON vectors):
//! - [`statistics`] — validator activity counters (GP §13)
//! - [`authorizations`] — authorizer pools/queues (GP §8)
//! - [`preimages`] — preimage provision (GP §12)
//! - [`history`] — recent blocks + Keccak MMR (GP §7)
//!
//! Serialization (codec vectors):
//! - [`codec`] — JAM codec primitives (GP Appendix C)
//! - [`types`] — protocol types with field-order codec + serde
//!
//! State trie:
//! - [`trie`] — binary Merkle state trie + root (GP Appendix D)
pub mod crypto;
pub mod hexutil;

#[macro_use]
pub mod codec;
pub mod types;
pub mod trie;

pub mod authorizations;
pub mod history;
pub mod preimages;
pub mod statistics;
