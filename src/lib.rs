//! Minimal, Gray-Paper-faithful JAM building blocks, verified against
//! `davxy/jam-test-vectors` (tiny).
//!
//! STF subsystems (decoded-JSON vectors):
//! - [`statistics`] — validator activity counters (GP §13)
//! - [`authorizations`] — authorizer pools/queues (GP §8)
//! - [`preimages`] — preimage provision (GP §12)
//! - [`history`] — recent blocks + Keccak MMR (GP §7)
//!
//! Serialization (codec vectors), via `jam-codec`:
//! - [`bytes`] — dual serde + jam-codec wrapper types (`Hex`, `Blob`, `FixedSeq`)
//! - [`types`] — protocol types with `#[derive(Encode, Decode)]` + serde
//!
//! State (GP Appendix D):
//! - [`trie`] — binary Merkle state trie + root
//! - [`state_key`] — `C(...)` state-key constructor
//! - [`state`] — full σ assembly, serialization, and merklization
//! - [`block_import`] — block-import STFs (τ, π, α) on typed state
pub mod crypto;
pub mod hexutil;

pub mod bytes;
pub mod types;
pub mod trie;
pub mod ring;
pub mod state_key;
pub mod state;
pub mod block_import;

pub mod authorizations;
pub mod history;
pub mod safrole;
pub mod preimages;
pub mod statistics;
pub mod disputes;
pub mod assurances;
