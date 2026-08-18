//! State component serialization `T(σ)` (GP Appendix D §Serialization).
//!
//! Each top-level component maps to a state-key `C(i)` (see [`crate::state_key`])
//! and a value serialized here with the JAM codec. All non-discriminator
//! integers in state are **fixed-length**; variable sequences carry a
//! general-natural length prefix; fixed-size sequences (validator sets, auth
//! queues, per-core arrays) carry none.
//!
//! This module currently covers the batch verified byte-for-byte against real
//! `traces/` state: α, φ, ψ, η, ι/κ/λ, ρ, τ, χ. The remaining chapters
//! (β, γ, π, ϑ, ξ, last-accout, service accounts) are follow-up work.

use crate::codec::FixedSeq;
use crate::types::{
    WorkReport, AUTH_QUEUE_SIZE, CORE_COUNT, ENTROPY_BUFFER_LEN, H128, H144, H32, VALIDATORS_COUNT,
};

// --- Component element types ----------------------------------------------

codec_struct!(ValidatorData {
    bandersnatch: H32,
    ed25519: H32,
    bls: H144,
    metadata: H128,
});

codec_struct!(AvailabilityAssignment {
    report: WorkReport,
    timeout: u32,
});

codec_struct!(AlwaysAccEntry {
    id: u32,
    gas: u64,
});

// `C(5)` — disputes records ψ: four length-prefixed hash sequences.
codec_struct!(DisputesRecords {
    good: Vec<H32>,
    bad: Vec<H32>,
    wonky: Vec<H32>,
    offenders: Vec<H32>,
});

// `C(12)` — privileges χ.
codec_struct!(Privileges {
    manager: u32,
    assign: FixedSeq<u32, CORE_COUNT>,
    delegator: u32,
    registrar: u32,
    always_acc: Vec<AlwaysAccEntry>,
});

// --- Chapter value types (state-key -> value) ------------------------------

/// `C(1)` — authorizer pools α: one length-prefixed pool per core.
pub type AuthPools = FixedSeq<Vec<H32>, CORE_COUNT>;
/// `C(2)` — authorizer queues φ: a fixed queue per core.
pub type AuthQueues = FixedSeq<FixedSeq<H32, AUTH_QUEUE_SIZE>, CORE_COUNT>;
/// `C(6)` — entropy buffer η.
pub type EntropyBuffer = FixedSeq<H32, ENTROPY_BUFFER_LEN>;
/// `C(7)`/`C(8)`/`C(9)` — validator sets ι / κ / λ.
pub type ValidatorSet = FixedSeq<ValidatorData, VALIDATORS_COUNT>;
/// `C(10)` — availability assignments ρ: optional assignment per core.
pub type AvailabilityAssignments = FixedSeq<Option<AvailabilityAssignment>, CORE_COUNT>;
/// `C(11)` — most recent timeslot τ.
pub type TimeSlot = u32;
