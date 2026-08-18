//! State component serialization `T(σ)` (GP Appendix D §Serialization).
//!
//! Each top-level component maps to a state-key `C(i)` (see [`crate::state_key`])
//! and a value serialized here with the JAM codec. Most state integers are
//! fixed-length; variable sequences carry a general-natural length prefix;
//! fixed-size sequences (validator sets, auth queues, per-core arrays) carry
//! none. Exception confirmed against the vectors: the core/service activity
//! records in statistics (π) use `Compact` integers.
//!
//! Covers all top-level chapters `C(1..=16)` and the service-account metadata
//! `C(255, s)`, each verified by byte-exact round-trip against real `traces/`
//! state. Not yet covered: the opaque per-service dictionary *values*
//! (storage/preimage blobs are identity; request values are `var{[E4(slot)]}`).

use crate::codec::{Codec, CodecError, Compact, FixedSeq, Reader};
use crate::types::{
    WorkReport, AUTH_QUEUE_SIZE, CORE_COUNT, ENTROPY_BUFFER_LEN, EPOCH_LENGTH, H128, H144, H32,
    VALIDATORS_COUNT,
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

// --- C(3) recent history β ------------------------------------------------

codec_struct!(ReportedWorkPackage {
    hash: H32,
    exports_root: H32,
});

codec_struct!(BlockInfo {
    header_hash: H32,
    beefy_root: H32,
    state_root: H32,
    reported: Vec<ReportedWorkPackage>,
});

codec_struct!(Mmr {
    peaks: Vec<Option<H32>>,
});

// `C(3)` — recent blocks β.
codec_struct!(RecentBlocks {
    history: Vec<BlockInfo>,
    mmr: Mmr,
});

// --- C(4) safrole γ -------------------------------------------------------

codec_struct!(TicketBody {
    id: H32,
    attempt: Compact,
});

/// Epoch sealing source: either the winning tickets or the fallback keys.
pub enum TicketsOrKeys {
    Tickets(FixedSeq<TicketBody, EPOCH_LENGTH>),
    Keys(FixedSeq<H32, EPOCH_LENGTH>),
}

impl Codec for TicketsOrKeys {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            TicketsOrKeys::Tickets(t) => {
                out.push(0);
                t.encode_to(out);
            }
            TicketsOrKeys::Keys(k) => {
                out.push(1);
                k.encode_to(out);
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        match r.u8()? {
            0 => Ok(TicketsOrKeys::Tickets(FixedSeq::decode(r)?)),
            1 => Ok(TicketsOrKeys::Keys(FixedSeq::decode(r)?)),
            b => Err(CodecError(format!("invalid TicketsOrKeys tag {b}"))),
        }
    }
}

/// `C(4)` — safrole state γ.
pub struct SafroleState {
    pub pending: ValidatorSet,
    pub ring_commitment: H144,
    pub tickets_or_keys: TicketsOrKeys,
    pub accumulator: Vec<TicketBody>,
}

impl Codec for SafroleState {
    fn encode_to(&self, out: &mut Vec<u8>) {
        self.pending.encode_to(out);
        self.ring_commitment.encode_to(out);
        self.tickets_or_keys.encode_to(out);
        self.accumulator.encode_to(out);
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        Ok(SafroleState {
            pending: Codec::decode(r)?,
            ring_commitment: Codec::decode(r)?,
            tickets_or_keys: Codec::decode(r)?,
            accumulator: Codec::decode(r)?,
        })
    }
}

// --- C(13) statistics π ---------------------------------------------------

codec_struct!(ValidatorActivityRecord {
    blocks: u32,
    tickets: u32,
    pre_images: u32,
    pre_images_size: u32,
    guarantees: u32,
    assurances: u32,
});

codec_struct!(CoreActivityRecord {
    da_load: Compact,
    popularity: Compact,
    imports: Compact,
    extrinsic_count: Compact,
    extrinsic_size: Compact,
    exports: Compact,
    bundle_size: Compact,
    gas_used: Compact,
});

codec_struct!(ServiceActivityRecord {
    provided_count: Compact,
    provided_size: Compact,
    refinement_count: Compact,
    refinement_gas_used: Compact,
    imports: Compact,
    extrinsic_count: Compact,
    extrinsic_size: Compact,
    exports: Compact,
    accumulate_count: Compact,
    accumulate_gas_used: Compact,
});

codec_struct!(ServiceStatEntry {
    id: u32,
    record: ServiceActivityRecord,
});

// `C(13)` — statistics π.
codec_struct!(Statistics {
    vals_curr: FixedSeq<ValidatorActivityRecord, VALIDATORS_COUNT>,
    vals_last: FixedSeq<ValidatorActivityRecord, VALIDATORS_COUNT>,
    cores: FixedSeq<CoreActivityRecord, CORE_COUNT>,
    services: Vec<ServiceStatEntry>,
});

// --- C(14)/C(15)/C(16) accumulation queues + last accout ------------------

codec_struct!(ReadyRecord {
    report: WorkReport,
    dependencies: Vec<H32>,
});

/// `C(14)` — ready queue ϑ: one group of ready records per epoch slot.
pub type ReadyQueue = FixedSeq<Vec<ReadyRecord>, EPOCH_LENGTH>;
/// `C(15)` — accumulated history ξ: one group of package hashes per epoch slot.
pub type AccumulatedQueue = FixedSeq<Vec<H32>, EPOCH_LENGTH>;

codec_struct!(LastAccEntry {
    service: u32,
    hash: H32,
});

/// `C(16)` — most-recent accumulation outputs.
pub type LastAccout = Vec<LastAccEntry>;

// --- C(255, s) service account metadata -----------------------------------

// `C(255, s)` — service account info (`ServiceInfo`): version, code hash,
// five u64 balances/gas/size fields, then four u32 counters/slots.
codec_struct!(ServiceInfo {
    version: u8,
    code_hash: H32,
    balance: u64,
    min_item_gas: u64,
    min_memo_gas: u64,
    bytes: u64,
    deposit_offset: u64,
    items: u32,
    creation_slot: u32,
    last_accumulation_slot: u32,
    parent_service: u32,
});
