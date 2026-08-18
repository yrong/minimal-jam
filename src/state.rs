//! State component serialization `T(σ)` and merklization (GP Appendix D).
//!
//! Each top-level component maps to a state-key `C(i)` (see [`crate::state_key`])
//! and a value encoded via `jam-codec`. Most state integers are fixed-length;
//! `#[codec(compact)]` marks the exceptions (statistics core/service records).
//! Fixed-size sequences use [`FixedSeq`]; variable ones use `Vec`.
//!
//! [`State`] is the full σ: typed chapters `C(1..=16)` + service accounts
//! `C(255, s)`, plus opaque per-service dictionary entries (their keys are
//! one-way hashes). It provides `serialize()` → `T(σ)`, `root()`, and
//! `from_entries()`, verified byte-exact against real `traces/` state.

use crate::bytes::{decode_all, FixedSeq};
use crate::crypto::Hash;
use crate::state_key::{chapter, service_account, StateKey};
use crate::trie::{state_key, state_root};
use crate::types::{
    WorkReport, AUTH_QUEUE_SIZE, CORE_COUNT, ENTROPY_BUFFER_LEN, EPOCH_LENGTH, H128, H144, H32,
    VALIDATORS_COUNT,
};
use jam_codec::{Decode, Encode, Error};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

macro_rules! record {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
        pub struct $name { $($(#[$fm])* pub $field: $ty),* }
    };
}

// --- Component element types ----------------------------------------------

record!(ValidatorData {
    bandersnatch: H32,
    ed25519: H32,
    bls: H144,
    metadata: H128,
});

record!(AvailabilityAssignment {
    report: WorkReport,
    timeout: u32,
});

record!(AlwaysAccEntry {
    id: u32,
    gas: u64,
});

record!(DisputesRecords {
    good: Vec<H32>,
    bad: Vec<H32>,
    wonky: Vec<H32>,
    offenders: Vec<H32>,
});

record!(Privileges {
    manager: u32,
    assign: FixedSeq<u32, CORE_COUNT>,
    delegator: u32,
    registrar: u32,
    always_acc: Vec<AlwaysAccEntry>,
});

// --- C(3) recent history β ------------------------------------------------

record!(ReportedWorkPackage {
    hash: H32,
    exports_root: H32,
});

record!(BlockInfo {
    header_hash: H32,
    beefy_root: H32,
    state_root: H32,
    reported: Vec<ReportedWorkPackage>,
});

record!(Mmr {
    peaks: Vec<Option<H32>>,
});

record!(RecentBlocks {
    history: Vec<BlockInfo>,
    mmr: Mmr,
});

// --- C(4) safrole γ -------------------------------------------------------

record!(TicketBody {
    id: H32,
    #[codec(compact)]
    attempt: u8,
});

/// Epoch sealing source: winning tickets or fallback keys.
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketsOrKeys {
    Tickets(FixedSeq<TicketBody, EPOCH_LENGTH>),
    Keys(FixedSeq<H32, EPOCH_LENGTH>),
}

record!(SafroleState {
    pending: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    ring_commitment: H144,
    tickets_or_keys: TicketsOrKeys,
    accumulator: Vec<TicketBody>,
});

// --- C(13) statistics π ---------------------------------------------------

record!(ValidatorActivityRecord {
    blocks: u32,
    tickets: u32,
    pre_images: u32,
    pre_images_size: u32,
    guarantees: u32,
    assurances: u32,
});

record!(CoreActivityRecord {
    #[codec(compact)]
    da_load: u32,
    #[codec(compact)]
    popularity: u16,
    #[codec(compact)]
    imports: u16,
    #[codec(compact)]
    extrinsic_count: u16,
    #[codec(compact)]
    extrinsic_size: u32,
    #[codec(compact)]
    exports: u16,
    #[codec(compact)]
    bundle_size: u32,
    #[codec(compact)]
    gas_used: u64,
});

record!(ServiceActivityRecord {
    #[codec(compact)]
    provided_count: u16,
    #[codec(compact)]
    provided_size: u32,
    #[codec(compact)]
    refinement_count: u32,
    #[codec(compact)]
    refinement_gas_used: u64,
    #[codec(compact)]
    imports: u32,
    #[codec(compact)]
    extrinsic_count: u32,
    #[codec(compact)]
    extrinsic_size: u32,
    #[codec(compact)]
    exports: u32,
    #[codec(compact)]
    accumulate_count: u32,
    #[codec(compact)]
    accumulate_gas_used: u64,
});

record!(ServiceStatEntry {
    id: u32,
    record: ServiceActivityRecord,
});

record!(Statistics {
    vals_curr: FixedSeq<ValidatorActivityRecord, VALIDATORS_COUNT>,
    vals_last: FixedSeq<ValidatorActivityRecord, VALIDATORS_COUNT>,
    cores: FixedSeq<CoreActivityRecord, CORE_COUNT>,
    services: Vec<ServiceStatEntry>,
});

// --- C(14)/C(15)/C(16) accumulation queues + last accout ------------------

record!(ReadyRecord {
    report: WorkReport,
    dependencies: Vec<H32>,
});

record!(LastAccEntry {
    service: u32,
    hash: H32,
});

// --- C(255, s) service account metadata -----------------------------------

record!(ServiceInfo {
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

// --- Chapter value type aliases -------------------------------------------

/// `C(1)` — authorizer pools α: one length-prefixed pool per core.
pub type AuthPools = FixedSeq<Vec<H32>, CORE_COUNT>;
/// `C(2)` — authorizer queues φ: a fixed queue per core.
pub type AuthQueues = FixedSeq<FixedSeq<H32, AUTH_QUEUE_SIZE>, CORE_COUNT>;
/// `C(6)` — entropy buffer η.
pub type EntropyBuffer = FixedSeq<H32, ENTROPY_BUFFER_LEN>;
/// `C(7)`/`C(8)`/`C(9)` — validator sets ι / κ / λ.
pub type ValidatorSet = FixedSeq<ValidatorData, VALIDATORS_COUNT>;
/// `C(10)` — availability assignments ρ.
pub type AvailabilityAssignments = FixedSeq<Option<AvailabilityAssignment>, CORE_COUNT>;
/// `C(11)` — most recent timeslot τ.
pub type TimeSlot = u32;
/// `C(14)` — ready queue ϑ.
pub type ReadyQueue = FixedSeq<Vec<ReadyRecord>, EPOCH_LENGTH>;
/// `C(15)` — accumulated history ξ.
pub type AccumulatedQueue = FixedSeq<Vec<H32>, EPOCH_LENGTH>;
/// `C(16)` — most-recent accumulation outputs.
pub type LastAccout = Vec<LastAccEntry>;

// --- Full state σ ---------------------------------------------------------

/// The full JAM state σ, sufficient to reconstruct `T(σ)` and its root.
///
/// Per-service dictionary entries (storage/preimage/request) are carried
/// opaquely as `(state-key, value)` because their keys are one-way hashes.
pub struct State {
    pub auth_pools: AuthPools,             // C(1) α
    pub auth_queues: AuthQueues,           // C(2) φ
    pub recent_blocks: RecentBlocks,       // C(3) β
    pub safrole: SafroleState,             // C(4) γ
    pub disputes: DisputesRecords,         // C(5) ψ
    pub entropy: EntropyBuffer,            // C(6) η
    pub staging_validators: ValidatorSet,  // C(7) ι
    pub active_validators: ValidatorSet,   // C(8) κ
    pub previous_validators: ValidatorSet, // C(9) λ
    pub avail: AvailabilityAssignments,    // C(10) ρ
    pub timeslot: TimeSlot,                // C(11) τ
    pub privileges: Privileges,            // C(12) χ
    pub statistics: Statistics,            // C(13) π
    pub ready: ReadyQueue,                 // C(14) ϑ
    pub accumulated: AccumulatedQueue,     // C(15) ξ
    pub last_accout: LastAccout,           // C(16)
    pub accounts: Vec<(u32, ServiceInfo)>, // C(255, s)
    pub service_dict: Vec<(StateKey, Vec<u8>)>, // opaque C(s, ·)
}

impl State {
    /// Serialize σ to the `T(σ)` dictionary (state-key → value bytes).
    pub fn serialize(&self) -> BTreeMap<StateKey, Vec<u8>> {
        let mut m = BTreeMap::new();
        m.insert(chapter(1), self.auth_pools.encode());
        m.insert(chapter(2), self.auth_queues.encode());
        m.insert(chapter(3), self.recent_blocks.encode());
        m.insert(chapter(4), self.safrole.encode());
        m.insert(chapter(5), self.disputes.encode());
        m.insert(chapter(6), self.entropy.encode());
        m.insert(chapter(7), self.staging_validators.encode());
        m.insert(chapter(8), self.active_validators.encode());
        m.insert(chapter(9), self.previous_validators.encode());
        m.insert(chapter(10), self.avail.encode());
        m.insert(chapter(11), self.timeslot.encode());
        m.insert(chapter(12), self.privileges.encode());
        m.insert(chapter(13), self.statistics.encode());
        m.insert(chapter(14), self.ready.encode());
        m.insert(chapter(15), self.accumulated.encode());
        m.insert(chapter(16), self.last_accout.encode());
        for (s, info) in &self.accounts {
            m.insert(service_account(*s), info.encode());
        }
        for (k, v) in &self.service_dict {
            m.insert(*k, v.clone());
        }
        m
    }

    /// Merklize σ into its 32-byte state root (GP Appendix D).
    pub fn root(&self) -> Hash {
        let entries: Vec<([u8; 32], Vec<u8>)> = self
            .serialize()
            .into_iter()
            .map(|(k, v)| (state_key(&k), v))
            .collect();
        state_root(&entries)
    }

    /// Parse a serialized `T(σ)` dictionary back into a typed σ.
    pub fn from_entries(entries: &[(StateKey, Vec<u8>)]) -> Result<Self, Error> {
        let mut ch: BTreeMap<u8, &Vec<u8>> = BTreeMap::new();
        let mut accounts = Vec::new();
        let mut service_dict = Vec::new();
        for (k, v) in entries {
            if (1..=16).contains(&k[0]) && *k == chapter(k[0]) {
                ch.insert(k[0], v);
            } else if k[0] == 255 {
                let s = u32::from_le_bytes([k[1], k[3], k[5], k[7]]);
                if *k == service_account(s) {
                    accounts.push((s, decode_all::<ServiceInfo>(v)?));
                    continue;
                }
                service_dict.push((*k, v.clone()));
            } else {
                service_dict.push((*k, v.clone()));
            }
        }
        let get = |i: u8| -> Result<&Vec<u8>, Error> {
            ch.get(&i)
                .copied()
                .ok_or_else(|| Error::from("missing chapter"))
        };
        Ok(State {
            auth_pools: decode_all(get(1)?)?,
            auth_queues: decode_all(get(2)?)?,
            recent_blocks: decode_all(get(3)?)?,
            safrole: decode_all(get(4)?)?,
            disputes: decode_all(get(5)?)?,
            entropy: decode_all(get(6)?)?,
            staging_validators: decode_all(get(7)?)?,
            active_validators: decode_all(get(8)?)?,
            previous_validators: decode_all(get(9)?)?,
            avail: decode_all(get(10)?)?,
            timeslot: decode_all(get(11)?)?,
            privileges: decode_all(get(12)?)?,
            statistics: decode_all(get(13)?)?,
            ready: decode_all(get(14)?)?,
            accumulated: decode_all(get(15)?)?,
            last_accout: decode_all(get(16)?)?,
            accounts,
            service_dict,
        })
    }
}
