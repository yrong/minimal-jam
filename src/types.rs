//! JAM protocol types for the codec vectors (GP / `lib/jam-types.asn`).
//!
//! Binary encoding is derived via `jam-codec` (`#[derive(Encode, Decode)]`);
//! fields marked `#[codec(compact)]` use the JAM general-natural encoding, all
//! other integers are fixed-length little-endian. Fixed-size sequences use
//! [`FixedSeq`]; variable ones use `Vec`. JSON (serde) is derived in parallel.

use crate::bytes::{Blob, FixedSeq, Hex, Null};
use jam_codec::{Decode, Encode};
use serde::{Deserialize, Serialize};

/// Tiny chain-spec sizes for fixed-length sequences.
pub const EPOCH_LENGTH: usize = 12;
pub const VALIDATORS_COUNT: usize = 6;
pub const VALIDATORS_SUPER_MAJORITY: usize = 5;
pub const CORE_COUNT: usize = 2;
pub const AUTH_QUEUE_SIZE: usize = 80;
pub const ENTROPY_BUFFER_LEN: usize = 4;

pub type H32 = Hex<32>;
pub type H64 = Hex<64>;
pub type H96 = Hex<96>;
pub type H784 = Hex<784>;
pub type H128 = Hex<128>;
pub type H144 = Hex<144>;
/// Availability bitfield: `ceil(core-count / 8)` = 1 byte for tiny.
pub type Bitfield = Hex<1>;

macro_rules! record {
    ($(#[$m:meta])* $name:ident { $($(#[$fm:meta])* $field:ident : $ty:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
        pub struct $name { $($(#[$fm])* pub $field: $ty),* }
    };
}

// --- Refine context / work package ----------------------------------------

record!(RefineContext {
    anchor: H32,
    state_root: H32,
    beefy_root: H32,
    lookup_anchor: H32,
    lookup_anchor_slot: u32,
    prerequisites: Vec<H32>,
});

record!(ImportSpec {
    tree_root: H32,
    index: u16,
});

record!(ExtrinsicSpec {
    hash: H32,
    len: u32,
});

record!(WorkItem {
    service: u32,
    code_hash: H32,
    refine_gas_limit: u64,
    accumulate_gas_limit: u64,
    export_count: u16,
    payload: Blob,
    import_segments: Vec<ImportSpec>,
    extrinsic: Vec<ExtrinsicSpec>,
});

record!(WorkPackage {
    auth_code_host: u32,
    auth_code_hash: H32,
    context: RefineContext,
    authorization: Blob,
    authorizer_config: Blob,
    items: Vec<WorkItem>,
});

// --- Work report ----------------------------------------------------------

/// `WorkExecResult` CHOICE — tag byte + payload (only `ok` carries data).
#[derive(Clone, Debug, PartialEq, Encode, Decode, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkExecResult {
    Ok(Blob),
    OutOfGas(Null),
    Panic(Null),
    BadExports(Null),
    OutputOversize(Null),
    BadCode(Null),
    CodeOversize(Null),
}

record!(RefineLoad {
    #[codec(compact)]
    gas_used: u64,
    #[codec(compact)]
    imports: u16,
    #[codec(compact)]
    extrinsic_count: u16,
    #[codec(compact)]
    extrinsic_size: u32,
    #[codec(compact)]
    exports: u16,
});

record!(WorkResult {
    service_id: u32,
    code_hash: H32,
    payload_hash: H32,
    accumulate_gas: u64,
    result: WorkExecResult,
    refine_load: RefineLoad,
});

record!(WorkPackageSpec {
    hash: H32,
    length: u32,
    erasure_root: H32,
    exports_root: H32,
    exports_count: u16,
});

record!(SegmentRootLookupItem {
    work_package_hash: H32,
    segment_tree_root: H32,
});

record!(WorkReport {
    package_spec: WorkPackageSpec,
    context: RefineContext,
    #[codec(compact)]
    core_index: u16,
    authorizer_hash: H32,
    #[codec(compact)]
    auth_gas_used: u64,
    auth_output: Blob,
    segment_root_lookup: Vec<SegmentRootLookupItem>,
    results: Vec<WorkResult>,
});

// --- Tickets --------------------------------------------------------------

record!(TicketEnvelope {
    #[codec(compact)]
    attempt: u8,
    signature: H784,
});

record!(TicketBody {
    id: H32,
    #[codec(compact)]
    attempt: u8,
});

// --- Disputes -------------------------------------------------------------

record!(Judgement {
    vote: bool,
    index: u16,
    signature: H64,
});

record!(Verdict {
    target: H32,
    age: u32,
    votes: FixedSeq<Judgement, VALIDATORS_SUPER_MAJORITY>,
});

record!(Culprit {
    target: H32,
    key: H32,
    signature: H64,
});

record!(Fault {
    target: H32,
    vote: bool,
    key: H32,
    signature: H64,
});

record!(DisputesExtrinsic {
    verdicts: Vec<Verdict>,
    culprits: Vec<Culprit>,
    faults: Vec<Fault>,
});

// --- Preimages / assurances / guarantees ----------------------------------

record!(Preimage {
    requester: u32,
    blob: Blob,
});

record!(AvailAssurance {
    anchor: H32,
    bitfield: Bitfield,
    validator_index: u16,
    signature: H64,
});

record!(ValidatorSignature {
    validator_index: u16,
    signature: H64,
});

record!(ReportGuarantee {
    report: WorkReport,
    slot: u32,
    signatures: Vec<ValidatorSignature>,
});

// --- Header / block -------------------------------------------------------

record!(EpochMarkValidatorKeys {
    bandersnatch: H32,
    ed25519: H32,
});

record!(EpochMark {
    entropy: H32,
    tickets_entropy: H32,
    validators: FixedSeq<EpochMarkValidatorKeys, VALIDATORS_COUNT>,
});

record!(Header {
    parent: H32,
    parent_state_root: H32,
    extrinsic_hash: H32,
    slot: u32,
    epoch_mark: Option<EpochMark>,
    tickets_mark: Option<FixedSeq<TicketBody, EPOCH_LENGTH>>,
    author_index: u16,
    entropy_source: H96,
    offenders_mark: Vec<H32>,
    seal: H96,
});

record!(Extrinsic {
    tickets: Vec<TicketEnvelope>,
    preimages: Vec<Preimage>,
    guarantees: Vec<ReportGuarantee>,
    assurances: Vec<AvailAssurance>,
    disputes: DisputesExtrinsic,
});

record!(Block {
    header: Header,
    extrinsic: Extrinsic,
});
