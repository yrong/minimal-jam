//! JAM protocol types for the codec vectors (GP / `lib/jam-types.asn`).
//!
//! Field order mirrors the ASN.1 schema exactly — the codec encodes fields in
//! declaration order. Fixed-size sequences use [`FixedSeq`]; variable ones use
//! `Vec`. Tiny chain-spec sizes are baked into the `FixedSeq` const parameters.

use crate::codec::{Blob, Codec, CodecError, Compact, FixedSeq, Hex, Reader};
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

// --- Refine context / work package ----------------------------------------

codec_struct!(RefineContext {
    anchor: H32,
    state_root: H32,
    beefy_root: H32,
    lookup_anchor: H32,
    lookup_anchor_slot: u32,
    prerequisites: Vec<H32>,
});

codec_struct!(ImportSpec {
    tree_root: H32,
    index: u16,
});

codec_struct!(ExtrinsicSpec {
    hash: H32,
    len: u32,
});

codec_struct!(WorkItem {
    service: u32,
    code_hash: H32,
    refine_gas_limit: u64,
    accumulate_gas_limit: u64,
    export_count: u16,
    payload: Blob,
    import_segments: Vec<ImportSpec>,
    extrinsic: Vec<ExtrinsicSpec>,
});

codec_struct!(WorkPackage {
    auth_code_host: u32,
    auth_code_hash: H32,
    context: RefineContext,
    authorization: Blob,
    authorizer_config: Blob,
    items: Vec<WorkItem>,
});

// --- Work report ----------------------------------------------------------

/// Serializes to `null` (used as the payload of unit `WorkExecResult` variants).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Null;

/// `WorkExecResult` CHOICE: tag byte + payload (only `ok` carries data).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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

impl Codec for WorkExecResult {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            WorkExecResult::Ok(b) => {
                out.push(0);
                b.encode_to(out);
            }
            WorkExecResult::OutOfGas(_) => out.push(1),
            WorkExecResult::Panic(_) => out.push(2),
            WorkExecResult::BadExports(_) => out.push(3),
            WorkExecResult::OutputOversize(_) => out.push(4),
            WorkExecResult::BadCode(_) => out.push(5),
            WorkExecResult::CodeOversize(_) => out.push(6),
        }
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        Ok(match r.u8()? {
            0 => WorkExecResult::Ok(Blob::decode(r)?),
            1 => WorkExecResult::OutOfGas(Null),
            2 => WorkExecResult::Panic(Null),
            3 => WorkExecResult::BadExports(Null),
            4 => WorkExecResult::OutputOversize(Null),
            5 => WorkExecResult::BadCode(Null),
            6 => WorkExecResult::CodeOversize(Null),
            b => return Err(CodecError(format!("invalid WorkExecResult tag {b}"))),
        })
    }
}

codec_struct!(RefineLoad {
    gas_used: Compact,
    imports: Compact,
    extrinsic_count: Compact,
    extrinsic_size: Compact,
    exports: Compact,
});

codec_struct!(WorkResult {
    service_id: u32,
    code_hash: H32,
    payload_hash: H32,
    accumulate_gas: u64,
    result: WorkExecResult,
    refine_load: RefineLoad,
});

codec_struct!(WorkPackageSpec {
    hash: H32,
    length: u32,
    erasure_root: H32,
    exports_root: H32,
    exports_count: u16,
});

codec_struct!(SegmentRootLookupItem {
    work_package_hash: H32,
    segment_tree_root: H32,
});

codec_struct!(WorkReport {
    package_spec: WorkPackageSpec,
    context: RefineContext,
    core_index: Compact,
    authorizer_hash: H32,
    auth_gas_used: Compact,
    auth_output: Blob,
    segment_root_lookup: Vec<SegmentRootLookupItem>,
    results: Vec<WorkResult>,
});

// --- Tickets --------------------------------------------------------------

codec_struct!(TicketEnvelope {
    attempt: Compact,
    signature: H784,
});

codec_struct!(TicketBody {
    id: H32,
    attempt: Compact,
});

// --- Disputes -------------------------------------------------------------

codec_struct!(Judgement {
    vote: bool,
    index: u16,
    signature: H64,
});

codec_struct!(Verdict {
    target: H32,
    age: u32,
    votes: FixedSeq<Judgement, VALIDATORS_SUPER_MAJORITY>,
});

codec_struct!(Culprit {
    target: H32,
    key: H32,
    signature: H64,
});

codec_struct!(Fault {
    target: H32,
    vote: bool,
    key: H32,
    signature: H64,
});

codec_struct!(DisputesExtrinsic {
    verdicts: Vec<Verdict>,
    culprits: Vec<Culprit>,
    faults: Vec<Fault>,
});

// --- Preimages / assurances / guarantees ----------------------------------

codec_struct!(Preimage {
    requester: u32,
    blob: Blob,
});

codec_struct!(AvailAssurance {
    anchor: H32,
    bitfield: Bitfield,
    validator_index: u16,
    signature: H64,
});

codec_struct!(ValidatorSignature {
    validator_index: u16,
    signature: H64,
});

codec_struct!(ReportGuarantee {
    report: WorkReport,
    slot: u32,
    signatures: Vec<ValidatorSignature>,
});

// --- Header / block -------------------------------------------------------

codec_struct!(EpochMarkValidatorKeys {
    bandersnatch: H32,
    ed25519: H32,
});

codec_struct!(EpochMark {
    entropy: H32,
    tickets_entropy: H32,
    validators: FixedSeq<EpochMarkValidatorKeys, VALIDATORS_COUNT>,
});

codec_struct!(Header {
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

codec_struct!(Extrinsic {
    tickets: Vec<TicketEnvelope>,
    preimages: Vec<Preimage>,
    guarantees: Vec<ReportGuarantee>,
    assurances: Vec<AvailAssurance>,
    disputes: DisputesExtrinsic,
});

codec_struct!(Block {
    header: Header,
    extrinsic: Extrinsic,
});
