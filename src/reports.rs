//! Work-report guarantees STF (GP §11 `\availassignmentspostguarantees`).
//!
//! Validates the guarantees extrinsic — guarantor assignment (entropy shuffle +
//! rotation), Ed25519 credentials, contextual validity of each work-report
//! (anchor recency, dependencies, gas, authorization) — then assigns the
//! accepted reports to their cores and updates core/service statistics.

use crate::bytes::{FixedSeq, Hex};
use crate::crypto::{blake2b_256, ed25519_verify};
use crate::state::{
    AuthPools, AvailabilityAssignment, AvailabilityAssignments, BlockInfo, CoreActivityRecord,
    EntropyBuffer, RecentBlocks, ServiceActivityRecord, ServiceInfo, ServiceStatEntry, ValidatorData,
};
use crate::types::{ReportGuarantee, CORE_COUNT, EPOCH_LENGTH, H32, VALIDATORS_COUNT};
use jam_codec::Encode;
use serde::{Deserialize, Serialize};

const EPOCH: u32 = EPOCH_LENGTH as u32;
/// Validator-core rotation period, in slots (tiny chain-spec).
const ROTATION: u32 = 4;
/// Maximum sum of dependency items in a work-report (`C_maxreportdeps`).
const MAX_REPORT_DEPS: usize = 8;
/// Maximum age of a lookup anchor, in slots (`C_maxlookupanchorage`).
const MAX_LOOKUP_ANCHOR_AGE: u32 = 14_400;
/// Per-report accumulation gas ceiling (`C_reportaccgas`).
const REPORT_ACC_GAS: u64 = 10_000_000;
/// Maximum total size of unbounded blobs in a report (`C_maxreportvarsize`).
const MAX_REPORT_VAR_SIZE: usize = 48 * 1024;

/// A service account (only the metadata relevant to this STF).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub service: ServiceInfo,
}

/// One `(service id, account)` entry of the accounts map.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountsMapEntry {
    pub id: u32,
    pub data: Account,
}

/// Reports STF state (`stf/reports` schema).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub avail_assignments: AvailabilityAssignments,
    pub curr_validators: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub prev_validators: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub entropy: EntropyBuffer,
    pub offenders: Vec<H32>,
    pub recent_blocks: RecentBlocks,
    pub auth_pools: AuthPools,
    pub accounts: Vec<AccountsMapEntry>,
    pub cores_statistics: FixedSeq<CoreActivityRecord, CORE_COUNT>,
    pub services_statistics: Vec<ServiceStatEntry>,
}

/// STF input: the guarantees extrinsic, block slot, and known-package set.
#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    pub guarantees: Vec<ReportGuarantee>,
    pub slot: u32,
    pub known_packages: Vec<H32>,
}

/// A package hash and its segment-tree (exports) root.
#[derive(Clone, Debug, Serialize)]
pub struct ReportedPackage {
    pub work_package_hash: H32,
    pub segment_tree_root: H32,
}

/// Output payload on success.
#[derive(Clone, Debug, Serialize)]
pub struct OutputData {
    pub reported: Vec<ReportedPackage>,
    pub reporters: Vec<H32>,
}

/// Reports STF validity errors (GP leaves the codes unspecified).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportsError {
    BadCoreIndex,
    FutureReportSlot,
    ReportEpochBeforeLast,
    InsufficientGuarantees,
    OutOfOrderGuarantee,
    NotSortedOrUniqueGuarantors,
    WrongAssignment,
    CoreEngaged,
    AnchorNotRecent,
    BadServiceId,
    BadCodeHash,
    DependencyMissing,
    DuplicatePackage,
    BadStateRoot,
    BadBeefyMmrRoot,
    CoreUnauthorized,
    BadValidatorIndex,
    WorkReportGasTooHigh,
    ServiceItemGasTooLow,
    TooManyDependencies,
    SegmentRootLookupInvalid,
    BadSignature,
    WorkReportTooBig,
    BannedValidator,
    LookupAnchorNotRecent,
    MissingWorkResults,
}

/// STF outcome, serializing to the vector's `output` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok(OutputData),
    Err(ReportsError),
}

/// Apply the reports STF.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    match run(pre, input) {
        Ok((out, post)) => (Outcome::Ok(out), post),
        Err(err) => (Outcome::Err(err), pre.clone()),
    }
}

/// Guarantor assignment: core index per validator, from an entropy shuffle of
/// `[⌊i/3⌋]` rotated by `⌊(t mod E) / ROTATION⌋`.
fn assignment(validators: usize, entropy: &[u8; 32], t: u32) -> Vec<usize> {
    let base: Vec<usize> = (0..validators).map(|i| i / 3).collect();
    let shuffled = fisher_yates(base, entropy);
    let cores = validators / 3;
    let rotate = ((t % EPOCH) / ROTATION) as usize;
    shuffled.iter().map(|c| (c + rotate) % cores).collect()
}

/// Fisher-Yates shuffle seeded by a 32-byte hash (GP §Shuffling).
fn fisher_yates<T: Clone>(mut s: Vec<T>, seed: &[u8; 32]) -> Vec<T> {
    let r = seq_from_hash(s.len(), seed);
    let mut out = Vec::with_capacity(s.len());
    let mut len = s.len();
    for ri in r.iter().take(s.len()) {
        let idx = (*ri as usize) % len;
        out.push(s[idx].clone());
        s[idx] = s[len - 1].clone();
        len -= 1;
    }
    out
}

/// Numeric-sequence-from-hash `Q` (GP eq. sequencefromhash).
fn seq_from_hash(len: usize, seed: &[u8; 32]) -> Vec<u32> {
    (0..len)
        .map(|i| {
            let mut buf = seed.to_vec();
            buf.extend_from_slice(&((i / 8) as u32).to_le_bytes());
            let hash = blake2b_256(&buf);
            let off = (4 * i) % 32;
            u32::from_le_bytes([hash[off], hash[off + 1], hash[off + 2], hash[off + 3]])
        })
        .collect()
}

fn run(pre: &State, input: &Input) -> Result<(OutputData, State), ReportsError> {
    let slot = input.slot;
    let validators = pre.curr_validators.0.len();
    let active_cores = validators / 3;

    // History after the parent state-root update (β): used for anchor and
    // dependency lookups.
    let history = &pre.recent_blocks.history;

    // Package hashes present in this extrinsic (for dependency resolution and
    // duplicate detection).
    let incoming: Vec<(H32, H32)> = input
        .guarantees
        .iter()
        .map(|g| {
            (
                g.report.package_spec.hash.clone(),
                g.report.package_spec.exports_root.clone(),
            )
        })
        .collect();

    // Guarantees must be ordered and unique by core index.
    let mut prev_core: Option<u16> = None;
    for g in &input.guarantees {
        let core = g.report.core_index;
        if core as usize >= CORE_COUNT {
            return Err(ReportsError::BadCoreIndex);
        }
        if let Some(p) = prev_core {
            if core <= p {
                return Err(ReportsError::OutOfOrderGuarantee);
            }
        }
        prev_core = Some(core);
    }

    let mut reporters: Vec<H32> = Vec::new();

    for g in &input.guarantees {
        let report = &g.report;
        let core = report.core_index as usize;

        // Guarantee slot must be within this or the previous rotation.
        if g.slot > slot {
            return Err(ReportsError::FutureReportSlot);
        }
        let last_rotation_start = ROTATION * (slot / ROTATION).saturating_sub(1);
        if g.slot < last_rotation_start {
            return Err(ReportsError::ReportEpochBeforeLast);
        }

        // Guarantors ordered and unique by validator index; 2–3 credentials.
        let mut prev_v: Option<u16> = None;
        for s in &g.signatures {
            if let Some(p) = prev_v {
                if s.validator_index <= p {
                    return Err(ReportsError::NotSortedOrUniqueGuarantors);
                }
            }
            prev_v = Some(s.validator_index);
        }
        if g.signatures.len() < 2 {
            return Err(ReportsError::InsufficientGuarantees);
        }

        // Select the guarantor assignment for the guarantee's rotation.
        let (cores, keys) = assignment_for(pre, slot, g.slot, validators);

        let report_hash = blake2b_256(&report.encode());
        let mut msg = b"jam_guarantee".to_vec();
        msg.extend_from_slice(&report_hash);

        for s in &g.signatures {
            let v = s.validator_index as usize;
            if v >= validators {
                return Err(ReportsError::BadValidatorIndex);
            }
            if cores[v] != core || core >= active_cores {
                return Err(ReportsError::WrongAssignment);
            }
            let key = &keys.0[v].ed25519.0;
            if pre.offenders.iter().any(|o| o.0 == *key) {
                return Err(ReportsError::BannedValidator);
            }
            if !ed25519_verify(key, &msg, &s.signature.0) {
                return Err(ReportsError::BadSignature);
            }
            reporters.push(Hex(*key));
        }

        // --- Work-report validity ---

        if report.results.is_empty() {
            return Err(ReportsError::MissingWorkResults);
        }

        // Core must be free.
        if pre.avail_assignments.0[core].is_some() {
            return Err(ReportsError::CoreEngaged);
        }

        // Authorizer must be in the core's pool.
        if !pre.auth_pools.0[core].iter().any(|a| a.0 == report.authorizer_hash.0) {
            return Err(ReportsError::CoreUnauthorized);
        }

        // Anchor must appear in recent history with matching fields.
        let anchor = &report.context.anchor;
        let matched = history.iter().find(|b| b.header_hash.0 == anchor.0);
        match matched {
            None => return Err(ReportsError::AnchorNotRecent),
            Some(b) => {
                if b.state_root.0 != report.context.state_root.0 {
                    return Err(ReportsError::BadStateRoot);
                }
                if b.beefy_root.0 != report.context.beefy_root.0 {
                    return Err(ReportsError::BadBeefyMmrRoot);
                }
            }
        }

        // Lookup anchor age.
        if report.context.lookup_anchor_slot + MAX_LOOKUP_ANCHOR_AGE < slot {
            return Err(ReportsError::LookupAnchorNotRecent);
        }

        // Dependency count.
        let deps = report.context.prerequisites.len() + report.segment_root_lookup.len();
        if deps > MAX_REPORT_DEPS {
            return Err(ReportsError::TooManyDependencies);
        }

        // Per-result service checks and gas.
        let mut total_gas: u64 = 0;
        for r in &report.results {
            let account = pre.accounts.iter().find(|a| a.id == r.service_id);
            let Some(account) = account else {
                return Err(ReportsError::BadServiceId);
            };
            if r.code_hash.0 != account.data.service.code_hash.0 {
                return Err(ReportsError::BadCodeHash);
            }
            if r.accumulate_gas < account.data.service.min_item_gas {
                return Err(ReportsError::ServiceItemGasTooLow);
            }
            total_gas += r.accumulate_gas;
        }
        if total_gas > REPORT_ACC_GAS {
            return Err(ReportsError::WorkReportGasTooHigh);
        }

        // Output size (auth output + `ok` result blobs).
        let mut out_size = report.auth_output.0.len();
        for r in &report.results {
            if let crate::types::WorkExecResult::Ok(blob) = &r.result {
                out_size += blob.0.len();
            }
        }
        if out_size > MAX_REPORT_VAR_SIZE {
            return Err(ReportsError::WorkReportTooBig);
        }

        // Dependencies and segment-root lookups must resolve.
        for p in &report.context.prerequisites {
            if !resolvable(&p.0, &incoming, history) {
                return Err(ReportsError::DependencyMissing);
            }
        }
        for item in &report.segment_root_lookup {
            if !seg_root_matches(
                &item.work_package_hash.0,
                &item.segment_tree_root.0,
                &incoming,
                history,
            ) {
                return Err(ReportsError::SegmentRootLookupInvalid);
            }
        }
    }

    // Duplicate package hashes: within the extrinsic and against history.
    for (i, (hash, _)) in incoming.iter().enumerate() {
        if incoming[..i].iter().any(|(h, _)| h.0 == hash.0) {
            return Err(ReportsError::DuplicatePackage);
        }
        if input.known_packages.iter().any(|k| k.0 == hash.0)
            || history
                .iter()
                .any(|b| b.reported.iter().any(|rp| rp.hash.0 == hash.0))
        {
            return Err(ReportsError::DuplicatePackage);
        }
    }

    // --- State transition: assign reports, update statistics ---
    let mut post = pre.clone();
    let mut reported: Vec<ReportedPackage> = Vec::new();

    for g in &input.guarantees {
        let report = &g.report;
        let core = report.core_index as usize;

        reported.push(ReportedPackage {
            work_package_hash: report.package_spec.hash.clone(),
            segment_tree_root: report.package_spec.exports_root.clone(),
        });

        post.avail_assignments.0[core] = Some(AvailabilityAssignment {
            report: report.clone(),
            timeout: slot,
        });

        // Core statistics.
        let cs = &mut post.cores_statistics.0[core];
        cs.bundle_size += report.package_spec.length;
        for r in &report.results {
            cs.imports += r.refine_load.imports;
            cs.extrinsic_count += r.refine_load.extrinsic_count;
            cs.extrinsic_size += r.refine_load.extrinsic_size;
            cs.exports += r.refine_load.exports;
            cs.gas_used += r.refine_load.gas_used;
        }

        // Service statistics (aggregated per service across its results).
        for r in &report.results {
            let entry = service_entry(&mut post.services_statistics, r.service_id);
            entry.refinement_count += 1;
            entry.refinement_gas_used += r.refine_load.gas_used;
            entry.imports += r.refine_load.imports as u32;
            entry.extrinsic_count += r.refine_load.extrinsic_count as u32;
            entry.extrinsic_size += r.refine_load.extrinsic_size;
            entry.exports += r.refine_load.exports as u32;
        }
    }
    // Reporters and reported packages form sets: sorted and unique.
    reported.sort_by(|a, b| a.work_package_hash.0.cmp(&b.work_package_hash.0));
    reporters.sort_by(|a, b| a.0.cmp(&b.0));
    reporters.dedup_by(|a, b| a.0 == b.0);
    Ok((OutputData { reported, reporters }, post))
}

/// Pick the `(cores, keys)` guarantor assignment for a guarantee whose slot is
/// `guarantee_slot`, relative to the block `slot`.
fn assignment_for<'a>(
    pre: &'a State,
    slot: u32,
    guarantee_slot: u32,
    validators: usize,
) -> (Vec<usize>, &'a FixedSeq<ValidatorData, VALIDATORS_COUNT>) {
    if slot / ROTATION == guarantee_slot / ROTATION {
        // Same rotation as the block: current assignment.
        (
            assignment(validators, &pre.entropy.0[2].0, slot),
            &pre.curr_validators,
        )
    } else {
        // Previous rotation.
        let prev_slot = slot.saturating_sub(ROTATION);
        if prev_slot / EPOCH == slot / EPOCH {
            (
                assignment(validators, &pre.entropy.0[2].0, prev_slot),
                &pre.curr_validators,
            )
        } else {
            (
                assignment(pre.prev_validators.0.len(), &pre.entropy.0[3].0, prev_slot),
                &pre.prev_validators,
            )
        }
    }
}

/// A package hash resolves if it is in the extrinsic or recent history.
fn resolvable(hash: &[u8; 32], incoming: &[(H32, H32)], history: &[BlockInfo]) -> bool {
    incoming.iter().any(|(h, _)| h.0 == *hash)
        || history
            .iter()
            .any(|b| b.reported.iter().any(|rp| rp.hash.0 == *hash))
}

/// A segment-root lookup matches if the package's exports root equals `root`.
fn seg_root_matches(
    hash: &[u8; 32],
    root: &[u8; 32],
    incoming: &[(H32, H32)],
    history: &[BlockInfo],
) -> bool {
    if let Some((_, r)) = incoming.iter().find(|(h, _)| h.0 == *hash) {
        return r.0 == *root;
    }
    for b in history {
        if let Some(rp) = b.reported.iter().find(|rp| rp.hash.0 == *hash) {
            return rp.exports_root.0 == *root;
        }
    }
    false
}

/// Get (or insert) the mutable service-statistics entry for `id`.
fn service_entry(stats: &mut Vec<ServiceStatEntry>, id: u32) -> &mut ServiceActivityRecord {
    if let Some(pos) = stats.iter().position(|e| e.id == id) {
        return &mut stats[pos].record;
    }
    stats.push(ServiceStatEntry {
        id,
        record: ServiceActivityRecord {
            provided_count: 0,
            provided_size: 0,
            refinement_count: 0,
            refinement_gas_used: 0,
            imports: 0,
            extrinsic_count: 0,
            extrinsic_size: 0,
            exports: 0,
            accumulate_count: 0,
            accumulate_gas_used: 0,
        },
    });
    let last = stats.len() - 1;
    &mut stats[last].record
}
