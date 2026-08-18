//! Accumulate STF (GP §12) — history, queuing, and dependency resolution.
//!
//! This slice implements the **queue management** half of accumulation: it
//! partitions newly-available reports into immediately-accumulatable and
//! deferred (dependency-bearing) ones, resolves the ready-queue dependency
//! graph, and shifts the ready (`ϑ`) and accumulated (`ξ`) ring buffers.
//!
//! The **execution** half — invoking each service's `accumulate` logic in the
//! PVM with the host-call ABI, deferred transfers, and the keccak accumulation
//! output root — is not yet implemented; vectors that actually accumulate a
//! report (immediate or dependency-resolved) are therefore not yet handled.

use crate::bytes::{Blob, FixedSeq, Hex};
use crate::state::{
    AccumulatedQueue, ReadyQueue, ReadyRecord, ServiceInfo, ServiceStatEntry,
};
use crate::types::{WorkReport, CORE_COUNT, EPOCH_LENGTH, H32};
use serde::{Deserialize, Serialize};

const EPOCH: usize = EPOCH_LENGTH;

/// A single service-storage key/value pair.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StorageMapEntry {
    pub key: Blob,
    pub value: Blob,
}

/// A provided preimage blob keyed by its hash.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreimagesBlobMapEntry {
    pub hash: H32,
    pub blob: Blob,
}

/// A preimage-request key (blob hash + length).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreimagesRequestsMapKey {
    pub hash: H32,
    pub length: u32,
}

/// A preimage request and its status (0–3 timeslots).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreimagesRequestsMapEntry {
    pub key: PreimagesRequestsMapKey,
    pub value: Vec<u32>,
}

/// A service account (`a`): metadata, storage, and preimages.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServiceAccount {
    pub service: ServiceInfo,
    pub storage: Vec<StorageMapEntry>,
    pub preimage_blobs: Vec<PreimagesBlobMapEntry>,
    pub preimage_requests: Vec<PreimagesRequestsMapEntry>,
}

/// One `(service id, account)` entry of `δ`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AccountsMapEntry {
    pub id: u32,
    pub data: ServiceAccount,
}

/// A free-accumulation grant `(service id, gas)`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AlwaysAccEntry {
    pub id: u32,
    pub gas: u64,
}

/// Privileged-service indices (`χ`).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Privileges {
    pub bless: u32,
    pub assign: FixedSeq<u32, CORE_COUNT>,
    pub designate: u32,
    pub register: u32,
    pub always_acc: Vec<AlwaysAccEntry>,
}

/// Accumulate STF state (`stf/accumulate` schema).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub slot: u32,
    pub entropy: H32,
    pub ready_queue: ReadyQueue,
    pub accumulated: AccumulatedQueue,
    pub privileges: Privileges,
    pub statistics: Vec<ServiceStatEntry>,
    pub accounts: Vec<AccountsMapEntry>,
}

/// STF input: the block slot and newly-available work reports.
#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    pub slot: u32,
    pub reports: Vec<WorkReport>,
}

/// STF outcome, serializing to the vector's `output` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok(H32),
    Err(()),
}

/// A report together with its outstanding dependencies (`ϑ` entry).
type Pending = (WorkReport, Vec<[u8; 32]>);

fn package_hash(r: &WorkReport) -> [u8; 32] {
    r.package_spec.hash.0
}

fn dependencies(r: &WorkReport) -> Vec<[u8; 32]> {
    let mut deps: Vec<[u8; 32]> = r.context.prerequisites.iter().map(|h| h.0).collect();
    deps.extend(r.segment_root_lookup.iter().map(|s| s.work_package_hash.0));
    deps
}

/// Queue-editing `E`: drop reports already accumulated, and drop resolved deps.
fn edit(records: &[Pending], accumulated: &[[u8; 32]]) -> Vec<Pending> {
    records
        .iter()
        .filter(|(r, _)| !accumulated.contains(&package_hash(r)))
        .map(|(r, deps)| {
            let deps = deps.iter().copied().filter(|d| !accumulated.contains(d)).collect();
            (r.clone(), deps)
        })
        .collect()
}

/// Priority queue `Q`: reports that can be accumulated, in dependency order.
fn priority(records: &[Pending]) -> Vec<WorkReport> {
    let ready: Vec<WorkReport> = records
        .iter()
        .filter(|(_, deps)| deps.is_empty())
        .map(|(r, _)| r.clone())
        .collect();
    if ready.is_empty() {
        return Vec::new();
    }
    let hashes: Vec<[u8; 32]> = ready.iter().map(package_hash).collect();
    let rest = edit(records, &hashes);
    let mut out = ready;
    out.extend(priority(&rest));
    out
}

/// Apply the accumulate STF.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    let m = input.slot as usize % EPOCH;
    let accumulated_cup: Vec<[u8; 32]> = pre.accumulated.0.iter().flatten().map(|h| h.0).collect();

    // Partition newly-available reports.
    let immediate: Vec<WorkReport> = input
        .reports
        .iter()
        .filter(|r| r.context.prerequisites.is_empty() && r.segment_root_lookup.is_empty())
        .cloned()
        .collect();
    let queued_raw: Vec<Pending> = input
        .reports
        .iter()
        .filter(|r| !r.context.prerequisites.is_empty() || !r.segment_root_lookup.is_empty())
        .map(|r| (r.clone(), dependencies(r)))
        .collect();
    let queued = edit(&queued_raw, &accumulated_cup);

    // Assemble the accumulation candidate sequence W*.
    let immediate_hashes: Vec<[u8; 32]> = immediate.iter().map(package_hash).collect();
    let mut q_input: Vec<Pending> = Vec::new();
    for i in 0..EPOCH {
        q_input.extend(pre.ready_queue.0[(m + i) % EPOCH].iter().map(record_to_pending));
    }
    q_input.extend(queued.iter().cloned());
    let q_input = edit(&q_input, &immediate_hashes);
    let mut accumulatable = immediate.clone();
    accumulatable.extend(priority(&q_input));

    // Execution is not yet implemented: bail (post == pre) so accumulating
    // vectors fail loudly rather than producing a wrong state.
    if !accumulatable.is_empty() {
        return (Outcome::Ok(Hex([0u8; 32])), pre.clone());
    }

    // --- n = 0: pure queue integration ---
    let mut post = pre.clone();
    post.slot = input.slot;
    // π_S holds only this block's accumulation stats; nothing accumulated → empty.
    post.statistics = Vec::new();

    // Shift the accumulated ring buffer; the newest slot holds this block's
    // accumulated package hashes (none here).
    let mut accd = pre.accumulated.0.clone();
    for i in 0..EPOCH - 1 {
        accd[i] = pre.accumulated.0[i + 1].clone();
    }
    accd[EPOCH - 1] = Vec::new();
    post.accumulated = FixedSeq(accd);
    let newest: Vec<[u8; 32]> = post.accumulated.0[EPOCH - 1].iter().map(|h| h.0).collect();

    // Rebuild the ready ring buffer (GP eq. finalstateaccumulation).
    let gap = (input.slot - pre.slot) as usize;
    let mut ready = pre.ready_queue.0.clone();
    for i in 0..EPOCH {
        let idx = (m + EPOCH - i) % EPOCH;
        ready[idx] = if i == 0 {
            edit(&queued, &newest).iter().map(pending_to_record).collect()
        } else if i < gap {
            Vec::new()
        } else {
            let old: Vec<Pending> = pre.ready_queue.0[idx].iter().map(record_to_pending).collect();
            edit(&old, &newest).iter().map(pending_to_record).collect()
        };
    }
    post.ready_queue = FixedSeq(ready);

    (Outcome::Ok(Hex([0u8; 32])), post)
}

fn record_to_pending(r: &ReadyRecord) -> Pending {
    (r.report.clone(), r.dependencies.iter().map(|h| h.0).collect())
}

fn pending_to_record((report, deps): &Pending) -> ReadyRecord {
    ReadyRecord {
        report: report.clone(),
        dependencies: deps.iter().map(|d| Hex(*d)).collect(),
    }
}

