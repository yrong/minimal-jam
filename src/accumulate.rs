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

use crate::accumulate_exec::{accounts_map, run_service, Operand};
use crate::bytes::{Blob, FixedSeq, Hex};
use crate::state::{
    AccumulatedQueue, ReadyQueue, ReadyRecord, ServiceActivityRecord, ServiceInfo, ServiceStatEntry,
};
use crate::types::{WorkExecResult, WorkReport, CORE_COUNT, EPOCH_LENGTH, H32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

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

    // --- Gas-bounded accumulation execution ---
    // Tiny block accumulation gas: max(block_gas_limit, report_acc_gas·cores).
    const BLOCK_ACC_GAS: i64 = 20_000_000;
    let mut acc_reports: Vec<WorkReport> = Vec::new();
    let mut gas_total = 0i64;
    for r in &accumulatable {
        let rg: i64 = r.results.iter().map(|d| d.accumulate_gas as i64).sum();
        if gas_total + rg > BLOCK_ACC_GAS {
            break;
        }
        gas_total += rg;
        acc_reports.push(r.clone());
    }

    let mut accounts = accounts_map(&pre.accounts);
    let mut services: Vec<u32> = Vec::new();
    for r in &acc_reports {
        for d in &r.results {
            if !services.contains(&d.service_id) {
                services.push(d.service_id);
            }
        }
    }
    let mut stat_map: BTreeMap<u32, (u32, u64)> = BTreeMap::new();
    let mut yields: Vec<(u32, [u8; 32])> = Vec::new();
    let mut deferred: Vec<crate::accumulate_exec::Transfer> = Vec::new();
    for &s in &services {
        let mut operands = Vec::new();
        let mut gas_s = 0i64;
        for r in &acc_reports {
            for d in &r.results {
                if d.service_id != s {
                    continue;
                }
                gas_s += d.accumulate_gas as i64;
                operands.push(Operand {
                    package_hash: r.package_spec.hash.0,
                    seg_root: r.package_spec.exports_root.0,
                    authorizer: r.authorizer_hash.0,
                    payload_hash: d.payload_hash.0,
                    gas_limit: d.accumulate_gas,
                    auth_trace: r.auth_output.0.clone(),
                    result: work_result(&d.result),
                });
            }
        }
        let count = operands.len() as u32;
        let code = accounts
            .get(&s)
            .and_then(|a| {
                let ch = a.service.code_hash.0;
                a.preimage_blobs.iter().find(|p| p.hash.0 == ch).map(|p| p.blob.0.clone())
            })
            .unwrap_or_default();
        let out = run_service(&code, input.slot, s, gas_s, &operands, accounts);
        accounts = out.accounts;
        stat_map.insert(s, (count, out.gas_used as u64));
        if let Some(h) = out.yielded {
            yields.push((s, h));
        }
        deferred.extend(out.transfers);
    }
    // Apply deferred transfers: credit the destination if it still exists,
    // otherwise the funds are burnt (e.g. the destination was ejected).
    for t in &deferred {
        if let Some(a) = accounts.get_mut(&t.dest) {
            a.service.balance += t.amount;
        }
    }
    // Update the last-accumulation slot for every accumulated service.
    for &s in &services {
        if let Some(a) = accounts.get_mut(&s) {
            a.service.last_accumulation_slot = input.slot;
        }
    }
    let n = acc_reports.len();

    let mut post = pre.clone();
    post.slot = input.slot;
    post.accounts = accounts
        .into_iter()
        .map(|(id, data)| AccountsMapEntry { id, data })
        .collect();
    post.statistics = stat_map
        .into_iter()
        .map(|(id, (count, gas))| ServiceStatEntry {
            id,
            record: ServiceActivityRecord {
                accumulate_count: count,
                accumulate_gas_used: gas,
                ..zero_service_record()
            },
        })
        .collect();

    // Shift the accumulated ring buffer; the newest slot holds this block's
    // accumulated package hashes.
    let mut accd = pre.accumulated.0.clone();
    for i in 0..EPOCH - 1 {
        accd[i] = pre.accumulated.0[i + 1].clone();
    }
    let mut newest: Vec<H32> = acc_reports.iter().map(|r| r.package_spec.hash.clone()).collect();
    newest.sort_by(|a, b| a.0.cmp(&b.0));
    accd[EPOCH - 1] = newest.clone();
    post.accumulated = FixedSeq(accd);
    let newest_raw: Vec<[u8; 32]> = newest.iter().map(|h| h.0).collect();

    // Rebuild the ready ring buffer (GP eq. finalstateaccumulation).
    let gap = (input.slot - pre.slot) as usize;
    let mut ready = pre.ready_queue.0.clone();
    for i in 0..EPOCH {
        let idx = (m + EPOCH - i) % EPOCH;
        ready[idx] = if i == 0 {
            edit(&queued, &newest_raw).iter().map(pending_to_record).collect()
        } else if i < gap {
            Vec::new()
        } else {
            let old: Vec<Pending> = pre.ready_queue.0[idx].iter().map(record_to_pending).collect();
            edit(&old, &newest_raw).iter().map(pending_to_record).collect()
        };
    }
    post.ready_queue = FixedSeq(ready);

    let root = if yields.is_empty() {
        [0u8; 32]
    } else {
        accumulation_root(&yields)
    };
    let _ = n;
    (Outcome::Ok(Hex(root)), post)
}

/// Map a work-execution result to the operand result (`Ok` blob or error code).
fn work_result(r: &WorkExecResult) -> Result<Vec<u8>, u8> {
    match r {
        WorkExecResult::Ok(b) => Ok(b.0.clone()),
        WorkExecResult::OutOfGas(_) => Err(1),
        WorkExecResult::Panic(_) => Err(2),
        WorkExecResult::BadExports(_) => Err(3),
        WorkExecResult::OutputOversize(_) => Err(4),
        WorkExecResult::BadCode(_) => Err(5),
        WorkExecResult::CodeOversize(_) => Err(6),
    }
}

/// A zeroed service-activity record.
fn zero_service_record() -> ServiceActivityRecord {
    ServiceActivityRecord {
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
    }
}

/// Accumulation-output root: the keccak well-balanced binary Merkle root
/// (GP `M_B`) of the service-indexed yields, leaves `E4(s) ‖ h`, sorted by
/// service. Empty yields give the zero hash.
fn accumulation_root(yields: &[(u32, [u8; 32])]) -> [u8; 32] {
    let mut pairs = yields.to_vec();
    pairs.sort_by_key(|(s, _)| *s);
    let leaves: Vec<Vec<u8>> = pairs
        .iter()
        .map(|(s, h)| {
            let mut leaf = s.to_le_bytes().to_vec();
            leaf.extend_from_slice(h);
            leaf
        })
        .collect();
    match leaves.len() {
        0 => [0u8; 32],
        1 => crate::crypto::keccak_256(&leaves[0]),
        _ => {
            let node = merkle_node(&leaves);
            let mut h = [0u8; 32];
            h.copy_from_slice(&node);
            h
        }
    }
}

/// GP Merkle node function `N` (keccak, `$node` prefix). A single node returns
/// its blob verbatim (possibly wider than 32 octets); combined nodes hash to 32.
fn merkle_node(v: &[Vec<u8>]) -> Vec<u8> {
    match v.len() {
        0 => vec![0u8; 32],
        1 => v[0].clone(),
        _ => {
            let mid = v.len().div_ceil(2);
            let mut buf = b"$node".to_vec();
            buf.extend_from_slice(&merkle_node(&v[..mid]));
            buf.extend_from_slice(&merkle_node(&v[mid..]));
            crate::crypto::keccak_256(&buf).to_vec()
        }
    }
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

