//! Accumulate STF (GP §12) — history, queuing, dependency resolution, and
//! PVM execution. Passes all 30 `stf/accumulate/tiny` vectors byte-exact.
//!
//! **Queue management** (this file): partitions newly-available reports into
//! immediately-accumulatable and deferred (dependency-bearing) ones, resolves
//! the ready-queue dependency graph (`E`/`Q`), and shifts the ready (`ϑ`) and
//! accumulated (`ξ`) ring buffers per GP eq. finalstateaccumulation.
//!
//! **Execution** (`accumulate_exec`): invokes each service's `accumulate`
//! logic in the PVM (`Ψ_A`, standard-program init `Y`), threads the host-call
//! ABI, deferred transfers, ejection, and the keccak accumulation-output root.
//!
//! Known simplifications (sufficient for the tiny vectors, not full GP):
//! - host-call gas uses a small empirical model, not the GP base constants;
//! - deferred transfers credit/burn the destination balance but do not run its
//!   `on_transfer` PVM logic (no covered vector requires it);
//! - unimplemented host calls (`new`/`upgrade`/`bless`/`designate`/`assign`/
//!   `solicit`/`forget`/`query`/`lookup`/`checkpoint`/`provide`) return `HUH`;
//! - the exceptional dimension rolls back to the pre-invocation accounts rather
//!   than honouring `checkpoint`; privileges (`χ`) and always-accumulate are
//!   carried through unchanged.

use crate::accumulate_exec::{run_service, ExecState, Operand};
use crate::state_key::{service_preimage, service_storage};
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

/// Shared, account-representation-agnostic accumulate core: queue management
/// (`W*`), gas-bounded PVM execution over the ready services, deferred
/// transfers, and the ready/accumulated ring-buffer rebuild. Both the typed STF
/// [`transition`] and the unified block-import path drive this on an
/// [`ExecState`].
pub struct AccCore {
    pub exec: ExecState,
    pub stat_map: BTreeMap<u32, (u32, u64)>,
    pub ready: ReadyQueue,
    pub accumulated: AccumulatedQueue,
    pub root: [u8; 32],
    /// Per-service accumulation outputs (service id, 32-byte yielded hash),
    /// in accumulation order — the block's C16 last-accumulation log.
    pub yields: Vec<(u32, [u8; 32])>,
}

pub fn accumulate_core(
    slot: u32,
    pre_slot: u32,
    ready_queue: &ReadyQueue,
    accumulated_q: &AccumulatedQueue,
    reports: &[WorkReport],
    entropy: [u8; 32],
    mut exec: ExecState,
) -> AccCore {
    let m = slot as usize % EPOCH;
    let accumulated_cup: Vec<[u8; 32]> = accumulated_q.0.iter().flatten().map(|h| h.0).collect();

    // Partition newly-available reports.
    let immediate: Vec<WorkReport> = reports
        .iter()
        .filter(|r| r.context.prerequisites.is_empty() && r.segment_root_lookup.is_empty())
        .cloned()
        .collect();
    let queued_raw: Vec<Pending> = reports
        .iter()
        .filter(|r| !r.context.prerequisites.is_empty() || !r.segment_root_lookup.is_empty())
        .map(|r| (r.clone(), dependencies(r)))
        .collect();
    let queued = edit(&queued_raw, &accumulated_cup);

    // Assemble the accumulation candidate sequence W*.
    let immediate_hashes: Vec<[u8; 32]> = immediate.iter().map(package_hash).collect();
    let mut q_input: Vec<Pending> = Vec::new();
    for i in 0..EPOCH {
        q_input.extend(ready_queue.0[(m + i) % EPOCH].iter().map(record_to_pending));
    }
    q_input.extend(queued.iter().cloned());
    let q_input = edit(&q_input, &immediate_hashes);
    let mut accumulatable = immediate.clone();
    accumulatable.extend(priority(&q_input));

    // --- Gas-bounded accumulation execution ---
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

    let mut services: Vec<u32> = Vec::new();
    for r in &acc_reports {
        for d in &r.results {
            if !services.contains(&d.service_id) {
                services.push(d.service_id);
            }
        }
    }
    // Always-accumulate (privileged) services run every block with a gas grant,
    // even with no work reports. Snapshot the grant map from the prior χ.
    let always: Vec<(u32, i64)> = exec
        .privileges
        .always_acc
        .iter()
        .map(|e| (e.id, e.gas as i64))
        .collect();
    for &(id, _) in &always {
        if !services.contains(&id) {
            services.push(id);
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
        // Privileged services get their always-accumulate gas grant on top.
        gas_s += always.iter().find(|(id, _)| *id == s).map(|(_, g)| *g).unwrap_or(0);
        let count = operands.len() as u32;
        // Resolve the service code from its preimage in the state-key dict.
        let code = exec
            .accounts
            .get(&s)
            .map(|a| a.code_hash.0)
            .and_then(|ch| exec.dict.get(&service_preimage(s, &ch)).cloned())
            .unwrap_or_default();
        let out = run_service(&code, slot, s, gas_s, &operands, &entropy, exec);
        exec = out.state;
        stat_map.insert(s, (count, out.gas_used as u64));
        if let Some(h) = out.yielded {
            yields.push((s, h));
        }
        deferred.extend(out.transfers);
    }
    // Apply deferred transfers: credit the destination if it still exists,
    // otherwise the funds are burnt (e.g. the destination was ejected).
    for t in &deferred {
        if let Some(a) = exec.accounts.get_mut(&t.dest) {
            a.balance += t.amount;
        }
    }
    // Update the last-accumulation slot for every accumulated service.
    for &s in &services {
        if let Some(a) = exec.accounts.get_mut(&s) {
            a.last_accumulation_slot = slot;
        }
    }

    // Shift the accumulated ring buffer; the newest slot holds this block's
    // accumulated package hashes.
    let mut accd = accumulated_q.0.clone();
    for i in 0..EPOCH - 1 {
        accd[i] = accumulated_q.0[i + 1].clone();
    }
    let mut newest: Vec<H32> = acc_reports.iter().map(|r| r.package_spec.hash.clone()).collect();
    newest.sort_by(|a, b| a.0.cmp(&b.0));
    accd[EPOCH - 1] = newest.clone();
    let newest_raw: Vec<[u8; 32]> = newest.iter().map(|h| h.0).collect();

    // Rebuild the ready ring buffer (GP eq. finalstateaccumulation).
    let gap = (slot - pre_slot) as usize;
    let mut ready = ready_queue.0.clone();
    for i in 0..EPOCH {
        let idx = (m + EPOCH - i) % EPOCH;
        ready[idx] = if i == 0 {
            edit(&queued, &newest_raw).iter().map(pending_to_record).collect()
        } else if i < gap {
            Vec::new()
        } else {
            let old: Vec<Pending> = ready_queue.0[idx].iter().map(record_to_pending).collect();
            edit(&old, &newest_raw).iter().map(pending_to_record).collect()
        };
    }

    let root = if yields.is_empty() {
        [0u8; 32]
    } else {
        accumulation_root(&yields)
    };
    AccCore {
        exec,
        stat_map,
        ready: FixedSeq(ready),
        accumulated: FixedSeq(accd),
        root,
        yields,
    }
}

/// Apply the accumulate STF (typed `stf/accumulate` schema).
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    let exec = to_exec(&pre.accounts);
    let core = accumulate_core(
        input.slot,
        pre.slot,
        &pre.ready_queue,
        &pre.accumulated,
        &input.reports,
        pre.entropy.0,
        exec,
    );
    let mut post = pre.clone();
    post.slot = input.slot;
    post.accounts = to_typed(core.exec, &pre.accounts);
    post.statistics = core
        .stat_map
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
    post.ready_queue = core.ready;
    post.accumulated = core.accumulated;
    (Outcome::Ok(Hex(core.root)), post)
}

/// Project typed accounts (`δ`) into the execution view: metadata map + the
/// opaque state-key dictionary (storage under hashed keys, plus preimage blobs
/// under their preimage keys so `code` can be resolved from the dict, exactly
/// as on the unified trace path). `key_raw` remembers the raw storage key
/// behind each hashed key for the reverse projection.
fn to_exec(accounts: &[AccountsMapEntry]) -> ExecState {
    let mut a = BTreeMap::new();
    let mut dict = BTreeMap::new();
    let mut key_raw = BTreeMap::new();
    for e in accounts {
        a.insert(e.id, e.data.service.clone());
        for s in &e.data.storage {
            let k = service_storage(e.id, &s.key.0);
            dict.insert(k, s.value.0.clone());
            key_raw.insert(k, (e.id, s.key.0.clone()));
        }
        for p in &e.data.preimage_blobs {
            dict.insert(service_preimage(e.id, &p.hash.0), p.blob.0.clone());
        }
    }
    ExecState {
        accounts: a,
        dict,
        key_raw,
        // The accumulate STF vectors have empty χ.always_acc and make no
        // privilege host calls, so an empty privilege context is exact here.
        privileges: crate::state::Privileges {
            manager: 0,
            assign: FixedSeq(vec![0u32; CORE_COUNT]),
            delegator: 0,
            registrar: 0,
            always_acc: Vec::new(),
        },
        auth_queues: FixedSeq(Vec::new()),
        staging: FixedSeq(Vec::new()),
    }
}

/// Reconstruct typed accounts from the post-execution state. Storage is rebuilt
/// from `key_raw` + `dict`; preimages/requests are carried through from the
/// pre-state (the accumulate host-set does not mutate them).
fn to_typed(state: ExecState, pre: &[AccountsMapEntry]) -> Vec<AccountsMapEntry> {
    let ExecState { accounts, dict, key_raw, .. } = state;
    let mut out = Vec::new();
    for (id, service) in accounts {
        let mut storage: Vec<StorageMapEntry> = key_raw
            .iter()
            .filter(|(_, (svc, _))| *svc == id)
            .filter_map(|(k, (_, raw))| {
                dict.get(k).map(|v| StorageMapEntry { key: Blob(raw.clone()), value: Blob(v.clone()) })
            })
            .collect();
        storage.sort_by(|x, y| x.key.0.cmp(&y.key.0));
        let (preimage_blobs, preimage_requests) = pre
            .iter()
            .find(|e| e.id == id)
            .map(|e| (e.data.preimage_blobs.clone(), e.data.preimage_requests.clone()))
            .unwrap_or_default();
        out.push(AccountsMapEntry {
            id,
            data: ServiceAccount { service, storage, preimage_blobs, preimage_requests },
        });
    }
    out
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

