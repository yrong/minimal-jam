//! Block-import state transitions wired onto the typed [`crate::state::State`]
//! and a decoded [`crate::types::Block`].
//!
//! Implemented here:
//! - τ (C11): the posterior timeslot is the block's slot.
//! - π (C13): validator activity records — author block count, ticket/preimage
//!   counts, and per-credential guarantee/assurance counts, with epoch rotation.
//! - α (C1): authorizer pools — drop consumed authorizers, enqueue the slot's
//!   queued authorizer, keep the newest `MAX_POOL`.
//! - β (C3): recent blocks — back-fill the prior head's state root, append the
//!   accumulation-output root to the Keccak MMR, push the new head. The
//!   accumulation-output root is a caller input (zero for blocks without work).
//! - η (C6): entropy accumulator — `η₀' = blake2b(η₀ ⌢ banderout(entropy_source))`
//!   with epoch rotation. `banderout` is the Bandersnatch IETF VRF output hash
//!   (`ark-vrf` 0.1.0), extracted from the signature's output point.
//! - γ (C4) safrole, fallback path: on an epoch boundary with no winning
//!   tickets, reseed the sealing keys from η₂' and reset the ticket accumulator
//!   (validators steady → no ring-VRF recompute).
//!
//! [`import_block`] composes these into a single `State → State` step and is
//! verified byte-exact (`T(σ')` dictionary + state root) against the whole
//! `traces/fallback` set (100 blocks, spanning epoch boundaries).
//!
//! Not yet wired (later slices): rejecting invalid ticket ring-proofs
//! (`bad_ticket_proof`), and the work-report-driven subsystems — core/service
//! statistics, guarantees ρ, assurances, disputes ψ, and accumulation (the
//! non-trivial β accumulation-output root). These fire on richer traces.

use crate::authorizations::MAX_POOL;
use crate::accumulate::accumulate_core;
use crate::accumulate_exec::ExecState;
use crate::bytes::{FixedSeq, Hex};
use crate::crypto::{blake2b_256, mmr_append, mmr_super_peak};
use crate::history::MAX_HISTORY;
use crate::safrole::{transition as safrole_step, Input as SafroleStfIn, State as SafroleStf};
use crate::assurances::{
    transition as assurances_step, Input as AssurancesIn, Outcome as AssurancesOutcome,
    State as AssurancesStf,
};
use crate::disputes::{transition as disputes_step, Input as DisputesIn, State as DisputesStf};
use crate::reports::{
    transition as reports_step, Account as RepAccount, AccountsMapEntry as RepAccountEntry,
    Input as ReportsIn, State as ReportsStf,
};
use crate::state::{
    AuthPools, AuthQueues, BlockInfo, CoreActivityRecord, EntropyBuffer, LastAccEntry, Mmr,
    RecentBlocks, ReportedWorkPackage,
    SafroleState, ServiceActivityRecord, ServiceInfo, ServiceStatEntry, State, Statistics,
    TimeSlot, ValidatorActivityRecord,
};
use crate::state_key::{service_preimage, service_request, StateKey};
use crate::types::{Block, CORE_COUNT, EPOCH_LENGTH, H32};
use std::collections::BTreeMap;
use ark_serialize::CanonicalDeserialize;
use ark_vrf::suites::bandersnatch::Output as VrfOutput;
use jam_codec::Encode;

/// τ' — posterior timeslot.
pub fn next_timeslot(block: &Block) -> TimeSlot {
    block.header.slot
}

fn zero_record() -> ValidatorActivityRecord {
    ValidatorActivityRecord {
        blocks: 0,
        tickets: 0,
        pre_images: 0,
        pre_images_size: 0,
        guarantees: 0,
        assurances: 0,
    }
}

/// π' — validator activity statistics (`vals_curr` / `vals_last`).
///
/// Note: this updates only the validator records. Core/service records are
/// carried through unchanged, which is exact for blocks without work reports
/// or preimages (e.g. the `fallback` traces).
pub fn next_statistics(pre: &Statistics, prior_slot: TimeSlot, block: &Block) -> Statistics {
    let epoch_len = EPOCH_LENGTH as u32;
    let rotate = block.header.slot / epoch_len > prior_slot / epoch_len;

    let n = pre.vals_curr.0.len();
    let (mut curr, last) = if rotate {
        (vec![zero_record(); n], pre.vals_curr.0.clone())
    } else {
        (pre.vals_curr.0.clone(), pre.vals_last.0.clone())
    };

    let a = block.header.author_index as usize;
    curr[a].blocks += 1;
    curr[a].tickets += block.extrinsic.tickets.len() as u32;
    curr[a].pre_images += block.extrinsic.preimages.len() as u32;
    curr[a].pre_images_size += block
        .extrinsic
        .preimages
        .iter()
        .map(|p| p.blob.0.len() as u32)
        .sum::<u32>();

    // A validator's guarantee count is credited once per block for the reports
    // it helped guarantee, not per signature: the guarantors form a set (GP's
    // deduplicated `reporters`), so a validator signing several guarantees in
    // one block still counts once.
    let mut guarantors: Vec<u16> = block
        .extrinsic
        .guarantees
        .iter()
        .flat_map(|g| g.signatures.iter().map(|c| c.validator_index))
        .collect();
    guarantors.sort_unstable();
    guarantors.dedup();
    for v in guarantors {
        curr[v as usize].guarantees += 1;
    }
    for a in &block.extrinsic.assurances {
        curr[a.validator_index as usize].assurances += 1;
    }

    Statistics {
        vals_curr: FixedSeq(curr),
        vals_last: FixedSeq(last),
        cores: pre.cores.clone(),
        services: pre.services.clone(),
    }
}

/// α' — authorizer pools per core.
pub fn next_auth_pools(pools: &AuthPools, queues: &AuthQueues, block: &Block) -> AuthPools {
    let slot = block.header.slot as usize;
    let mut out = Vec::with_capacity(pools.0.len());

    for c in 0..pools.0.len() {
        let mut pool = pools.0[c].clone();

        // Drop the authorizer consumed by each report guaranteed on core c.
        for g in &block.extrinsic.guarantees {
            if g.report.core_index as usize == c {
                if let Some(p) = pool.iter().position(|h| *h == g.report.authorizer_hash) {
                    pool.remove(p);
                }
            }
        }

        // Enqueue this slot's scheduled authorizer, keep the newest MAX_POOL.
        let queue = &queues.0[c].0;
        pool.push(queue[slot % queue.len()].clone());
        if pool.len() > MAX_POOL {
            pool.drain(0..pool.len() - MAX_POOL);
        }
        out.push(pool);
    }

    FixedSeq(out)
}

/// β' — recent blocks history (GP §7).
///
/// Back-fill the prior head's posterior state root with `H_r`, append the
/// accumulation-output root to the Keccak MMR, then push a new head carrying
/// the block header hash, the MMR super-peak, a zero (not-yet-known) state
/// root, and the reported work packages. Capped at `MAX_HISTORY`.
///
/// `accumulate_root` is the accumulation-output root; for blocks without work
/// reports it is the empty root (zero hash).
pub fn next_recent_blocks(pre: &RecentBlocks, block: &Block, accumulate_root: [u8; 32]) -> RecentBlocks {
    let mut history = pre.history.clone();
    if let Some(last) = history.last_mut() {
        last.state_root = block.header.parent_state_root.clone();
    }

    let mut peaks: Vec<Option<[u8; 32]>> = pre.mmr.peaks.iter().map(|p| p.as_ref().map(|h| h.0)).collect();
    mmr_append(&mut peaks, accumulate_root);
    let beefy_root = mmr_super_peak(&peaks);

    // Reported work-packages are stored sorted by package hash, matching the
    // reports STF's `reported` output.
    let mut reported: Vec<ReportedWorkPackage> = block
        .extrinsic
        .guarantees
        .iter()
        .map(|g| ReportedWorkPackage {
            hash: g.report.package_spec.hash.clone(),
            exports_root: g.report.package_spec.exports_root.clone(),
        })
        .collect();
    reported.sort_by(|a, b| a.hash.0.cmp(&b.hash.0));

    history.push(BlockInfo {
        header_hash: Hex(blake2b_256(&block.header.encode())),
        beefy_root: Hex(beefy_root),
        state_root: Hex([0u8; 32]),
        reported,
    });
    if history.len() > MAX_HISTORY {
        history.drain(0..history.len() - MAX_HISTORY);
    }

    let peaks = peaks.iter().map(|p| p.map(Hex)).collect();
    RecentBlocks {
        history,
        mmr: Mmr { peaks },
    }
}

/// `banderout` — the 32-byte Bandersnatch IETF VRF output hash of a 96-byte
/// signature. The output point is the signature's first 32 bytes; the hash is
/// `Output::hash()` per the JAM-era `ark-vrf` (0.1.0).
pub fn bander_output(sig: &[u8; 96]) -> [u8; 32] {
    let out = VrfOutput::deserialize_compressed(&sig[0..32])
        .expect("valid bandersnatch VRF output point");
    let hash = out.hash();
    let bytes: &[u8] = hash.as_ref();
    let mut y = [0u8; 32];
    y.copy_from_slice(&bytes[..32]);
    y
}

/// η' — entropy accumulator (GP §sealing/entropy).
///
/// `η₀' = blake2b(η₀ ⌢ banderout(entropy_source))`; on an epoch boundary the
/// prior accumulator rotates into the history: `(η₁',η₂',η₃') = (η₀,η₁,η₂)`.
pub fn next_entropy(pre: &EntropyBuffer, prior_slot: TimeSlot, block: &Block) -> EntropyBuffer {
    let y = bander_output(&block.header.entropy_source.0);
    let eta0 = pre.0[0].0;
    let mut buf = eta0.to_vec();
    buf.extend_from_slice(&y);
    let new0 = Hex(blake2b_256(&buf));

    let epoch_len = EPOCH_LENGTH as u32;
    let out = if block.header.slot / epoch_len > prior_slot / epoch_len {
        vec![new0, Hex(eta0), pre.0[1].clone(), pre.0[2].clone()]
    } else {
        vec![new0, pre.0[1].clone(), pre.0[2].clone(), pre.0[3].clone()]
    };
    FixedSeq(out)
}

/// Unified block-import entry point: apply the block-level state transitions to
/// `pre` under `block`, returning the posterior σ.
///
/// The safrole-owned chapters — τ (C11), η (C6), the validator sets ι/κ/λ
/// (C7/8/9), and γ (C4: pending, ring commitment, sealing keys, ticket
/// accumulator) — are delegated to the tested [`crate::safrole::transition`],
/// which covers within-epoch advance, ticket accumulation, and the epoch
/// transition (fallback keys or winning tickets, γ_z ring commitment). The
/// remaining crypto-light chapters are computed here: π (C13), α (C1), and
/// β (C3, with an empty accumulation-output root).
///
/// **Scope:** reproduces the `fallback` and `safrole` traces byte-exact.
/// Work-report-driven subsystems (guarantees ρ, assurances, disputes ψ,
/// accumulation → non-trivial β root) are later increments.
pub fn import_block(pre: &State, block: &Block) -> State {
    let prior_slot = pre.timeslot;
    let mut post = pre.clone();

    // π (C13 validators) and α (C1) — computed against the prior state. β (C3)
    // is deferred until after accumulate, whose output root feeds its MMR.
    post.statistics = next_statistics(&pre.statistics, prior_slot, block);
    post.auth_pools = next_auth_pools(&pre.auth_pools, &pre.auth_queues, block);

    // τ/η/ι/κ/λ/γ — delegate to the safrole STF. The per-block entropy is the
    // Bandersnatch VRF output of the seal's entropy source.
    let sf_pre = SafroleStf {
        tau: pre.timeslot,
        eta: pre.entropy.clone(),
        lambda: pre.previous_validators.clone(),
        kappa: pre.active_validators.clone(),
        gamma_k: pre.safrole.pending.clone(),
        iota: pre.staging_validators.clone(),
        gamma_a: pre.safrole.accumulator.clone(),
        gamma_s: pre.safrole.tickets_or_keys.clone(),
        gamma_z: pre.safrole.ring_commitment.clone(),
        post_offenders: pre.disputes.offenders.clone(),
    };
    let sf_in = SafroleStfIn {
        slot: block.header.slot,
        entropy: Hex(bander_output(&block.header.entropy_source.0)),
        extrinsic: block.extrinsic.tickets.clone(),
    };
    let (_out, sf) = safrole_step(&sf_pre, &sf_in);
    post.timeslot = sf.tau;
    post.entropy = sf.eta;
    post.previous_validators = sf.lambda;
    post.active_validators = sf.kappa;
    post.staging_validators = sf.iota;
    post.safrole = SafroleState {
        pending: sf.gamma_k,
        ring_commitment: sf.gamma_z,
        tickets_or_keys: sf.gamma_s,
        accumulator: sf.gamma_a,
    };

    // --- Availability half (GP §10/§11) ------------------------------------
    // ρ (C10) evolves through three subsystems, each a function of the prior
    // state σ: disputes clear judged assignments (ρ†), assurances clear the
    // available/timed-out ones (ρ‡), guarantees add newly-reported ones (ρ').
    // ψ (C5) and the core/service halves of π (C13) update alongside.
    let (_dout, disp) = disputes_step(
        &DisputesStf {
            psi: pre.disputes.clone(),
            rho: pre.avail.clone(),
            tau: pre.timeslot,
            kappa: pre.active_validators.clone(),
            lambda: pre.previous_validators.clone(),
        },
        &DisputesIn { disputes: block.extrinsic.disputes.clone() },
    );
    post.disputes = disp.psi;
    let rho_dagger = disp.rho;

    let (aout, asr) = assurances_step(
        &AssurancesStf {
            avail_assignments: rho_dagger,
            curr_validators: post.active_validators.clone(),
        },
        &AssurancesIn {
            assurances: block.extrinsic.assurances.clone(),
            slot: block.header.slot,
            parent: block.header.parent.clone(),
        },
    );
    let rho_ddagger = asr.avail_assignments;

    // Reports validate report anchors against recent history β with the parent
    // block's posterior state root back-filled (β†): the pre-state's last entry
    // still carries a placeholder until this block's β update runs.
    let mut beta_dagger = pre.recent_blocks.clone();
    if let Some(last) = beta_dagger.history.last_mut() {
        last.state_root = block.header.parent_state_root.clone();
    }

    let (_rout, rep) = reports_step(
        &ReportsStf {
            avail_assignments: rho_ddagger,
            curr_validators: post.active_validators.clone(),
            prev_validators: post.previous_validators.clone(),
            entropy: post.entropy.clone(),
            offenders: post.disputes.offenders.clone(),
            recent_blocks: beta_dagger,
            auth_pools: pre.auth_pools.clone(),
            accounts: avail_accounts(&pre.accounts),
            // Core/service statistics (π_C, π_S) are per-block: reports starts
            // from a zeroed baseline, not the carried-through prior values.
            cores_statistics: zero_cores(),
            services_statistics: Vec::new(),
        },
        &ReportsIn {
            guarantees: block.extrinsic.guarantees.clone(),
            slot: block.header.slot,
            known_packages: known_packages(pre),
        },
    );
    post.avail = rep.avail_assignments;
    post.statistics.cores = rep.cores_statistics;
    post.statistics.services = rep.services_statistics;

    // --- Accumulate (GP §12) ------------------------------------------------
    // Reports made available this block (assurances output) are the accumulate
    // input; the shared core evolves service accounts (δ, C255 + service dict),
    // the ready/accumulated ring buffers (ϑ C14, ξ C15), and yields the
    // accumulation-output root that seeds β's MMR (C3).
    let available: Vec<crate::types::WorkReport> = match aout {
        AssurancesOutcome::Ok(o) => o.reported,
        AssurancesOutcome::Err(_) => Vec::new(),
    };

    // Availability-driven core statistics (π_C): every assurance credits its
    // cores' assurer count (popularity); each report made available this block
    // adds its work-bundle length to that core's data-availability load.
    for a in &block.extrinsic.assurances {
        for c in 0..CORE_COUNT {
            if a.bitfield.0[c / 8] & (1 << (c % 8)) != 0 {
                post.statistics.cores.0[c].popularity += 1;
            }
        }
    }
    for r in &available {
        post.statistics.cores.0[r.core_index as usize].da_load += r.package_spec.length;
    }
    let exec = ExecState {
        accounts: pre.accounts.iter().cloned().collect(),
        dict: pre.service_dict.iter().cloned().collect::<BTreeMap<StateKey, Vec<u8>>>(),
        key_raw: BTreeMap::new(),
        privileges: pre.privileges.clone(),
        auth_queues: pre.auth_queues.clone(),
        staging: post.staging_validators.clone(),
    };
    let core = accumulate_core(
        block.header.slot,
        pre.timeslot,
        &pre.ready,
        &pre.accumulated,
        &available,
        post.entropy.0[0].0,
        exec,
    );
    let ExecState {
        accounts: acc_out,
        dict: mut service_dict,
        privileges: post_privileges,
        auth_queues: post_auth_queues,
        staging: post_staging,
        ..
    } = core.exec;
    post.accounts = acc_out.into_iter().collect();
    post.ready = core.ready;
    post.accumulated = core.accumulated;
    // χ (C12), φ (C2), ι (C7) — mutated by bless/assign/designate.
    post.privileges = post_privileges;
    post.auth_queues = post_auth_queues;
    post.staging_validators = post_staging;
    merge_accumulate_stats(&mut post.statistics.services, &core.stat_map);
    // C16: this block's accumulation-output log (service, yielded hash).
    post.last_accout = core
        .yields
        .iter()
        .map(|(s, h)| LastAccEntry { service: *s, hash: Hex(*h) })
        .collect();

    // Preimage provision (GP §12): store each provided blob under its preimage
    // state-key, stamp the matching request with this slot, and advance the
    // provider's provided_* statistics. The footprint (a_i/a_o) counts requests
    // fixed at solicit time, so provision leaves account metadata unchanged.
    for p in &block.extrinsic.preimages {
        let s = p.requester;
        let blob = p.blob.0.clone();
        let len = blob.len() as u32;
        let hash = blake2b_256(&blob);
        service_dict.insert(service_preimage(s, &hash), blob);
        let mut status = vec![1u8]; // sequence length 1
        status.extend_from_slice(&block.header.slot.to_le_bytes());
        service_dict.insert(service_request(s, len, &hash), status);
        let rec = service_stat_mut(&mut post.statistics.services, s);
        rec.provided_count += 1;
        rec.provided_size += len;
    }
    post.statistics.services.sort_by_key(|e| e.id);
    post.service_dict = service_dict.into_iter().collect();

    // β (C3): now that the accumulation-output root is known, fold it into the
    // recent-blocks MMR.
    post.recent_blocks = next_recent_blocks(&pre.recent_blocks, block, core.root);
    post
}

/// A per-block-zeroed core-statistics vector (π_C baseline).
fn zero_cores() -> FixedSeq<CoreActivityRecord, CORE_COUNT> {
    let z = CoreActivityRecord {
        da_load: 0,
        popularity: 0,
        imports: 0,
        extrinsic_count: 0,
        extrinsic_size: 0,
        exports: 0,
        bundle_size: 0,
        gas_used: 0,
    };
    FixedSeq(vec![z; CORE_COUNT])
}

/// A zeroed service-activity record (π_S baseline).
fn zero_service_activity() -> ServiceActivityRecord {
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

/// Get (or create, zeroed) the π_S record for service `id`.
fn service_stat_mut(services: &mut Vec<ServiceStatEntry>, id: u32) -> &mut ServiceActivityRecord {
    match services.iter().position(|e| e.id == id) {
        Some(pos) => &mut services[pos].record,
        None => {
            services.push(ServiceStatEntry { id, record: zero_service_activity() });
            &mut services.last_mut().unwrap().record
        }
    }
}

/// Fold accumulate per-service activity (count, gas) into the service
/// statistics π_S already carrying refinement counts, creating entries for
/// services that accumulated without being refined this block.
fn merge_accumulate_stats(
    services: &mut Vec<ServiceStatEntry>,
    stat_map: &BTreeMap<u32, (u32, u64)>,
) {
    for (id, (count, gas)) in stat_map {
        let rec = service_stat_mut(services, *id);
        rec.accumulate_count = *count;
        rec.accumulate_gas_used = *gas;
    }
    services.sort_by_key(|e| e.id);
}

/// Project the unified service accounts into the reports STF's metadata-only
/// view (`Account { service }`); storage/preimages are irrelevant to C11.
fn avail_accounts(accounts: &[(u32, ServiceInfo)]) -> Vec<RepAccountEntry> {
    accounts
        .iter()
        .map(|(id, info)| RepAccountEntry {
            id: *id,
            data: RepAccount { service: info.clone() },
        })
        .collect()
}

/// Work-package hashes already known — the accumulated set ξ (C15) plus the
/// ready queue ϑ (C14). The reports STF rejects any guarantee whose package is
/// already known (or present in recent history β, which it checks itself).
fn known_packages(pre: &State) -> Vec<H32> {
    let mut out = Vec::new();
    for slot in &pre.accumulated.0 {
        out.extend(slot.iter().cloned());
    }
    for slot in &pre.ready.0 {
        for r in slot {
            out.push(r.report.package_spec.hash.clone());
        }
    }
    out
}
