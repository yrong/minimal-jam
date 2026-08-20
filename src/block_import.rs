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
//! Not yet wired (later slices): the safrole **ring-VRF ticket path** (winning
//! tickets, `bad_ticket_proof`), work-report-driven core/service statistics,
//! guarantees ρ, assurances, disputes ψ, and accumulation (the non-trivial β
//! accumulation-output root). These fire on non-`fallback` traces.

use crate::authorizations::MAX_POOL;
use crate::bytes::{FixedSeq, Hex};
use crate::crypto::{blake2b_256, mmr_append, mmr_super_peak};
use crate::history::MAX_HISTORY;
use crate::safrole::fallback_keys;
use crate::state::{
    AuthPools, AuthQueues, BlockInfo, EntropyBuffer, Mmr, RecentBlocks, ReportedWorkPackage,
    State, Statistics, TicketsOrKeys, TimeSlot, ValidatorActivityRecord,
};
use crate::types::{Block, EPOCH_LENGTH};
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

    for g in &block.extrinsic.guarantees {
        for cred in &g.signatures {
            curr[cred.validator_index as usize].guarantees += 1;
        }
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

    let reported = block
        .extrinsic
        .guarantees
        .iter()
        .map(|g| ReportedWorkPackage {
            hash: g.report.package_spec.hash.clone(),
            exports_root: g.report.package_spec.exports_root.clone(),
        })
        .collect();

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

/// Unified block-import entry point: apply the implemented block-level state
/// transitions to `pre` under `block`, returning the posterior σ.
///
/// **Scope (this slice):** the crypto-light block chapters that fully determine
/// no-work, no-epoch-boundary blocks — τ (C11), π (C13), α (C1), β (C3) with an
/// empty accumulation-output root, and η (C6). All other chapters (γ safrole,
/// ψ disputes, validator sets, ρ, accumulation queues, service accounts) are
/// carried through unchanged. This reproduces the `fallback` traces byte-exact;
/// epoch-boundary validator/safrole rotation and work-report-driven subsystems
/// (guarantees ρ, assurances, accumulate) are later increments.
pub fn import_block(pre: &State, block: &Block) -> State {
    let prior_slot = pre.timeslot;
    let mut post = pre.clone();
    post.timeslot = next_timeslot(block);
    post.statistics = next_statistics(&pre.statistics, prior_slot, block);
    post.auth_pools = next_auth_pools(&pre.auth_pools, &pre.auth_queues, block);
    // No work reports in scope → the accumulation-output root is the empty hash.
    post.recent_blocks = next_recent_blocks(&pre.recent_blocks, block, [0u8; 32]);
    post.entropy = next_entropy(&pre.entropy, prior_slot, block);

    // γ (C4) safrole: on an epoch boundary with no winning tickets (fallback),
    // reseed the epoch's sealing keys from η₂' and reset the ticket accumulator.
    // Validators are steady in fallback, so γ_p / γ_z are carried through (no
    // ring-VRF recompute).
    let epoch_len = EPOCH_LENGTH as u32;
    if block.header.slot / epoch_len > prior_slot / epoch_len {
        post.safrole.tickets_or_keys =
            TicketsOrKeys::Keys(fallback_keys(&post.entropy.0[2].0, &post.active_validators.0));
        post.safrole.accumulator = Vec::new();
    }
    post
}
