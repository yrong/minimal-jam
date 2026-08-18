//! Block-import state transitions wired onto the typed [`crate::state::State`]
//! and a decoded [`crate::types::Block`].
//!
//! Implemented here (no PVM / bandersnatch required):
//! - τ (C11): the posterior timeslot is the block's slot.
//! - π (C13): validator activity records — author block count, ticket/preimage
//!   counts, and per-credential guarantee/assurance counts, with epoch rotation.
//! - α (C1): authorizer pools — drop consumed authorizers, enqueue the slot's
//!   queued authorizer, keep the newest `MAX_POOL`.
//!
//! Not yet wired (need later slices): β (needs the accumulation-output root),
//! η/γ (bandersnatch VRF), and the core/service statistics driven by reports.

use crate::authorizations::MAX_POOL;
use crate::codec::FixedSeq;
use crate::state::{AuthPools, AuthQueues, Statistics, TimeSlot, ValidatorActivityRecord};
use crate::types::{Block, EPOCH_LENGTH};

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
            if g.report.core_index.0 as usize == c {
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
