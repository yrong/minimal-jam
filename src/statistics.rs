//! Validator statistics STF (GP §13, `π_V` / `π_L`).
//!
//! Per block: bump the author's block/ticket/preimage counters and, per
//! credential, the guarantee/assurance counters. On an epoch boundary the
//! current accumulator rotates into "last" and a fresh accumulator starts.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Tiny chain-spec epoch length (slots per epoch).
pub const EPOCH_DURATION: u64 = 12;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValStats {
    pub blocks: u64,
    pub tickets: u64,
    pub pre_images: u64,
    pub pre_images_size: u64,
    pub guarantees: u64,
    pub assurances: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub vals_curr_stats: Vec<ValStats>,
    pub vals_last_stats: Vec<ValStats>,
    pub slot: u64,
    pub curr_validators: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize)]
struct Credential {
    validator_index: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct Guarantee {
    signatures: Vec<Credential>,
}

#[derive(Clone, Debug, Deserialize)]
struct Assurance {
    validator_index: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct PreimageItem {
    blob: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Extrinsic {
    tickets: Vec<Value>,
    preimages: Vec<PreimageItem>,
    guarantees: Vec<Guarantee>,
    assurances: Vec<Assurance>,
    #[allow(dead_code)]
    disputes: Value,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    slot: u64,
    author_index: usize,
    extrinsic: Extrinsic,
}

fn blob_len(hex: &str) -> u64 {
    (hex.trim_start_matches("0x").len() as u64) / 2
}

/// Apply the statistics STF, returning the posterior state.
pub fn transition(pre: &State, input: &Input) -> State {
    let n = pre.vals_curr_stats.len();
    let prior_epoch = pre.slot / EPOCH_DURATION;
    let new_epoch = input.slot / EPOCH_DURATION;

    let (mut curr, last) = if new_epoch > prior_epoch {
        (vec![ValStats::default(); n], pre.vals_curr_stats.clone())
    } else {
        (pre.vals_curr_stats.clone(), pre.vals_last_stats.clone())
    };

    let a = input.author_index;
    curr[a].blocks += 1;
    curr[a].tickets += input.extrinsic.tickets.len() as u64;
    curr[a].pre_images += input.extrinsic.preimages.len() as u64;
    curr[a].pre_images_size += input
        .extrinsic
        .preimages
        .iter()
        .map(|p| blob_len(&p.blob))
        .sum::<u64>();

    for g in &input.extrinsic.guarantees {
        for c in &g.signatures {
            curr[c.validator_index].guarantees += 1;
        }
    }
    for asr in &input.extrinsic.assurances {
        curr[asr.validator_index].assurances += 1;
    }

    State {
        vals_curr_stats: curr,
        vals_last_stats: last,
        // `slot` here is τ (prior timeslot); the statistics subsystem does not
        // advance it — the vectors keep it equal to the pre-state value.
        slot: pre.slot,
        curr_validators: pre.curr_validators.clone(),
    }
}
