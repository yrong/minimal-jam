//! Recent-blocks history STF (GP §7, `β`).
//!
//! Back-fill the parent state root into the previous head, append the
//! accumulation root to the Keccak MMR, then push a new head carrying the
//! MMR super-peak as its BEEFY root. History is capped at `MAX_HISTORY`.

use crate::crypto::{mmr_append, mmr_super_peak, Hash};
use crate::hexutil::{from_hex, to_hex, ZERO_HASH_HEX};
use serde::{Deserialize, Serialize};

/// Max retained recent blocks (`H`).
pub const MAX_HISTORY: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReportedWorkPackage {
    pub hash: String,
    pub exports_root: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockInfo {
    pub header_hash: String,
    pub beefy_root: String,
    pub state_root: String,
    pub reported: Vec<ReportedWorkPackage>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mmr {
    pub peaks: Vec<Option<String>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentBlocks {
    pub history: Vec<BlockInfo>,
    pub mmr: Mmr,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub beta: RecentBlocks,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    header_hash: String,
    parent_state_root: String,
    accumulate_root: String,
    work_packages: Vec<ReportedWorkPackage>,
}

/// Apply the history STF, returning the posterior state.
pub fn transition(pre: &State, input: &Input) -> State {
    let mut history = pre.beta.history.clone();

    // Back-fill the parent state root into the prior head (H_r).
    if let Some(last) = history.last_mut() {
        last.state_root = input.parent_state_root.clone();
    }

    // Append the accumulation root to the MMR and recompute the super-peak.
    let mut peaks: Vec<Option<Hash>> = pre
        .beta
        .mmr
        .peaks
        .iter()
        .map(|p| p.as_ref().map(|h| from_hex_32(h)))
        .collect();
    mmr_append(&mut peaks, from_hex_32(&input.accumulate_root));
    let beefy_root = to_hex(&mmr_super_peak(&peaks));

    history.push(BlockInfo {
        header_hash: input.header_hash.clone(),
        beefy_root,
        state_root: ZERO_HASH_HEX.to_string(),
        reported: input.work_packages.clone(),
    });
    if history.len() > MAX_HISTORY {
        let drop = history.len() - MAX_HISTORY;
        history.drain(0..drop);
    }

    let peaks = peaks
        .iter()
        .map(|p| p.as_ref().map(|h| to_hex(h)))
        .collect();

    State {
        beta: RecentBlocks {
            history,
            mmr: Mmr { peaks },
        },
    }
}

fn from_hex_32(s: &str) -> Hash {
    let v = from_hex(s);
    let mut r = [0u8; 32];
    r.copy_from_slice(&v);
    r
}
