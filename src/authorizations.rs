//! Authorizer pools/queues STF (GP §8, `α` / `φ`).
//!
//! For each core: drop the authorizer consumed by any guaranteed report,
//! push the queued authorizer for this slot, then keep the newest `MAX_POOL`.

use serde::{Deserialize, Serialize};

/// Max authorizers retained per core pool (`O`); constant across chain specs.
pub const MAX_POOL: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// `α`: per-core authorizer pool.
    pub auth_pools: Vec<Vec<String>>,
    /// `φ`: per-core authorizer queue (rotated by slot).
    pub auth_queues: Vec<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
struct CoreAuthorizer {
    core: usize,
    auth_hash: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    slot: u64,
    auths: Vec<CoreAuthorizer>,
}

/// Apply the authorizations STF, returning the posterior state.
pub fn transition(pre: &State, input: &Input) -> State {
    let cores = pre.auth_pools.len();
    let mut pools = pre.auth_pools.clone();

    for c in 0..cores {
        let pool = &mut pools[c];

        // Remove the authorizer consumed by each report guaranteed on core c.
        for auth in input.auths.iter().filter(|a| a.core == c) {
            if let Some(pos) = pool.iter().position(|h| *h == auth.auth_hash) {
                pool.remove(pos);
            }
        }

        // Enqueue the scheduled authorizer for this slot.
        let queue = &pre.auth_queues[c];
        if !queue.is_empty() {
            let idx = (input.slot as usize) % queue.len();
            pool.push(queue[idx].clone());
        }

        // Retain only the newest MAX_POOL authorizers.
        if pool.len() > MAX_POOL {
            let drop = pool.len() - MAX_POOL;
            pool.drain(0..drop);
        }
    }

    State {
        auth_pools: pools,
        auth_queues: pre.auth_queues.clone(),
    }
}
