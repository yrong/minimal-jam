//! Preimage provision STF (GP §12, service `a_p` / `a_l`).
//!
//! Preimages in the extrinsic must be strictly ordered/unique by
//! `(service, blake2b(blob))` and each must be solicited-but-unprovided.
//! On success blobs land in `a_p`, the matching request records the slot,
//! and the service's `provided_*` statistics advance.

use crate::hexutil::{blob_len, to_hex};
use crate::crypto::blake2b_256;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEntry {
    pub hash: String,
    pub blob: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestKey {
    pub hash: String,
    pub length: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestEntry {
    pub key: RequestKey,
    pub value: Vec<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountData {
    pub preimage_blobs: Vec<BlobEntry>,
    pub preimage_requests: Vec<RequestEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountEntry {
    pub id: u64,
    pub data: AccountData,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRecord {
    pub provided_count: u64,
    pub provided_size: u64,
    pub refinement_count: u64,
    pub refinement_gas_used: u64,
    pub imports: u64,
    pub extrinsic_count: u64,
    pub extrinsic_size: u64,
    pub exports: u64,
    pub accumulate_count: u64,
    pub accumulate_gas_used: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatEntry {
    pub id: u64,
    pub record: ServiceRecord,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    pub accounts: Vec<AccountEntry>,
    pub statistics: Vec<StatEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct PreimageItem {
    requester: u64,
    blob: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    preimages: Vec<PreimageItem>,
    slot: u64,
}

/// STF outcome: success or a validity error (GP leaves codes unspecified).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    Unneeded,
    NotSortedUnique,
}

impl Outcome {
    /// JSON representation matching the test-vector `output` field.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Outcome::Ok => serde_json::json!({ "ok": null }),
            Outcome::Unneeded => serde_json::json!({ "err": "preimage_unneeded" }),
            Outcome::NotSortedUnique => {
                serde_json::json!({ "err": "preimages_not_sorted_unique" })
            }
        }
    }
}

fn account_mut<'a>(state: &'a mut State, id: u64) -> Option<&'a mut AccountData> {
    state
        .accounts
        .iter_mut()
        .find(|a| a.id == id)
        .map(|a| &mut a.data)
}

/// Apply the preimages STF. Returns the outcome and posterior state; on error
/// the state is returned unchanged.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    // 1. Ordered and unique by (service, blob) per GP §12.
    let order: Vec<(u64, Vec<u8>)> = input
        .preimages
        .iter()
        .map(|p| (p.requester, crate::hexutil::from_hex(&p.blob)))
        .collect();
    for w in order.windows(2) {
        if w[0] >= w[1] {
            return (Outcome::NotSortedUnique, pre.clone());
        }
    }

    // Preimage keys are keyed by blake2b(blob).
    let keyed: Vec<(u64, [u8; 32])> = input
        .preimages
        .iter()
        .map(|p| (p.requester, blake2b_256(&crate::hexutil::from_hex(&p.blob))))
        .collect();

    // 2. Every provided blob must be solicited and not yet provided.
    for (item, (_, hash)) in input.preimages.iter().zip(keyed.iter()) {
        let len = blob_len(&item.blob);
        let solicited = pre
            .accounts
            .iter()
            .find(|a| a.id == item.requester)
            .map(|a| {
                a.data.preimage_requests.iter().any(|r| {
                    r.key.hash == to_hex(hash) && r.key.length == len && r.value.is_empty()
                })
            })
            .unwrap_or(false);
        if !solicited {
            return (Outcome::Unneeded, pre.clone());
        }
    }

    // 3. Apply: store blobs, stamp requests, advance service statistics.
    let mut post = pre.clone();
    for (item, (_, hash)) in input.preimages.iter().zip(keyed.iter()) {
        let hash_hex = to_hex(hash);
        let len = blob_len(&item.blob);

        if let Some(data) = account_mut(&mut post, item.requester) {
            let entry = BlobEntry {
                hash: hash_hex.clone(),
                blob: item.blob.clone(),
            };
            let pos = data
                .preimage_blobs
                .binary_search_by(|e| e.hash.cmp(&entry.hash))
                .unwrap_or_else(|e| e);
            data.preimage_blobs.insert(pos, entry);

            if let Some(req) = data
                .preimage_requests
                .iter_mut()
                .find(|r| r.key.hash == hash_hex && r.key.length == len)
            {
                req.value = vec![input.slot];
            }
        }

        match post.statistics.iter_mut().find(|s| s.id == item.requester) {
            Some(s) => {
                s.record.provided_count += 1;
                s.record.provided_size += len;
            }
            None => {
                let record = ServiceRecord {
                    provided_count: 1,
                    provided_size: len,
                    ..Default::default()
                };
                let entry = StatEntry {
                    id: item.requester,
                    record,
                };
                let pos = post
                    .statistics
                    .binary_search_by(|s| s.id.cmp(&entry.id))
                    .unwrap_or_else(|e| e);
                post.statistics.insert(pos, entry);
            }
        }
    }

    (Outcome::Ok, post)
}
