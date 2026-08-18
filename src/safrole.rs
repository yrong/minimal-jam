//! Safrole STF (GP §6) — isolated form matching the `stf/safrole` vectors.
//!
//! Scope of this slice: **within-epoch** advance (no epoch change) and the
//! monotonic-slot (`bad_slot`) error, with an empty tickets extrinsic. These
//! need only τ and the entropy accumulator η — the per-block VRF output is
//! supplied as `input.entropy`, so no bandersnatch crypto is required here.
//!
//! Deferred to the next slice: epoch transition (validator rotation, γ_s
//! fallback keys, the γ_z ring commitment via `ark-vrf` + SRS, epoch/tickets
//! markers) and ticket processing (ring-proof verification).

use crate::bytes::{FixedSeq, Hex};
use crate::crypto::blake2b_256;
use crate::ring::ring_commitment;
use crate::state::{TicketBody, TicketsOrKeys, ValidatorData};
use crate::types::{
    EpochMark, EpochMarkValidatorKeys, TicketEnvelope, EPOCH_LENGTH, H144, H32, VALIDATORS_COUNT,
};
use serde::{Deserialize, Serialize};

const EPOCH: u32 = EPOCH_LENGTH as u32;

/// Safrole STF state (`stf/safrole` schema).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub tau: u32,
    pub eta: FixedSeq<H32, 4>,
    pub lambda: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub kappa: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub gamma_k: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub iota: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub gamma_a: Vec<TicketBody>,
    pub gamma_s: TicketsOrKeys,
    pub gamma_z: H144,
    pub post_offenders: Vec<H32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    pub slot: u32,
    pub entropy: H32,
    pub extrinsic: Vec<TicketEnvelope>,
}

/// Output payload on success.
#[derive(Clone, Debug, Serialize)]
pub struct OutputData {
    pub epoch_mark: Option<EpochMark>,
    pub tickets_mark: Option<FixedSeq<TicketBody, EPOCH_LENGTH>>,
}

/// Safrole STF validity errors (GP leaves the codes unspecified).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SafroleError {
    BadSlot,
    UnexpectedTicket,
    BadTicketOrder,
    BadTicketProof,
    BadTicketAttempt,
    Reserved,
    DuplicateTicket,
}

/// STF outcome, serializing to the vector's `output` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok(OutputData),
    Err(SafroleError),
}

/// Apply the safrole STF. This slice handles the within-epoch, no-ticket case
/// and epoch transitions with an empty tickets extrinsic. Ticket processing
/// (ring-proof verification of a non-empty `E_T`) is not yet implemented.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    // Timeslot must be strictly monotonic.
    if input.slot <= pre.tau {
        return (Outcome::Err(SafroleError::BadSlot), pre.clone());
    }
    assert!(
        input.extrinsic.is_empty(),
        "safrole ticket processing not yet implemented"
    );

    // η₀ folds in the per-block entropy every block.
    let new_eta0 = {
        let mut buf = pre.eta.0[0].0.to_vec();
        buf.extend_from_slice(&input.entropy.0);
        Hex(blake2b_256(&buf))
    };

    if input.slot / EPOCH == pre.tau / EPOCH {
        // Within-epoch advance: only τ and η₀ change.
        let mut post = pre.clone();
        post.tau = input.slot;
        post.eta.0[0] = new_eta0;
        return (Outcome::Ok(OutputData { epoch_mark: None, tickets_mark: None }), post);
    }

    // --- Epoch transition (no tickets → fallback sealing keys) ---

    // Validator rotation: λ'=κ, κ'=γ_k, γ_k'=Φ(ι) (offender keys nulled).
    let lambda = pre.kappa.clone();
    let kappa = pre.gamma_k.clone();
    let gamma_k = FixedSeq(nullify_offenders(&pre.iota.0, &pre.post_offenders));
    let iota = pre.iota.clone();

    // γ_z' commits to the next-epoch validators' bandersnatch keys.
    let gk_keys: Vec<[u8; 32]> = gamma_k.0.iter().map(|v| v.bandersnatch.0).collect();
    let gamma_z: H144 = Hex(ring_commitment(&gk_keys));

    // η rotation: (η₁',η₂',η₃') = (η₀,η₁,η₂), η₀' folds the block entropy.
    let eta = FixedSeq(vec![
        new_eta0,
        pre.eta.0[0].clone(),
        pre.eta.0[1].clone(),
        pre.eta.0[2].clone(),
    ]);

    // γ_s' = fallback key sequence F(η₂', κ'); η₂' = prior η₁.
    let gamma_s = TicketsOrKeys::Keys(fallback_keys(&eta.0[2].0, &kappa.0));

    // Epoch marker: (η₁', η₂', next-epoch validator keys).
    let epoch_mark = EpochMark {
        entropy: pre.eta.0[0].clone(),
        tickets_entropy: pre.eta.0[1].clone(),
        validators: FixedSeq(
            gamma_k
                .0
                .iter()
                .map(|v| EpochMarkValidatorKeys {
                    bandersnatch: v.bandersnatch.clone(),
                    ed25519: v.ed25519.clone(),
                })
                .collect(),
        ),
    };

    let post = State {
        tau: input.slot,
        eta,
        lambda,
        kappa,
        gamma_k,
        iota,
        gamma_a: Vec::new(),
        gamma_s,
        gamma_z,
        post_offenders: pre.post_offenders.clone(),
    };
    (Outcome::Ok(OutputData { epoch_mark: Some(epoch_mark), tickets_mark: None }), post)
}

/// Fallback key sequence `F(r, k)` (GP eq. fallbackkeysequence): for each epoch
/// slot, pick a validator by `LE(blake2b(r ‖ E4(i))[..4]) mod |k|` and take its
/// bandersnatch key.
fn fallback_keys(r: &[u8; 32], validators: &[ValidatorData]) -> FixedSeq<H32, EPOCH_LENGTH> {
    let mut keys = Vec::with_capacity(EPOCH_LENGTH);
    for i in 0..EPOCH_LENGTH as u32 {
        let mut buf = r.to_vec();
        buf.extend_from_slice(&i.to_le_bytes());
        let h = blake2b_256(&buf);
        let idx = u32::from_le_bytes([h[0], h[1], h[2], h[3]]) as usize % validators.len();
        keys.push(validators[idx].bandersnatch.clone());
    }
    FixedSeq(keys)
}

/// `Φ` — replace each validator whose ed25519 key is in `offenders` with a
/// null (all-zero) entry, leaving the rest unchanged (GP offender nullification).
fn nullify_offenders(validators: &[ValidatorData], offenders: &[H32]) -> Vec<ValidatorData> {
    let null = ValidatorData {
        bandersnatch: Hex([0u8; 32]),
        ed25519: Hex([0u8; 32]),
        bls: Hex([0u8; 144]),
        metadata: Hex([0u8; 128]),
    };
    validators
        .iter()
        .map(|v| {
            if offenders.iter().any(|o| o.0 == v.ed25519.0) {
                null.clone()
            } else {
                v.clone()
            }
        })
        .collect()
}
