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
use crate::state::{TicketBody, TicketsOrKeys, ValidatorData};
use crate::types::{EpochMark, TicketEnvelope, EPOCH_LENGTH, H144, H32, VALIDATORS_COUNT};
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
/// and the monotonic-slot error; other cases panic (not yet implemented).
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    // Timeslot must be strictly monotonic.
    if input.slot <= pre.tau {
        return (Outcome::Err(SafroleError::BadSlot), pre.clone());
    }

    let epoch_changed = input.slot / EPOCH != pre.tau / EPOCH;
    assert!(
        !epoch_changed,
        "safrole epoch transition not yet implemented"
    );
    assert!(
        input.extrinsic.is_empty(),
        "safrole ticket processing not yet implemented"
    );

    // Within-epoch advance: bump τ and fold the per-block entropy into η₀.
    let mut post = pre.clone();
    post.tau = input.slot;
    let mut buf = pre.eta.0[0].0.to_vec();
    buf.extend_from_slice(&input.entropy.0);
    post.eta.0[0] = Hex(blake2b_256(&buf));

    (
        Outcome::Ok(OutputData {
            epoch_mark: None,
            tickets_mark: None,
        }),
        post,
    )
}
