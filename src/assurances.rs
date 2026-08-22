//! Availability-assurances STF (GP §11, `\availassignmentspostassurances`).
//!
//! Validators attest, per core, that they hold their erasure-coded piece of a
//! pending work-report. A report becomes *available* once a strict two-thirds
//! super-majority of the active set assures its core; such reports are removed
//! from `ρ` and returned. Reports past the assurance timeout are also cleared
//! (but not reported).

use crate::bytes::FixedSeq;
use crate::crypto::{blake2b_256, ed25519_verify};
use crate::state::{AvailabilityAssignments, ValidatorData};
use crate::types::{AvailAssurance, WorkReport, CORE_COUNT, H32, VALIDATORS_COUNT};
use serde::{Deserialize, Serialize};

/// Slots after which a reported-but-unavailable assignment is cleared
/// (`C_assurancetimeoutperiod`, GP defs).
const ASSURANCE_TIMEOUT: u32 = 5;

/// Assurances STF state (`stf/assurances` schema).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub avail_assignments: AvailabilityAssignments,
    pub curr_validators: FixedSeq<ValidatorData, VALIDATORS_COUNT>,
}

/// STF input: the assurances extrinsic, block slot, and parent hash.
#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    pub assurances: Vec<AvailAssurance>,
    pub slot: u32,
    pub parent: H32,
}

/// Output payload on success: reports that just became available.
#[derive(Clone, Debug, Serialize)]
pub struct OutputData {
    pub reported: Vec<WorkReport>,
}

/// Assurances STF validity errors (GP leaves the codes unspecified).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AssurancesError {
    BadAttestationParent,
    BadValidatorIndex,
    CoreNotEngaged,
    BadSignature,
    NotSortedOrUniqueAssurers,
}

/// STF outcome, serializing to the vector's `output` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok(OutputData),
    Err(AssurancesError),
}

/// Apply the assurances STF.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    match run(pre, input) {
        Ok((out, post)) => (Outcome::Ok(out), post),
        Err(err) => (Outcome::Err(err), pre.clone()),
    }
}

fn run(pre: &State, input: &Input) -> Result<(OutputData, State), AssurancesError> {
    let validators = pre.curr_validators.0.len();

    // Per-core availability tally.
    let mut counts = [0usize; CORE_COUNT];
    let mut prev: Option<u16> = None;

    for a in &input.assurances {
        // Every assurance is anchored on the parent header.
        if a.anchor.0 != input.parent.0 {
            return Err(AssurancesError::BadAttestationParent);
        }
        let idx = a.validator_index as usize;
        if idx >= validators {
            return Err(AssurancesError::BadValidatorIndex);
        }
        // Assurers must be strictly ordered and unique by validator index.
        if let Some(p) = prev {
            if a.validator_index <= p {
                return Err(AssurancesError::NotSortedOrUniqueAssurers);
            }
        }
        prev = Some(a.validator_index);
        // Signature over `jam_available ‖ H(E(parent, bitfield))`.
        let mut preimage = input.parent.0.to_vec();
        preimage.extend_from_slice(&a.bitfield.0);
        let mut msg = b"jam_available".to_vec();
        msg.extend_from_slice(&blake2b_256(&preimage));
        if !ed25519_verify(&pre.curr_validators.0[idx].ed25519.0, &msg, &a.signature.0) {
            return Err(AssurancesError::BadSignature);
        }
        // A set bit implies an assigned report on that core.
        for core in 0..CORE_COUNT {
            if bit_set(&a.bitfield.0, core) {
                if pre.avail_assignments.0[core].is_none() {
                    return Err(AssurancesError::CoreNotEngaged);
                }
                counts[core] += 1;
            }
        }
    }

    // A report is available with a strict two-thirds super-majority.
    let mut reported = Vec::new();
    let mut avail_assignments = pre.avail_assignments.clone();
    for core in 0..CORE_COUNT {
        let Some(assignment) = pre.avail_assignments.0[core].clone() else {
            continue;
        };
        let available = 3 * counts[core] > 2 * validators;
        let stale = input.slot >= assignment.timeout + ASSURANCE_TIMEOUT;
        if available {
            reported.push(assignment.report);
            avail_assignments.0[core] = None;
        } else if stale {
            avail_assignments.0[core] = None;
        }
    }

    let post = State {
        avail_assignments,
        curr_validators: pre.curr_validators.clone(),
    };
    Ok((OutputData { reported }, post))
}

/// Test bit `core` of an LSB-first bitfield (`core 0` = least-significant bit).
fn bit_set(bitfield: &[u8], core: usize) -> bool {
    bitfield[core / 8] & (1 << (core % 8)) != 0
}
