//! Disputes STF (GP §10) — verdicts, culprits, faults.
//!
//! Records judgments over work-report validity (`ψ = (good, bad, wonky,
//! offenders)`), punishes offending validators, and clears availability
//! assignments (`ρ`) for reports judged non-positive. Ed25519 judgment,
//! culprit and fault signatures are verified against the current (`κ`) or
//! previous (`λ`) epoch validator set.

use crate::crypto::{blake2b_256, ed25519_verify};
use crate::state::{AvailabilityAssignments, DisputesRecords, ValidatorData};
use crate::types::{DisputesExtrinsic, EPOCH_LENGTH, H32, VALIDATORS_COUNT, VALIDATORS_SUPER_MAJORITY};
use jam_codec::Encode;
use serde::{Deserialize, Serialize};

const EPOCH: u32 = EPOCH_LENGTH as u32;
/// Positive-vote tally that makes a verdict wonky, `⌊V/3⌋`.
const WONKY_VOTES: usize = VALIDATORS_COUNT / 3;
/// Culprits required to justify a bad verdict (a report's guarantor count).
const MIN_CULPRITS: usize = 2;

/// Disputes STF state (`stf/disputes` schema).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct State {
    pub psi: DisputesRecords,
    pub rho: AvailabilityAssignments,
    pub tau: u32,
    pub kappa: crate::bytes::FixedSeq<ValidatorData, VALIDATORS_COUNT>,
    pub lambda: crate::bytes::FixedSeq<ValidatorData, VALIDATORS_COUNT>,
}

/// STF input: the disputes extrinsic.
#[derive(Clone, Debug, Deserialize)]
pub struct Input {
    pub disputes: DisputesExtrinsic,
}

/// Output payload on success: the new-offenders marker.
#[derive(Clone, Debug, Serialize)]
pub struct OutputData {
    pub offenders_mark: Vec<H32>,
}

/// Disputes STF validity errors (GP leaves the codes unspecified).
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DisputesError {
    AlreadyJudged,
    BadVoteSplit,
    VerdictsNotSortedUnique,
    JudgementsNotSortedUnique,
    CulpritsNotSortedUnique,
    FaultsNotSortedUnique,
    NotEnoughCulprits,
    NotEnoughFaults,
    CulpritsVerdictNotBad,
    FaultVerdictWrong,
    OffenderAlreadyReported,
    BadJudgementAge,
    BadValidatorIndex,
    BadSignature,
    BadGuarantorKey,
    BadAuditorKey,
}

/// STF outcome, serializing to the vector's `output` shape.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Ok(OutputData),
    Err(DisputesError),
}

#[derive(Clone, Copy, PartialEq)]
enum Vote {
    Good,
    Bad,
    Wonky,
}

/// Apply the disputes STF.
pub fn transition(pre: &State, input: &Input) -> (Outcome, State) {
    match run(pre, input) {
        Ok((out, post)) => (Outcome::Ok(out), post),
        Err(err) => (Outcome::Err(err), pre.clone()),
    }
}

fn run(pre: &State, input: &Input) -> Result<(OutputData, State), DisputesError> {
    let disp = &input.disputes;
    let epoch = pre.tau / EPOCH;

    // Verdicts must be ordered and unique by report hash.
    if !strictly_ascending(disp.verdicts.iter().map(|v| &v.target.0)) {
        return Err(DisputesError::VerdictsNotSortedUnique);
    }

    // Validate each verdict and derive its (report hash, kind).
    let mut results: Vec<(H32, Vote)> = Vec::with_capacity(disp.verdicts.len());
    for v in &disp.verdicts {
        // Age must be the prior state's epoch or one less.
        if v.age != epoch && v.age + 1 != epoch {
            return Err(DisputesError::BadJudgementAge);
        }
        let keys = if v.age == epoch { &pre.kappa } else { &pre.lambda };

        // Judgments must be ordered and unique by validator index.
        if !strictly_ascending(v.votes.0.iter().map(|j| j.index)) {
            return Err(DisputesError::JudgementsNotSortedUnique);
        }
        // Report must not already have a recorded verdict.
        if is_judged(&pre.psi, &v.target) {
            return Err(DisputesError::AlreadyJudged);
        }

        let mut positive = 0usize;
        for j in &v.votes.0 {
            let idx = j.index as usize;
            if idx >= keys.0.len() {
                return Err(DisputesError::BadValidatorIndex);
            }
            let ctx: &[u8] = if j.vote { b"jam_valid" } else { b"jam_invalid" };
            if !verify(&keys.0[idx].ed25519.0, ctx, &v.target.0, &j.signature.0) {
                return Err(DisputesError::BadSignature);
            }
            if j.vote {
                positive += 1;
            }
        }

        let kind = if positive == VALIDATORS_SUPER_MAJORITY {
            Vote::Good
        } else if positive == 0 {
            Vote::Bad
        } else if positive == WONKY_VOTES {
            Vote::Wonky
        } else {
            return Err(DisputesError::BadVoteSplit);
        };
        results.push((v.target.clone(), kind));
    }

    // Posterior verdict sets (used by culprit/fault validity below).
    let mut psi = pre.psi.clone();
    for (target, kind) in &results {
        match kind {
            Vote::Good => psi.good.push(target.clone()),
            Vote::Bad => psi.bad.push(target.clone()),
            Vote::Wonky => psi.wonky.push(target.clone()),
        }
    }

    // Known validator Ed25519 keys (κ ∪ λ) for offender-key membership.
    let validator_keys: Vec<[u8; 32]> = pre
        .kappa
        .0
        .iter()
        .chain(pre.lambda.0.iter())
        .map(|v| v.ed25519.0)
        .collect();

    // Culprits: ordered/unique by key, target bad, key a known non-offender,
    // valid guarantee signature.
    if !strictly_ascending(disp.culprits.iter().map(|c| &c.key.0)) {
        return Err(DisputesError::CulpritsNotSortedUnique);
    }
    for c in &disp.culprits {
        if !contains(&psi.bad, &c.target) {
            return Err(DisputesError::CulpritsVerdictNotBad);
        }
        if !validator_keys.contains(&c.key.0) {
            return Err(DisputesError::BadGuarantorKey);
        }
        if contains(&pre.psi.offenders, &c.key) {
            return Err(DisputesError::OffenderAlreadyReported);
        }
        if !verify(&c.key.0, b"jam_guarantee", &c.target.0, &c.signature.0) {
            return Err(DisputesError::BadSignature);
        }
    }

    // Faults: ordered/unique by key, vote contradicts the verdict, key a known
    // non-offender, valid judgment signature.
    if !strictly_ascending(disp.faults.iter().map(|f| &f.key.0)) {
        return Err(DisputesError::FaultsNotSortedUnique);
    }
    for f in &disp.faults {
        let in_bad = contains(&psi.bad, &f.target);
        let in_good = contains(&psi.good, &f.target);
        if in_bad == in_good || f.vote != in_bad {
            return Err(DisputesError::FaultVerdictWrong);
        }
        if !validator_keys.contains(&f.key.0) {
            return Err(DisputesError::BadAuditorKey);
        }
        if contains(&pre.psi.offenders, &f.key) {
            return Err(DisputesError::OffenderAlreadyReported);
        }
        let ctx: &[u8] = if f.vote { b"jam_valid" } else { b"jam_invalid" };
        if !verify(&f.key.0, ctx, &f.target.0, &f.signature.0) {
            return Err(DisputesError::BadSignature);
        }
    }

    // Each new bad verdict needs enough culprits; each good verdict a fault.
    for (target, kind) in &results {
        match kind {
            Vote::Bad => {
                if disp.culprits.iter().filter(|c| c.target == *target).count() < MIN_CULPRITS {
                    return Err(DisputesError::NotEnoughCulprits);
                }
            }
            Vote::Good => {
                if !disp.faults.iter().any(|f| f.target == *target) {
                    return Err(DisputesError::NotEnoughFaults);
                }
            }
            Vote::Wonky => {}
        }
    }

    // Offenders marker: culprit keys then fault keys, in extrinsic order.
    let mut offenders_mark: Vec<H32> = Vec::new();
    for c in &disp.culprits {
        offenders_mark.push(c.key.clone());
    }
    for f in &disp.faults {
        offenders_mark.push(f.key.clone());
    }

    // ψ' sets are kept sorted; offenders assimilate the new marker.
    for key in &offenders_mark {
        psi.offenders.push(key.clone());
    }
    sort_hashes(&mut psi.good);
    sort_hashes(&mut psi.bad);
    sort_hashes(&mut psi.wonky);
    sort_hashes(&mut psi.offenders);

    // Clear availability assignments for reports judged bad or wonky.
    let cleared: Vec<[u8; 32]> = results
        .iter()
        .filter(|(_, k)| matches!(k, Vote::Bad | Vote::Wonky))
        .map(|(t, _)| t.0)
        .collect();
    let mut rho = pre.rho.clone();
    for slot in rho.0.iter_mut() {
        if let Some(a) = slot {
            if cleared.contains(&blake2b_256(&a.report.encode())) {
                *slot = None;
            }
        }
    }

    let post = State {
        psi,
        rho,
        tau: pre.tau,
        kappa: pre.kappa.clone(),
        lambda: pre.lambda.clone(),
    };
    Ok((OutputData { offenders_mark }, post))
}

fn verify(pubkey: &[u8; 32], ctx: &[u8], target: &[u8; 32], sig: &[u8; 64]) -> bool {
    let mut msg = ctx.to_vec();
    msg.extend_from_slice(target);
    ed25519_verify(pubkey, &msg, sig)
}

fn is_judged(psi: &DisputesRecords, target: &H32) -> bool {
    contains(&psi.good, target) || contains(&psi.bad, target) || contains(&psi.wonky, target)
}

fn contains(set: &[H32], hash: &H32) -> bool {
    set.iter().any(|h| h.0 == hash.0)
}

fn sort_hashes(set: &mut [H32]) {
    set.sort_by(|a, b| a.0.cmp(&b.0));
}

fn strictly_ascending<T: Ord, I: IntoIterator<Item = T>>(iter: I) -> bool {
    let mut prev: Option<T> = None;
    for item in iter {
        if let Some(p) = &prev {
            if item <= *p {
                return false;
            }
        }
        prev = Some(item);
    }
    true
}
