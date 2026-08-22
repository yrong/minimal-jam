//! Disputes STF conformance: decode each vector, run the transition, and assert
//! the output and post-state match.

use std::fs;
use std::path::Path;

use minimal_jam::disputes::{transition, Input, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input: Input,
    pre_state: State,
    output: serde_json::Value,
    post_state: State,
}

fn run(name: &str) {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/disputes")
        .join(format!("{name}.json"));
    let c: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|e| panic!("parse {name}: {e}"));

    let (outcome, post) = transition(&c.pre_state, &c.input);
    assert_eq!(
        serde_json::to_value(&outcome).unwrap(),
        c.output,
        "output mismatch: {name}"
    );
    assert_eq!(post, c.post_state, "post_state mismatch: {name}");
}

#[test]
fn disputes_vectors() {
    run("progress_with_no_verdicts-1");
    // Verdicts: ordering, uniqueness, vote tally.
    run("progress_with_verdicts-1"); // reports not sorted within a verdict
    run("progress_with_verdicts-2"); // votes not unique within a verdict
    run("progress_with_verdicts-3"); // verdicts not sorted
    run("progress_with_verdicts-4"); // sorted, valid
    run("progress_with_verdicts-5"); // bad vote split
    run("progress_with_verdicts-6"); // wonky verdict
    // Culprits.
    run("progress_with_culprits-1"); // missing culprits for bad verdict
    run("progress_with_culprits-2"); // single culprit for bad verdict
    run("progress_with_culprits-3"); // two culprits, not sorted
    run("progress_with_culprits-4"); // two culprits, sorted
    run("progress_with_culprits-5"); // already-recorded verdict
    run("progress_with_culprits-6"); // culprit already an offender
    run("progress_with_culprits-7"); // offender for absent verdict
    // Faults.
    run("progress_with_faults-1"); // missing faults for good verdict
    run("progress_with_faults-2"); // one fault, good verdict
    run("progress_with_faults-3"); // two faults, not sorted
    run("progress_with_faults-4"); // two faults, sorted
    run("progress_with_faults-5"); // already-recorded verdict
    run("progress_with_faults-6"); // fault already an offender
    run("progress_with_faults-7"); // vote matches verdict
    // Key membership and signatures.
    run("progress_with_invalid_keys-1"); // bad guarantor key
    run("progress_with_invalid_keys-2"); // bad auditor key
    run("progress_with_bad_signatures-1"); // bad judgment signature
    run("progress_with_bad_signatures-2"); // bad culprit signature
    // Validator-set selection and age.
    run("progress_with_verdict_signatures_from_previous_set-1"); // λ set
    run("progress_with_verdict_signatures_from_previous_set-2"); // age too old
    // Availability invalidation.
    run("progress_invalidates_avail_assignments-1");
}
