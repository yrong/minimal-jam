//! Assurances STF conformance: decode each vector, run the transition, and
//! assert the output and post-state match.

use std::fs;
use std::path::Path;

use minimal_jam::assurances::{transition, Input, State};
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
        .join("tests/vectors/assurances")
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
fn assurances_vectors() {
    run("no_assurances-1");
    run("some_assurances-1"); // super-majority makes a core available
    run("no_assurances_with_stale_report-1"); // timed-out report removed, not reported
    run("assurances_for_stale_report-1"); // stale but available -> reported
    run("assurances_with_bad_signature-1");
    run("assurances_with_bad_validator_index-1");
    run("assurance_for_not_engaged_core-1");
    run("assurance_with_bad_attestation_parent-1");
    run("assurers_not_sorted_or_unique-1"); // not sorted
    run("assurers_not_sorted_or_unique-2"); // duplicate assurer
}
