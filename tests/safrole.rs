//! Safrole STF conformance (within-epoch / bad-slot slice): decode each vector,
//! run the transition, and assert the output and post-state match.

use std::fs;
use std::path::Path;

use minimal_jam::safrole::{transition, Input, State};
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
        .join("tests/vectors/safrole")
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
fn safrole_within_epoch_vectors() {
    // Within-epoch advances (τ, η) and the monotonic-slot error.
    run("enact-epoch-change-with-no-tickets-1"); // tau 0 -> slot 1
    run("enact-epoch-change-with-no-tickets-2"); // tau 1 -> slot 1: bad_slot
    run("enact-epoch-change-with-no-tickets-3"); // tau 1 -> slot 10
}
