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

#[test]
fn safrole_epoch_change_vectors() {
    // Epoch transitions with no tickets: rotation, γ_z ring commitment,
    // γ_s fallback keys, η rotation, epoch marker.
    run("enact-epoch-change-with-no-tickets-4"); // epoch 0 -> 1
    run("enact-epoch-change-with-padding-1");
    run("skip-epochs-1"); // skips multiple epochs
    run("skip-epoch-tail-1");
}

#[test]
fn safrole_ticket_vectors() {
    // Ticket submission: RingVRF proof verification, id extraction, validity
    // (attempt/order/duplicate/tail), accumulator merge, winning-tickets marker,
    // and Z(γ_a) sealing on epoch change.
    run("publish-tickets-no-mark-1"); // bad_ticket_attempt
    run("publish-tickets-no-mark-2"); // ok: 0 -> 3 accumulated
    run("publish-tickets-no-mark-5"); // bad_ticket_proof (invalid ring proof)
    run("publish-tickets-no-mark-3"); // duplicate_ticket
    run("publish-tickets-no-mark-4"); // bad_ticket_order
    run("publish-tickets-no-mark-6"); // ok: 3 -> 6 accumulated
    run("publish-tickets-no-mark-7"); // unexpected_ticket (tail)
    run("publish-tickets-no-mark-8"); // ok: empty extrinsic in tail
    run("publish-tickets-no-mark-9"); // ok: epoch change, γ_a reset
    run("publish-tickets-with-mark-1"); // ok: 7 -> 9
    run("publish-tickets-with-mark-2"); // ok: 9 -> 12 (saturated)
    run("publish-tickets-with-mark-3"); // ok: 12 -> 12 (keep lowest E)
    run("publish-tickets-with-mark-4"); // winning-tickets marker Z(γ_a)
    run("publish-tickets-with-mark-5"); // epoch change, Z(γ_a) sealing
}
