//! Accumulate STF conformance (queue-management slice). Vectors that actually
//! accumulate a report (PVM execution) are not yet handled and are listed as
//! known-deferred rather than asserted.

use std::fs;
use std::path::Path;

use minimal_jam::accumulate::{transition, Input, State};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input: Input,
    pre_state: State,
    output: serde_json::Value,
    post_state: State,
}

fn run(name: &str) -> Result<(), String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors/accumulate")
        .join(format!("{name}.json"));
    let c: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|e| panic!("parse {name}: {e}"));
    let (outcome, post) = transition(&c.pre_state, &c.input);
    if serde_json::to_value(&outcome).unwrap() != c.output {
        return Err("output".into());
    }
    if post != c.post_state {
        return Err("post_state".into());
    }
    Ok(())
}

/// Queue-management vectors: reports are enqueued (unsatisfied deps) or the
/// block accumulates nothing, so no PVM execution is required.
const QUEUE_ONLY: &[&str] = &[
    "no_available_reports-1",
    "enqueue_and_unlock_simple-1",
    "enqueue_and_unlock_with_sr_lookup-1",
    "enqueue_and_unlock_chain-1",
    "enqueue_and_unlock_chain-2",
    "enqueue_and_unlock_chain_wraps-1",
    "enqueue_and_unlock_chain_wraps-3",
    "enqueue_self_referential-1",
    "enqueue_self_referential-2",
    "enqueue_self_referential-3",
    "enqueue_self_referential-4",
    "queues_are_shifted-2",
    "ready_queue_editing-1",
    "work_for_ejected_service-1",
];

#[test]
fn accumulate_queue_vectors() {
    let mut failures = Vec::new();
    for name in QUEUE_ONLY {
        if let Err(why) = run(name) {
            failures.push(format!("{name}: {why}"));
        }
    }
    assert!(failures.is_empty(), "{} failed:\n{}", failures.len(), failures.join("\n"));
}
