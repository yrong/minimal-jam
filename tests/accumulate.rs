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
        let gp = serde_json::to_value(&post).unwrap();
        let wp = serde_json::to_value(&c.post_state).unwrap();
        let field = ["accounts", "statistics", "ready_queue", "accumulated", "slot", "privileges", "entropy"]
            .iter()
            .find(|k| gp[*k] != wp[*k])
            .map(|s| s.to_string())
            .unwrap_or_else(|| "other".into());
        return Err(format!("post_state.{field}"));
    }
    Ok(())
}

#[test]
fn accumulate_vectors() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/accumulate");
    let mut names: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "json").then(|| p.file_stem()?.to_str().map(String::from))?
        })
        .collect();
    names.sort();
    let mut failures = Vec::new();
    for name in &names {
        if let Err(why) = run(name) {
            failures.push(format!("{name}: {why}"));
        }
    }
    eprintln!("accumulate: {}/{} pass", names.len() - failures.len(), names.len());
    assert!(
        failures.is_empty(),
        "{}/{} failed:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n")
    );
}
