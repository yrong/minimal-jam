//! Reports STF conformance: decode every vector in the directory, run the
//! transition, and assert the output and post-state match.

use std::fs;
use std::path::Path;

use minimal_jam::reports::{transition, Input, State};
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
        .join("tests/vectors/reports")
        .join(format!("{name}.json"));
    let c: Case = serde_json::from_str(&fs::read_to_string(&path).unwrap())
        .unwrap_or_else(|e| panic!("parse {name}: {e}"));

    let (outcome, post) = transition(&c.pre_state, &c.input);
    let got = serde_json::to_value(&outcome).unwrap();
    if got != c.output {
        return Err(format!("output: got {got} want {}", c.output));
    }
    if post != c.post_state {
        let gp = serde_json::to_value(&post).unwrap();
        let wp = serde_json::to_value(&c.post_state).unwrap();
        let field = ["avail_assignments", "cores_statistics", "services_statistics"]
            .iter()
            .find(|k| gp[*k] != wp[*k])
            .map(|s| s.to_string())
            .unwrap_or_else(|| "other".into());
        return Err(format!("post_state differs in {field}"));
    }
    Ok(())
}

#[test]
fn reports_vectors() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/reports");
    let mut names: Vec<String> = fs::read_dir(&dir)
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
    assert!(
        failures.is_empty(),
        "{}/{} failed:\n{}",
        failures.len(),
        names.len(),
        failures.join("\n")
    );
}
