//! Runs each STF module against the downloaded `jam-test-vectors` (tiny) and
//! asserts the computed posterior state (and, where defined, the output)
//! matches the vector byte-for-byte.

use std::fs;
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Deserialize;

fn vector_dir(component: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/vectors")
        .join(component)
}

/// All `*.json` vector paths for a component, sorted by name.
fn vectors(component: &str) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = fs::read_dir(vector_dir(component))
        .unwrap_or_else(|e| panic!("read {component} dir: {e}"))
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|x| x == "json").unwrap_or(false))
        .collect();
    paths.sort();
    assert!(!paths.is_empty(), "no vectors for {component}");
    paths
}

fn load<T: DeserializeOwned>(path: &Path) -> T {
    let raw = fs::read_to_string(path).unwrap();
    serde_json::from_str(&raw).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[derive(Deserialize)]
struct Case<I, S> {
    input: I,
    pre_state: S,
    output: serde_json::Value,
    post_state: S,
}

#[test]
fn statistics_vectors() {
    use minimal_jam::statistics::{transition, Input, State};
    for path in vectors("statistics") {
        let c: Case<Input, State> = load(&path);
        let got = transition(&c.pre_state, &c.input);
        assert_eq!(got, c.post_state, "post_state mismatch: {}", path.display());
        assert!(c.output.is_null(), "expected null output: {}", path.display());
    }
}

#[test]
fn authorizations_vectors() {
    use minimal_jam::authorizations::{transition, Input, State};
    for path in vectors("authorizations") {
        let c: Case<Input, State> = load(&path);
        let got = transition(&c.pre_state, &c.input);
        assert_eq!(got, c.post_state, "post_state mismatch: {}", path.display());
        assert!(c.output.is_null(), "expected null output: {}", path.display());
    }
}

#[test]
fn history_vectors() {
    use minimal_jam::history::{transition, Input, State};
    for path in vectors("history") {
        let c: Case<Input, State> = load(&path);
        let got = transition(&c.pre_state, &c.input);
        assert_eq!(got, c.post_state, "post_state mismatch: {}", path.display());
        assert!(c.output.is_null(), "expected null output: {}", path.display());
    }
}

#[test]
fn preimages_vectors() {
    use minimal_jam::preimages::{transition, Input, State};
    for path in vectors("preimages") {
        let c: Case<Input, State> = load(&path);
        let (outcome, got) = transition(&c.pre_state, &c.input);
        assert_eq!(
            outcome.to_json(),
            c.output,
            "output mismatch: {}",
            path.display()
        );
        assert_eq!(got, c.post_state, "post_state mismatch: {}", path.display());
    }
}
