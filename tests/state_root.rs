//! End-to-end state merklization: parse a real trace's serialized state into a
//! typed `State` (σ), then assert (a) re-serializing reproduces the exact
//! key/value set and (b) `State::root()` equals the vector's `state_root`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use minimal_jam::hexutil::from_hex;
use minimal_jam::state::State;
use minimal_jam::state_key::StateKey;
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyVal {
    key: String,
    value: String,
}
#[derive(Deserialize)]
struct Snapshot {
    state_root: String,
    keyvals: Vec<KeyVal>,
}
#[derive(Deserialize)]
struct Trace {
    pre_state: Snapshot,
    post_state: Snapshot,
}

fn key31(hex: &str) -> StateKey {
    let bytes = from_hex(hex);
    let mut k = [0u8; 31];
    k.copy_from_slice(&bytes);
    k
}

fn check_snapshot(snap: &Snapshot, ctx: &str) {
    let entries: Vec<(StateKey, Vec<u8>)> = snap
        .keyvals
        .iter()
        .map(|kv| (key31(&kv.key), from_hex(&kv.value)))
        .collect();
    let expected: BTreeMap<StateKey, Vec<u8>> = entries.iter().cloned().collect();

    let sigma = State::from_entries(&entries).unwrap_or_else(|e| panic!("{ctx}: parse σ: {e}"));

    // (a) re-serializing the typed σ reproduces the exact T(σ) dictionary.
    assert_eq!(sigma.serialize(), expected, "{ctx}: T(σ) reconstruction mismatch");

    // (b) the merklized root matches the vector.
    let root = format!("0x{}", hex::encode(sigma.root()));
    assert_eq!(root, snap.state_root.to_lowercase(), "{ctx}: state root mismatch");
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
        } else if p.extension().map(|x| x == "json").unwrap_or(false) {
            out.push(p);
        }
    }
}

fn check_dir(dir: &Path) -> usize {
    let mut files = Vec::new();
    walk(dir, &mut files);
    files.sort();
    for path in &files {
        let t: Trace = serde_json::from_str(&fs::read_to_string(path).unwrap())
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        check_snapshot(&t.pre_state, &format!("{} pre", path.display()));
        check_snapshot(&t.post_state, &format!("{} post", path.display()));
    }
    files.len()
}

#[test]
fn vendored_state_root() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/traces");
    assert!(check_dir(&dir) > 0, "no vendored traces");
}

#[test]
fn external_state_root() {
    let Ok(dir) = std::env::var("JAM_TRACES_DIR") else {
        eprintln!("JAM_TRACES_DIR unset; skipping exhaustive state-root check");
        return;
    };
    let n = check_dir(Path::new(&dir));
    assert!(n > 0, "no traces under JAM_TRACES_DIR");
    eprintln!("merklized σ for {n} trace files");
}
