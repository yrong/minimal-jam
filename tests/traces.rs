//! Trie-vs-real-state conformance: for each block-import trace, rebuild the
//! `pre_state` and `post_state` roots from their key/value sets and assert they
//! match the vector's `state_root`. This exercises the App. D trie on real,
//! production-shaped JAM state (31-byte keys padded to 32).
//!
//! Always-on: the small vendored sample under `tests/vectors/traces`.
//! Opt-in exhaustive: set `JAM_TRACES_DIR` to a full `traces/` checkout.

use std::fs;
use std::path::{Path, PathBuf};

use minimal_jam::hexutil::from_hex;
use minimal_jam::trie::{state_key, state_root};
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyVal {
    key: String,
    value: String,
}

#[derive(Deserialize)]
struct StateSnapshot {
    state_root: String,
    keyvals: Vec<KeyVal>,
}

#[derive(Deserialize)]
struct Trace {
    pre_state: StateSnapshot,
    post_state: StateSnapshot,
}

/// Recursively collect `*.json` files under `dir`.
fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            json_files(&p, out);
        } else if p.extension().map(|x| x == "json").unwrap_or(false) {
            out.push(p);
        }
    }
}

/// Rebuild and check one snapshot's root; returns its expected root hex.
fn check_snapshot(snap: &StateSnapshot, path: &Path, side: &str) -> String {
    let kvs: Vec<([u8; 32], Vec<u8>)> = snap
        .keyvals
        .iter()
        .map(|kv| (state_key(&from_hex(&kv.key)), from_hex(&kv.value)))
        .collect();
    let got = format!("0x{}", hex::encode(state_root(&kvs)));
    assert_eq!(
        got,
        snap.state_root.to_lowercase(),
        "{side} root mismatch: {}",
        path.display()
    );
    snap.state_root.to_lowercase()
}

fn check_dir(dir: &Path) -> usize {
    let mut files = Vec::new();
    json_files(dir, &mut files);
    files.sort();
    for path in &files {
        let raw = fs::read_to_string(path).unwrap();
        let t: Trace = serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
        check_snapshot(&t.pre_state, path, "pre_state");
        check_snapshot(&t.post_state, path, "post_state");
    }
    files.len()
}

#[test]
fn vendored_traces() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/traces");
    let n = check_dir(&dir);
    assert!(n > 0, "no vendored traces found");
}

/// Exhaustive check over a full local `traces/` checkout when `JAM_TRACES_DIR`
/// is set; skipped otherwise.
#[test]
fn external_traces() {
    let Ok(dir) = std::env::var("JAM_TRACES_DIR") else {
        eprintln!("JAM_TRACES_DIR unset; skipping exhaustive traces check");
        return;
    };
    let n = check_dir(Path::new(&dir));
    assert!(n > 0, "no traces found under JAM_TRACES_DIR={dir}");
    eprintln!("verified {n} trace files under {dir}");
}
