//! Verify the `C(...)` state-key constructor against real block-import traces:
//! every state key in a trace must be explained as a chapter key `C(1..=16)`,
//! a service account key `C(255, s)`, or a service-dictionary key `C(s, ·)` for
//! a service `s` that has an account in the same state.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use minimal_jam::hexutil::from_hex;
use minimal_jam::state_key::{chapter, service_account, StateKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyVal {
    key: String,
}
#[derive(Deserialize)]
struct Snapshot {
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

/// Service id encoded in a `C(s, ·)` dictionary key (even byte positions).
fn dict_service_id(k: &StateKey) -> u32 {
    u32::from_le_bytes([k[0], k[2], k[4], k[6]])
}

/// Service id encoded in a `C(255, s)` account key (odd byte positions).
fn account_service_id(k: &StateKey) -> u32 {
    u32::from_le_bytes([k[1], k[3], k[5], k[7]])
}

fn classify_snapshot(keys: &[StateKey]) {
    let chapters: BTreeSet<StateKey> = (1u8..=16).map(chapter).collect();
    for &c in &chapters {
        assert!(keys.contains(&c), "missing chapter key {}", hex::encode(c));
    }

    // Discover service accounts (C(255, s)) and validate their layout.
    let mut services = BTreeSet::new();
    for k in keys {
        if k[0] == 255 {
            let s = account_service_id(k);
            assert_eq!(service_account(s), *k, "malformed account key");
            services.insert(s);
        }
    }

    // Every key must be a chapter, an account, or a dict entry of a known service.
    for k in keys {
        if chapters.contains(k) || k[0] == 255 {
            continue;
        }
        let s = dict_service_id(k);
        assert!(
            services.contains(&s),
            "dict key {} references unknown service {s}",
            hex::encode(k)
        );
    }
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

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn traces() -> Vec<PathBuf> {
    json_files(&Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/traces"))
}

fn check_files(files: &[PathBuf]) {
    for path in files {
        let t: Trace = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        for snap in [&t.pre_state, &t.post_state] {
            let keys: Vec<StateKey> = snap.keyvals.iter().map(|kv| key31(&kv.key)).collect();
            classify_snapshot(&keys);
        }
    }
}

#[test]
fn state_keys_explain_real_traces() {
    let files = traces();
    assert!(!files.is_empty(), "no vendored traces");
    check_files(&files);
}

#[test]
fn state_keys_explain_external_traces() {
    let Ok(dir) = std::env::var("JAM_TRACES_DIR") else {
        eprintln!("JAM_TRACES_DIR unset; skipping exhaustive state-key check");
        return;
    };
    let files = json_files(Path::new(&dir));
    assert!(!files.is_empty(), "no traces under JAM_TRACES_DIR");
    check_files(&files);
    eprintln!("classified {} trace files under {dir}", files.len());
}
