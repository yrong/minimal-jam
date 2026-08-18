//! Per-component state serialization conformance: for each implemented chapter,
//! decode its value from a real trace's state and re-encode it, asserting a
//! byte-exact round-trip. This proves `T(σ)` value serialization component by
//! component against production state.
//!
//! Always-on: the vendored `fallback` sample. Opt-in exhaustive: `JAM_TRACES_DIR`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use minimal_jam::codec::{Codec, Reader};
use minimal_jam::hexutil::from_hex;
use minimal_jam::state::{
    AccumulatedQueue, AuthPools, AuthQueues, AvailabilityAssignments, DisputesRecords,
    EntropyBuffer, LastAccout, Privileges, ReadyQueue, RecentBlocks, SafroleState, ServiceInfo,
    Statistics, TimeSlot, ValidatorSet,
};
use minimal_jam::state_key::{chapter, service_account};
use serde::Deserialize;

#[derive(Deserialize)]
struct KeyVal {
    key: String,
    value: String,
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

/// Decode `T` from `bytes`, require full consumption, and re-encode to the same bytes.
fn round_trip<T: Codec>(bytes: &[u8], ctx: &str) {
    let mut r = Reader::new(bytes);
    let v = T::decode(&mut r).unwrap_or_else(|e| panic!("{ctx}: decode: {e}"));
    assert_eq!(r.remaining(), 0, "{ctx}: trailing bytes");
    assert_eq!(v.encode(), bytes, "{ctx}: re-encode mismatch");
}

fn check_chapter<T: Codec>(map: &BTreeMap<String, Vec<u8>>, i: u8, ctx: &str) {
    let key = hex::encode(chapter(i));
    let value = map
        .get(&key)
        .unwrap_or_else(|| panic!("{ctx}: chapter C({i}) missing"));
    round_trip::<T>(value, &format!("{ctx} C({i})"));
}

fn check_snapshot(snap: &Snapshot, ctx: &str) {
    let map: BTreeMap<String, Vec<u8>> = snap
        .keyvals
        .iter()
        .map(|kv| (kv.key.trim_start_matches("0x").to_string(), from_hex(&kv.value)))
        .collect();

    check_chapter::<AuthPools>(&map, 1, ctx); // α
    check_chapter::<AuthQueues>(&map, 2, ctx); // φ
    check_chapter::<DisputesRecords>(&map, 5, ctx); // ψ
    check_chapter::<EntropyBuffer>(&map, 6, ctx); // η
    check_chapter::<ValidatorSet>(&map, 7, ctx); // ι
    check_chapter::<ValidatorSet>(&map, 8, ctx); // κ
    check_chapter::<ValidatorSet>(&map, 9, ctx); // λ
    check_chapter::<AvailabilityAssignments>(&map, 10, ctx); // ρ
    check_chapter::<TimeSlot>(&map, 11, ctx); // τ
    check_chapter::<Privileges>(&map, 12, ctx); // χ
    check_chapter::<RecentBlocks>(&map, 3, ctx); // β
    check_chapter::<SafroleState>(&map, 4, ctx); // γ
    check_chapter::<Statistics>(&map, 13, ctx); // π
    check_chapter::<ReadyQueue>(&map, 14, ctx); // ϑ
    check_chapter::<AccumulatedQueue>(&map, 15, ctx); // ξ
    check_chapter::<LastAccout>(&map, 16, ctx); // last accout

    // Service account metadata: keys C(255, s).
    for kv in &snap.keyvals {
        let kb = from_hex(&kv.key);
        if kb[0] == 255 {
            let s = u32::from_le_bytes([kb[1], kb[3], kb[5], kb[7]]);
            if hex::encode(service_account(s)) == kv.key.trim_start_matches("0x") {
                round_trip::<ServiceInfo>(&from_hex(&kv.value), &format!("{ctx} C(255,{s})"));
            }
        }
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
fn vendored_state_components() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/traces");
    assert!(check_dir(&dir) > 0, "no vendored traces");
}

#[test]
fn external_state_components() {
    let Ok(dir) = std::env::var("JAM_TRACES_DIR") else {
        eprintln!("JAM_TRACES_DIR unset; skipping exhaustive state-component check");
        return;
    };
    let n = check_dir(Path::new(&dir));
    assert!(n > 0, "no traces under JAM_TRACES_DIR");
    eprintln!("round-tripped state components in {n} trace files");
}
