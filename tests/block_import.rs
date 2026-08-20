//! Block-import STF wiring against real `fallback` traces: decode the block and
//! pre-state, run the implemented transitions (τ, π, α), and assert the
//! recomputed chapter values equal the trace's post-state.
//!
//! Restricted to `fallback` traces, where extrinsics carry no work reports or
//! preimages, so validator statistics alone fully determine π and the
//! core/service records are unchanged.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use minimal_jam::block_import::{
    import_block, next_auth_pools, next_entropy, next_recent_blocks, next_statistics,
    next_timeslot,
};
use jam_codec::Encode;
use minimal_jam::hexutil::from_hex;
use minimal_jam::state::State;
use minimal_jam::state_key::{chapter, StateKey};
use minimal_jam::types::Block;
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
    block: Block,
    post_state: Snapshot,
}

fn key31(hex: &str) -> StateKey {
    let mut k = [0u8; 31];
    k.copy_from_slice(&from_hex(hex));
    k
}

fn check_file(path: &Path) {
    let t: Trace = serde_json::from_str(&fs::read_to_string(path).unwrap())
        .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));

    let pre_entries: Vec<(StateKey, Vec<u8>)> = t
        .pre_state
        .keyvals
        .iter()
        .map(|kv| (key31(&kv.key), from_hex(&kv.value)))
        .collect();
    let sigma = State::from_entries(&pre_entries).unwrap();

    let post: BTreeMap<StateKey, Vec<u8>> = t
        .post_state
        .keyvals
        .iter()
        .map(|kv| (key31(&kv.key), from_hex(&kv.value)))
        .collect();
    let want = |i: u8| -> &Vec<u8> { post.get(&chapter(i)).expect("chapter present") };

    let ctx = path.display();

    // τ (C11): posterior timeslot is the block's slot.
    assert_eq!(next_timeslot(&t.block).encode(), *want(11), "{ctx}: τ mismatch");

    // π (C13): validator statistics.
    let stats = next_statistics(&sigma.statistics, sigma.timeslot, &t.block);
    assert_eq!(stats.encode(), *want(13), "{ctx}: π mismatch");

    // α (C1): authorizer pools.
    let pools = next_auth_pools(&sigma.auth_pools, &sigma.auth_queues, &t.block);
    assert_eq!(pools.encode(), *want(1), "{ctx}: α mismatch");

    // β (C3): recent blocks. Fallback has no work reports, so the
    // accumulation-output root is the empty (zero) hash.
    let beta = next_recent_blocks(&sigma.recent_blocks, &t.block, [0u8; 32]);
    assert_eq!(beta.encode(), *want(3), "{ctx}: β mismatch");

    // η (C6): entropy accumulator (bandersnatch VRF output).
    let eta = next_entropy(&sigma.entropy, sigma.timeslot, &t.block);
    assert_eq!(eta.encode(), *want(6), "{ctx}: η mismatch");

    // Unified entry point: import_block must reproduce the entire posterior σ —
    // every chapter (changed and carried-through) and the merklized root.
    let post_sigma = import_block(&sigma, &t.block);
    assert_eq!(post_sigma.serialize(), post, "{ctx}: T(σ') dictionary mismatch");
    let root = format!("0x{}", hex::encode(post_sigma.root()));
    assert_eq!(root, t.post_state.state_root.to_lowercase(), "{ctx}: σ' root mismatch");
}

/// Collect fallback trace files under `dir` (a directory that contains or is a
/// `fallback` set).
fn fallback_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = fs::read_dir(dir) else { return };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().map(|x| x == "json").unwrap_or(false)
                && p.file_stem().map(|s| s != "genesis").unwrap_or(false)
                && p.components().any(|c| c.as_os_str() == "fallback")
            {
                out.push(p);
            }
        }
    }
    walk(dir, &mut out);
    out.sort();
    out
}

#[test]
fn vendored_fallback_import() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/traces");
    let files = fallback_files(&dir);
    assert!(!files.is_empty(), "no vendored fallback traces");
    for f in files {
        check_file(&f);
    }
}

#[test]
fn external_fallback_import() {
    let Ok(dir) = std::env::var("JAM_TRACES_DIR") else {
        eprintln!("JAM_TRACES_DIR unset; skipping exhaustive block-import check");
        return;
    };
    let files = fallback_files(Path::new(&dir));
    assert!(!files.is_empty(), "no fallback traces under JAM_TRACES_DIR");
    for f in &files {
        check_file(f);
    }
    eprintln!("block-import verified for {} fallback traces", files.len());
}
