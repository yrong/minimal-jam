//! State-trie conformance: for each `trie/trie.json` case, build the key/value
//! set and assert `state_root == output`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use minimal_jam::trie::{state_root, Key};
use serde::Deserialize;

#[derive(Deserialize)]
struct Case {
    input: BTreeMap<String, String>,
    output: String,
}

fn key32(s: &str) -> Key {
    let bytes = hex::decode(s).unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&bytes);
    k
}

#[test]
fn trie_vectors() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/trie/trie.json");
    let raw = fs::read_to_string(&path).unwrap();
    let cases: Vec<Case> = serde_json::from_str(&raw).unwrap();
    assert!(!cases.is_empty());

    for (n, c) in cases.iter().enumerate() {
        let kvs: Vec<(Key, Vec<u8>)> = c
            .input
            .iter()
            .map(|(k, v)| (key32(k), hex::decode(v).unwrap()))
            .collect();
        let got = hex::encode(state_root(&kvs));
        assert_eq!(got, c.output, "case {n} ({} kv)", kvs.len());
    }
}
