//! Codec conformance: for each `codec/tiny` vector, assert
//! `encode(from_json(.json)) == .bin` and `decode(.bin) == from_json(.json)`,
//! with no trailing bytes.

use std::fmt::Debug;
use std::fs;
use std::path::Path;

use jam_codec::{Decode, Encode};
use minimal_jam::bytes::decode_all;
use minimal_jam::types::*;
use serde::de::DeserializeOwned;

fn check<T: Encode + Decode + DeserializeOwned + PartialEq + Debug>(name: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/codec");
    let json = fs::read_to_string(dir.join(format!("{name}.json")))
        .unwrap_or_else(|e| panic!("read {name}.json: {e}"));
    let bin = fs::read(dir.join(format!("{name}.bin")))
        .unwrap_or_else(|e| panic!("read {name}.bin: {e}"));

    let value: T = serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse {name}: {e}"));

    // Encode direction: JSON value must serialize to the canonical bytes.
    assert_eq!(value.encode(), bin, "encode mismatch: {name}");

    // Decode direction: bytes must round-trip to the same value, fully consumed.
    let decoded = decode_all::<T>(&bin).unwrap_or_else(|e| panic!("decode {name}: {e:?}"));
    assert_eq!(decoded, value, "decode mismatch: {name}");
}

#[test]
fn codec_vectors() {
    check::<RefineContext>("refine_context");
    check::<WorkItem>("work_item");
    check::<WorkPackage>("work_package");
    check::<WorkResult>("work_result_0");
    check::<WorkResult>("work_result_1");
    check::<WorkReport>("work_report");
    check::<Vec<TicketEnvelope>>("tickets_extrinsic");
    check::<DisputesExtrinsic>("disputes_extrinsic");
    check::<Vec<Preimage>>("preimages_extrinsic");
    check::<Vec<AvailAssurance>>("assurances_extrinsic");
    check::<Vec<ReportGuarantee>>("guarantees_extrinsic");
    check::<Header>("header_0");
    check::<Header>("header_1");
    check::<Extrinsic>("extrinsic");
    check::<Block>("block");
}
