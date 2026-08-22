//! Bandersnatch ring commitment (GP safrole `γ_z`), via `ark-vrf` 0.1.0 + the
//! Zcash SRS. The commitment is the `RingVerifierKey` commitment over the
//! validators' bandersnatch public keys; invalid/absent keys use the padding
//! point. Tiny uses `ring_size = 6`.

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_vrf::suites::bandersnatch::{Output, PcsParams, Public, RingProofParams};
use std::sync::LazyLock;

/// KZG SRS (Zcash powers-of-tau, uncompressed) shipped by the test vectors.
const SRS: &[u8] = include_bytes!("zcash-srs-2-11-uncompressed.bin");

/// Tiny chain-spec ring size (number of validators).
const RING_SIZE: usize = 6;

/// A `BandersnatchRingCommitment` is 144 bytes.
pub type RingCommitmentBytes = [u8; 144];

static PARAMS: LazyLock<RingProofParams> = LazyLock::new(|| {
    let pcs =
        PcsParams::deserialize_uncompressed_unchecked(&mut &SRS[..]).expect("valid Zcash SRS");
    RingProofParams::from_pcs_params(RING_SIZE, pcs).expect("ring params from SRS")
});

/// Ring commitment `γ_z` over the given 32-byte bandersnatch public keys.
///
/// A key that is not a valid point (e.g. a nulled/offender key) is replaced by
/// the ring padding point, per the JAM/`ark-vrf` convention.
pub fn ring_commitment(keys: &[[u8; 32]]) -> RingCommitmentBytes {
    let padding = RingProofParams::padding_point();
    let pts: Vec<_> = keys
        .iter()
        .map(|k| {
            Public::deserialize_compressed(&k[..])
                .map(|p| p.0)
                .unwrap_or(padding)
        })
        .collect();

    let commitment = PARAMS.verifier_key(&pts).commitment();
    let mut out = Vec::with_capacity(144);
    commitment
        .serialize_compressed(&mut out)
        .expect("serialize ring commitment");
    let mut bytes = [0u8; 144];
    bytes.copy_from_slice(&out);
    bytes
}

/// Bandersnatch VRF output hash `banderout` — the 32-byte VRF output of a
/// signature (IETF or ring), taken from the output point in its first 32 bytes.
pub fn vrf_output_hash(signature: &[u8]) -> [u8; 32] {
    let out = Output::deserialize_compressed(&signature[..32])
        .expect("valid bandersnatch VRF output point");
    let hash = out.hash();
    let bytes: &[u8] = hash.as_ref();
    let mut y = [0u8; 32];
    y.copy_from_slice(&bytes[..32]);
    y
}

/// Verify a Bandersnatch RingVRF signature against a ring commitment `γ_z`.
///
/// `signature` is the JAM ticket proof: a 32-byte compressed VRF output point
/// followed by the ring proof. `input_data` is the VRF input pre-image and
/// `aux` the (empty, for tickets) additional data. Returns `true` iff the proof
/// verifies under the ring committed by `commitment`.
pub fn ring_verify(commitment: &[u8; 144], input_data: &[u8], aux: &[u8], signature: &[u8]) -> bool {
    use ark_vrf::suites::bandersnatch::{BandersnatchSha512Ell2, Input, RingCommitment, RingProof};

    if signature.len() < 32 {
        return false;
    }
    let Ok(commit) = RingCommitment::deserialize_compressed(&commitment[..]) else {
        return false;
    };
    let Some(input) = Input::new(input_data) else {
        return false;
    };
    let Ok(output) = Output::deserialize_compressed(&signature[..32]) else {
        return false;
    };
    let Ok(proof) = RingProof::deserialize_compressed(&signature[32..]) else {
        return false;
    };
    let vk = PARAMS.verifier_key_from_commitment(commit);
    let verifier = PARAMS.verifier(vk);
    <Public as ark_vrf::ring::Verifier<BandersnatchSha512Ell2>>::verify(
        input, output, aux, &proof, &verifier,
    )
    .is_ok()
}
