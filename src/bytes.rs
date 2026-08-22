//! Dual-purpose value wrappers: serde (JSON hex/number/array) on one side,
//! `jam-codec` `Encode`/`Decode` (the JAM binary codec) on the other.
//!
//! The binary encoding is delegated to `jam-codec`; these wrappers only add the
//! JSON representations the test vectors use and the fixed-vs-variable sequence
//! distinction the trie needs.

use jam_codec::{Decode, Encode, Error, Input, Output};
use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

/// Fixed-size `N`-byte array (hash, key, signature). Encodes as raw bytes with
/// no length prefix; JSON is a `0x`-prefixed hex string.
#[derive(Clone, PartialEq, Eq)]
pub struct Hex<const N: usize>(pub [u8; N]);

impl<const N: usize> Encode for Hex<N> {
    fn size_hint(&self) -> usize {
        N
    }
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        dest.write(&self.0);
    }
}

impl<const N: usize> Decode for Hex<N> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut a = [0u8; N];
        input.read(&mut a)?;
        Ok(Hex(a))
    }
}

impl<const N: usize> fmt::Debug for Hex<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl<const N: usize> serde::Serialize for Hex<N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

struct HexVisitor<const N: usize>;
impl<'de, const N: usize> Visitor<'de> for HexVisitor<N> {
    type Value = Hex<N>;
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a 0x-prefixed hex string of {N} bytes")
    }
    fn visit_str<E: de::Error>(self, v: &str) -> Result<Hex<N>, E> {
        let bytes = hex::decode(v.trim_start_matches("0x")).map_err(E::custom)?;
        if bytes.len() != N {
            return Err(E::custom(format!("expected {N} bytes, got {}", bytes.len())));
        }
        let mut a = [0u8; N];
        a.copy_from_slice(&bytes);
        Ok(Hex(a))
    }
}

impl<'de, const N: usize> serde::Deserialize<'de> for Hex<N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_str(HexVisitor::<N>)
    }
}

/// Variable-length byte sequence (`ByteSequence`): compact length prefix then
/// raw bytes (identical to `Vec<u8>` under `jam-codec`); JSON is a hex string.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl Encode for Blob {
    fn size_hint(&self) -> usize {
        self.0.len() + 4
    }
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        self.0.encode_to(dest);
    }
}

impl Decode for Blob {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        Ok(Blob(Vec::<u8>::decode(input)?))
    }
}

impl fmt::Debug for Blob {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(&self.0))
    }
}

impl serde::Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> serde::Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Blob;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "a 0x-prefixed hex string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Blob, E> {
                Ok(Blob(hex::decode(v.trim_start_matches("0x")).map_err(E::custom)?))
            }
        }
        d.deserialize_str(V)
    }
}

/// Fixed-size sequence of exactly `N` items. No length prefix; JSON is a plain
/// array (serde-transparent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedSeq<T, const N: usize>(pub Vec<T>);

impl<T: Encode, const N: usize> Encode for FixedSeq<T, N> {
    fn encode_to<W: Output + ?Sized>(&self, dest: &mut W) {
        debug_assert_eq!(self.0.len(), N, "fixed sequence must hold exactly N items");
        for item in &self.0 {
            item.encode_to(dest);
        }
    }
}

impl<T: Decode, const N: usize> Decode for FixedSeq<T, N> {
    fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
        let mut v = Vec::with_capacity(N);
        for _ in 0..N {
            v.push(T::decode(input)?);
        }
        Ok(FixedSeq(v))
    }
}

impl<T: serde::Serialize, const N: usize> serde::Serialize for FixedSeq<T, N> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(s)
    }
}

impl<'de, T: serde::Deserialize<'de>, const N: usize> serde::Deserialize<'de> for FixedSeq<T, N> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(FixedSeq(Vec::<T>::deserialize(d)?))
    }
}

/// Empty payload that serializes as JSON `null` and encodes to nothing. Used as
/// the body of unit CHOICE variants (e.g. `WorkExecResult::Panic`).
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Null;

impl Encode for Null {
    fn size_hint(&self) -> usize {
        0
    }
    fn encode_to<W: Output + ?Sized>(&self, _dest: &mut W) {}
}

impl Decode for Null {
    fn decode<I: Input>(_input: &mut I) -> Result<Self, Error> {
        Ok(Null)
    }
}

/// Decode `T` from exactly `bytes`, erroring on any trailing input.
pub fn decode_all<T: Decode>(bytes: &[u8]) -> Result<T, Error> {
    let mut input = bytes;
    let v = T::decode(&mut input)?;
    if !input.is_empty() {
        return Err("trailing bytes".into());
    }
    Ok(v)
}
