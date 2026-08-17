//! JAM codec (GP Appendix C).
//!
//! SCALE-like: fixed-width integers are little-endian; the variable-length
//! "general natural" encoding is used **only** for the length prefix of
//! variable-length sequences (incl. byte sequences). Fixed-size sequences carry
//! no prefix.

use serde::de::{self, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

/// Codec error with a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodecError(pub String);

impl fmt::Display for CodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "codec error: {}", self.0)
    }
}

fn err<T>(msg: impl Into<String>) -> Result<T, CodecError> {
    Err(CodecError(msg.into()))
}

/// Cursor over an input buffer.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], CodecError> {
        if self.remaining() < n {
            return err(format!("unexpected end: need {n}, have {}", self.remaining()));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }
}

/// Encode a natural number with the JAM variable-length scheme (GP App. C).
pub fn encode_nat(x: u64, out: &mut Vec<u8>) {
    if x == 0 {
        out.push(0);
        return;
    }
    for l in 0u32..8 {
        let bound: u128 = 1u128 << (7 * (l + 1));
        if (x as u128) < bound {
            let base = 256u32 - (1u32 << (8 - l));
            out.push(base as u8 + (x >> (8 * l)) as u8);
            for i in 0..l {
                out.push((x >> (8 * i)) as u8);
            }
            return;
        }
    }
    out.push(255);
    out.extend_from_slice(&x.to_le_bytes());
}

/// Decode a natural number (inverse of [`encode_nat`]).
pub fn decode_nat(r: &mut Reader) -> Result<u64, CodecError> {
    let first = r.u8()?;
    let l = first.leading_ones();
    if l == 8 {
        let b = r.take(8)?;
        return Ok(u64::from_le_bytes(b.try_into().unwrap()));
    }
    let high = (first & (0xffu8 >> l)) as u64;
    let mut val = 0u64;
    for i in 0..l {
        val |= (r.u8()? as u64) << (8 * i);
    }
    val |= high << (8 * l);
    Ok(val)
}

/// A type that can be JAM-encoded and decoded.
pub trait Codec: Sized {
    fn encode_to(&self, out: &mut Vec<u8>);
    fn decode(r: &mut Reader) -> Result<Self, CodecError>;

    fn encode(&self) -> Vec<u8> {
        let mut v = Vec::new();
        self.encode_to(&mut v);
        v
    }
}

macro_rules! impl_codec_int {
    ($($t:ty),*) => {$(
        impl Codec for $t {
            fn encode_to(&self, out: &mut Vec<u8>) {
                out.extend_from_slice(&self.to_le_bytes());
            }
            fn decode(r: &mut Reader) -> Result<Self, CodecError> {
                let n = std::mem::size_of::<$t>();
                Ok(<$t>::from_le_bytes(r.take(n)?.try_into().unwrap()))
            }
        }
    )*};
}
impl_codec_int!(u8, u16, u32, u64);

impl Codec for bool {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.push(*self as u8);
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        match r.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            b => err(format!("invalid bool byte {b}")),
        }
    }
}

impl<T: Codec> Codec for Option<T> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        match self {
            None => out.push(0),
            Some(v) => {
                out.push(1);
                v.encode_to(out);
            }
        }
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        match r.u8()? {
            0 => Ok(None),
            1 => Ok(Some(T::decode(r)?)),
            b => err(format!("invalid option tag {b}")),
        }
    }
}

/// Variable-length sequence: general-natural length prefix, then items.
impl<T: Codec> Codec for Vec<T> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_nat(self.len() as u64, out);
        for it in self {
            it.encode_to(out);
        }
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        let n = decode_nat(r)? as usize;
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(T::decode(r)?);
        }
        Ok(v)
    }
}

// ---------------------------------------------------------------------------
// Byte types
// ---------------------------------------------------------------------------

/// Fixed-size `N`-byte array (hash, key, signature). No length prefix.
#[derive(Clone, PartialEq, Eq)]
pub struct Hex<const N: usize>(pub [u8; N]);

impl<const N: usize> Codec for Hex<N> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.0);
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        let mut a = [0u8; N];
        a.copy_from_slice(r.take(N)?);
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

/// Variable-length byte sequence (`ByteSequence`): general-natural length
/// prefix, then raw bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);

impl Codec for Blob {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_nat(self.0.len() as u64, out);
        out.extend_from_slice(&self.0);
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        let n = decode_nat(r)? as usize;
        Ok(Blob(r.take(n)?.to_vec()))
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

/// `Compact<T>`: an integer encoded with the JAM general-natural scheme rather
/// than fixed-width. JSON representation is a plain number. Backed by `u64`
/// since the variable encoding is width-agnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Compact(pub u64);

impl Codec for Compact {
    fn encode_to(&self, out: &mut Vec<u8>) {
        encode_nat(self.0, out);
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        Ok(Compact(decode_nat(r)?))
    }
}

impl serde::Serialize for Compact {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u64(self.0)
    }
}

impl<'de> serde::Deserialize<'de> for Compact {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Ok(Compact(u64::deserialize(d)?))
    }
}

/// Fixed-size sequence of exactly `N` items. No length prefix; JSON is a plain
/// array (serde-transparent).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FixedSeq<T, const N: usize>(pub Vec<T>);

impl<T: Codec, const N: usize> Codec for FixedSeq<T, N> {
    fn encode_to(&self, out: &mut Vec<u8>) {
        debug_assert_eq!(self.0.len(), N, "fixed sequence must hold exactly N items");
        for it in &self.0 {
            it.encode_to(out);
        }
    }
    fn decode(r: &mut Reader) -> Result<Self, CodecError> {
        let mut v = Vec::with_capacity(N);
        for _ in 0..N {
            v.push(T::decode(r)?);
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

/// Define a struct plus its field-order codec and serde derives.
#[macro_export]
macro_rules! codec_struct {
    ($(#[$m:meta])* $name:ident { $($field:ident : $ty:ty),* $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Debug, PartialEq, serde::Serialize, serde::Deserialize)]
        pub struct $name { $(pub $field: $ty),* }

        impl $crate::codec::Codec for $name {
            fn encode_to(&self, out: &mut Vec<u8>) {
                $( $crate::codec::Codec::encode_to(&self.$field, out); )*
            }
            fn decode(r: &mut $crate::codec::Reader) -> Result<Self, $crate::codec::CodecError> {
                Ok(Self { $( $field: $crate::codec::Codec::decode(r)? ),* })
            }
        }
    };
}
