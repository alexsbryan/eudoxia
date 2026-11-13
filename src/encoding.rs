//! Streaming closed-schema producer. docs/ENCODING.md fixes tags and field order.
use alloc::string::{String, ToString};
use serde::{
    Serialize, Serializer,
    ser::{
        self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
        SerializeTupleStruct, SerializeTupleVariant,
    },
};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) enum Error {
    UnknownLength,
    Float,
    Range,
    Count,
    Message(String),
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Message(s) => f.write_str(s),
            _ => write!(f, "invalid frame-4 value: {self:?}"),
        }
    }
}
impl core::error::Error for Error {}
impl ser::Error for Error {
    fn custom<T: core::fmt::Display>(message: T) -> Self {
        Self::Message(message.to_string())
    }
}

trait Sink {
    fn write(&mut self, bytes: &[u8]);
}
impl Sink for Sha256 {
    fn write(&mut self, bytes: &[u8]) {
        self.update(bytes);
    }
}
#[cfg(test)]
impl Sink for alloc::vec::Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}
struct Encoder<S>(S);
impl<S: Sink> Encoder<S> {
    fn byte(&mut self, tag: u8) {
        self.0.write(&[tag]);
    }
    fn number(&mut self, tag: u8, n: u64) {
        self.byte(tag);
        self.0.write(&n.to_be_bytes());
    }
    fn bytes(&mut self, tag: u8, bytes: &[u8]) {
        self.number(tag, bytes.len() as u64);
        self.0.write(bytes);
    }
    fn compound(&mut self, tag: u8, len: usize) -> Compound<'_, S> {
        self.number(tag, len as u64);
        Compound {
            encoder: self,
            left: len,
            key: false,
        }
    }
    fn variant(&mut self, tag: u8, name: &str) {
        self.byte(tag);
        self.bytes(5, name.as_bytes());
    }
}
pub(crate) fn fingerprint(
    domain: &[u8],
    value: &impl Serialize,
) -> Result<crate::Fingerprint, Error> {
    let mut h = Sha256::new();
    h.update(b"eudoxia/frame/4\0");
    h.update((domain.len() as u64).to_be_bytes());
    h.update(domain);
    let mut encoder = Encoder(h);
    value.serialize(&mut encoder)?;
    Ok(crate::Fingerprint(encoder.0.finalize().into()))
}
#[cfg(test)]
fn bytes(value: &impl Serialize) -> alloc::vec::Vec<u8> {
    let mut e = Encoder(alloc::vec::Vec::new());
    value.serialize(&mut e).unwrap();
    e.0
}
pub(crate) fn raw<S: Serializer>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_bytes(value)
}
pub(crate) struct Raw<'a>(pub &'a [u8]);
impl Serialize for Raw<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        raw(self.0, s)
    }
}

struct Compound<'a, S> {
    encoder: &'a mut Encoder<S>,
    left: usize,
    key: bool,
}
impl<S: Sink> Compound<'_, S> {
    fn element<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        self.left = self.left.checked_sub(1).ok_or(Error::Count)?;
        value.serialize(&mut *self.encoder)
    }
    fn field<T: Serialize + ?Sized>(&mut self, key: &str, value: &T) -> Result<(), Error> {
        self.encoder.bytes(5, key.as_bytes());
        self.element(value)
    }
    fn finish(self) -> Result<(), Error> {
        if self.left == 0 && !self.key {
            Ok(())
        } else {
            Err(Error::Count)
        }
    }
}
macro_rules! sequence {
    ($trait:ident,$method:ident) => {
        impl<S: Sink> $trait for Compound<'_, S> {
            type Ok = ();
            type Error = Error;
            fn $method<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
                self.element(value)
            }
            fn end(self) -> Result<(), Error> {
                self.finish()
            }
        }
    };
}
sequence!(SerializeSeq, serialize_element);
sequence!(SerializeTuple, serialize_element);
sequence!(SerializeTupleStruct, serialize_field);
sequence!(SerializeTupleVariant, serialize_field);
macro_rules! structure {
    ($trait:ident) => {
        impl<S: Sink> $trait for Compound<'_, S> {
            type Ok = ();
            type Error = Error;
            fn serialize_field<T: Serialize + ?Sized>(
                &mut self,
                key: &'static str,
                value: &T,
            ) -> Result<(), Error> {
                self.field(key, value)
            }
            fn end(self) -> Result<(), Error> {
                self.finish()
            }
        }
    };
}
structure!(SerializeStruct);
structure!(SerializeStructVariant);
impl<S: Sink> SerializeMap for Compound<'_, S> {
    type Ok = ();
    type Error = Error;
    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), Error> {
        if self.key || self.left == 0 {
            return Err(Error::Count);
        }
        key.serialize(&mut *self.encoder)?;
        self.key = true;
        Ok(())
    }
    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), Error> {
        if !self.key {
            return Err(Error::Count);
        }
        self.key = false;
        self.element(value)
    }
    fn end(self) -> Result<(), Error> {
        self.finish()
    }
}
macro_rules! integer {
    ($method:ident,$ty:ty,$target:ident) => {
        fn $method(self, n: $ty) -> Result<(), Error> {
            self.$target(n.into())
        }
    };
}
impl<'a, S: Sink> Serializer for &'a mut Encoder<S> {
    type Ok = ();
    type Error = Error;
    type SerializeSeq = Compound<'a, S>;
    type SerializeTuple = Compound<'a, S>;
    type SerializeTupleStruct = Compound<'a, S>;
    type SerializeTupleVariant = Compound<'a, S>;
    type SerializeMap = Compound<'a, S>;
    type SerializeStruct = Compound<'a, S>;
    type SerializeStructVariant = Compound<'a, S>;
    fn serialize_bool(self, b: bool) -> Result<(), Error> {
        self.byte(if b { 2 } else { 1 });
        Ok(())
    }
    integer!(serialize_i8, i8, serialize_i64);
    integer!(serialize_i16, i16, serialize_i64);
    integer!(serialize_i32, i32, serialize_i64);
    fn serialize_i64(self, n: i64) -> Result<(), Error> {
        self.number(if n < 0 { 4 } else { 3 }, n.unsigned_abs());
        Ok(())
    }
    fn serialize_i128(self, n: i128) -> Result<(), Error> {
        self.serialize_i64(n.try_into().map_err(|_| Error::Range)?)
    }
    integer!(serialize_u8, u8, serialize_u64);
    integer!(serialize_u16, u16, serialize_u64);
    integer!(serialize_u32, u32, serialize_u64);
    fn serialize_u64(self, n: u64) -> Result<(), Error> {
        self.number(3, n);
        Ok(())
    }
    fn serialize_u128(self, n: u128) -> Result<(), Error> {
        self.serialize_u64(n.try_into().map_err(|_| Error::Range)?)
    }
    fn serialize_f32(self, _: f32) -> Result<(), Error> {
        Err(Error::Float)
    }
    fn serialize_f64(self, _: f64) -> Result<(), Error> {
        Err(Error::Float)
    }
    fn serialize_char(self, c: char) -> Result<(), Error> {
        self.serialize_str(c.encode_utf8(&mut [0; 4]))
    }
    fn serialize_str(self, s: &str) -> Result<(), Error> {
        self.bytes(5, s.as_bytes());
        Ok(())
    }
    fn serialize_bytes(self, b: &[u8]) -> Result<(), Error> {
        self.bytes(8, b);
        Ok(())
    }
    fn serialize_none(self) -> Result<(), Error> {
        self.byte(10);
        Ok(())
    }
    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), Error> {
        self.byte(11);
        value.serialize(self)
    }
    fn serialize_unit(self) -> Result<(), Error> {
        self.byte(0);
        Ok(())
    }
    fn serialize_unit_struct(self, _: &'static str) -> Result<(), Error> {
        self.serialize_unit()
    }
    fn serialize_unit_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
    ) -> Result<(), Error> {
        self.variant(12, variant);
        Ok(())
    }
    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        value.serialize(self)
    }
    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), Error> {
        self.variant(13, variant);
        value.serialize(self)
    }
    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Error> {
        Ok(self.compound(6, len.ok_or(Error::UnknownLength)?))
    }
    fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Error> {
        Ok(self.compound(6, len))
    }
    fn serialize_tuple_struct(
        self,
        _: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Error> {
        Ok(self.compound(6, len))
    }
    fn serialize_tuple_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Error> {
        self.variant(14, variant);
        Ok(self.compound(6, len))
    }
    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Error> {
        Ok(self.compound(9, len.ok_or(Error::UnknownLength)?))
    }
    fn serialize_struct(self, _: &'static str, len: usize) -> Result<Self::SerializeStruct, Error> {
        Ok(self.compound(7, len))
    }
    fn serialize_struct_variant(
        self,
        _: &'static str,
        _: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Error> {
        self.variant(15, variant);
        Ok(self.compound(7, len))
    }
    fn is_human_readable(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Serialize)]
    enum Variant {
        No,
        Item(u64),
        Pair(u64, u64),
        Window { from: u64, until: u64 },
    }
    #[derive(Serialize)]
    struct Vector<'a> {
        z: u64,
        a: &'a str,
        raw: Raw<'a>,
        negatives: [i64; 2],
        options: [Option<u8>; 2],
        variants: [Variant; 4],
        map: alloc::collections::BTreeMap<&'a str, u64>,
    }
    #[test]
    fn independent_frame4_vector_covers_raw_bytes_options_variants_and_order() {
        let value = Vector {
            z: 42,
            a: "λ",
            raw: Raw(&[0, 255]),
            negatives: [-1, i64::MIN],
            options: [None, Some(3)],
            variants: [
                Variant::No,
                Variant::Item(7),
                Variant::Pair(1, 2),
                Variant::Window { from: 0, until: 9 },
            ],
            map: [("z", 2), ("a", 1)].into(),
        };
        assert_eq!(bytes(&value).len(), 384);
        assert_eq!(
            crate::AuthorityId::from_bytes(fingerprint(b"vector/v4", &value).unwrap().0).hex(),
            "b03820429b5dcf9a243339c3c8354dbd8ea424a123642492cb64f1455c7bbae5"
        );
    }
    #[test]
    fn raw_body_has_one_length_frame_not_one_integer_frame_per_byte() {
        let body = alloc::vec![255;64*1024];
        assert_eq!(bytes(&Raw(&body)).len(), body.len() + 9);
    }
    #[test]
    fn unknown_lengths_floats_and_misdeclared_counts_are_not_silent_encodings() {
        assert!(fingerprint(b"test", &1.5_f64).is_err());
        let mut e = Encoder(alloc::vec::Vec::new());
        assert!(e.serialize_seq(None).is_err());
        let seq = e.serialize_seq(Some(1)).unwrap();
        assert!(SerializeSeq::end(seq).is_err());
        let mut seq = e.serialize_seq(Some(0)).unwrap();
        assert!(SerializeSeq::serialize_element(&mut seq, &1_u8).is_err());
    }
}
