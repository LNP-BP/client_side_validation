// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
//
// Written in 2019-2022 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::collections::BTreeSet;
use std::fmt::Debug;
use std::hash::Hash;
use std::io;

use amplify::confinement::{
    Confined, SmallOrdMap, SmallOrdSet, SmallVec, TinyString, TinyVec,
};

use crate::schema::{Sizing, Ty};
use crate::{
    ConfinedDecode, ConfinedEncode, ConfinedType, ConfinedWrite, Error,
};

impl<T> ConfinedType for Option<T>
where
    T: ConfinedType,
{
    const TYPE_NAME: &'static str = stringify!(T::TYPE_NAME, "?");

    fn confined_type() -> Ty { Ty::option(T::confined_type()) }
}

impl<T> ConfinedEncode for Option<T>
where
    T: ConfinedEncode,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_option(self.as_ref())
    }
}

impl<T> ConfinedDecode for Option<T>
where
    T: ConfinedDecode,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u8::confined_decode(d)?;
        match len {
            0 => Ok(None),
            1 => Ok(Some(T::confined_decode(d)?)),
            invalid => Err(Error::DataIntegrityError(format!(
                "invalid optional value `{}`",
                invalid
            ))),
        }
    }
}

impl ConfinedType for TinyString {
    const TYPE_NAME: &'static str = "String";

    fn confined_type() -> Ty { Ty::Unicode(Sizing::U8) }
}

impl ConfinedEncode for TinyString {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_string(self)
    }
}

impl ConfinedDecode for TinyString {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u8::confined_decode(d)?;
        let mut data = Vec::<u8>::with_capacity(len as usize);
        d.read_exact(&mut data)?;
        let s = String::from_utf8(data)?;
        Ok(
            TinyString::try_from(s)
                .expect("amplify::TinyString type is broken"),
        )
    }
}

impl<T> ConfinedType for TinyVec<T>
where
    T: ConfinedType,
{
    const TYPE_NAME: &'static str = stringify!("[", T::TYPE_NAME, "]");

    fn confined_type() -> Ty { Ty::list(T::confined_type(), Sizing::U8) }
}

impl<T> ConfinedEncode for TinyVec<T>
where
    T: ConfinedEncode,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_list(self)
    }
}

impl<T> ConfinedDecode for TinyVec<T>
where
    T: ConfinedDecode,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u8::confined_decode(d)?;
        let mut data = TinyVec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::confined_decode(d)?)
                .expect("TinyVec must have up to 255 items");
        }
        Ok(data)
    }
}

impl<T> ConfinedType for SmallVec<T>
where
    T: ConfinedType,
{
    const TYPE_NAME: &'static str = stringify!("[", T::TYPE_NAME, "]");

    fn confined_type() -> Ty { Ty::list(T::confined_type(), Sizing::U16) }
}

impl<T> ConfinedEncode for SmallVec<T>
where
    T: ConfinedEncode,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_list(self)
    }
}

impl<T> ConfinedDecode for SmallVec<T>
where
    T: ConfinedDecode,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u16::confined_decode(d)?;
        let mut data = SmallVec::<T>::with_capacity(len as usize);
        for _ in 0..len {
            data.push(T::confined_decode(d)?)
                .expect("SmallVec must have up to 2^16-1 items");
        }
        Ok(data)
    }
}

impl<T> ConfinedType for SmallOrdSet<T>
where
    T: ConfinedType + Hash + Ord,
{
    const TYPE_NAME: &'static str = stringify!("{", T::TYPE_NAME, "}");

    fn confined_type() -> Ty { Ty::set(T::confined_type(), Sizing::U16) }
}

/// Strict encoding for a unique value collection represented by a rust
/// `BTreeSet` type is performed in the same way as `Vec` encoding.
/// NB: Array members must are ordered with the sort operation, so type
/// `T` must implement `Ord` trait in such a way that it produces
/// deterministically-sorted result
impl<T> ConfinedEncode for SmallOrdSet<T>
where
    T: ConfinedEncode + Hash + Ord,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_set(self)
    }
}

/// Strict decoding of a unique value collection represented by a rust
/// `BTreeSet` type is performed alike `Vec` decoding with the only
/// exception: if the repeated value met a [Error::RepeatedValue] is
/// returned.
impl<T> ConfinedDecode for SmallOrdSet<T>
where
    T: ConfinedDecode + Hash + Ord + Debug,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u16::confined_decode(d)?;
        let mut data = SmallOrdSet::<T>::new();
        for _ in 0..len {
            let val = T::confined_decode(d)?;
            if let Some(max) = data.iter().max() {
                if max > &val {
                    return Err(Error::BrokenOrder(
                        format!("{:?}", val),
                        format!("{:?}", max),
                    ));
                }
            }
            if data.contains(&val) {
                return Err(Error::RepeatedValue(format!("{:?}", val)));
            }
            data.push(val)
                .expect("SmallOrdSet must have up to 2^16-1 items");
        }
        Ok(data)
    }
}

impl<T, const MIN: usize> ConfinedType
    for Confined<BTreeSet<T>, MIN, { u8::MAX as usize }>
where
    T: ConfinedType + Hash + Ord,
{
    const TYPE_NAME: &'static str = stringify!("{", T::TYPE_NAME, "}");

    fn confined_type() -> Ty {
        Ty::set(T::confined_type(), Sizing::U8_NONEMPTY)
    }
}

/// Strict encoding for a unique value collection represented by a rust
/// `BTreeSet` type is performed in the same way as `Vec` encoding.
/// NB: Array members must are ordered with the sort operation, so type
/// `T` must implement `Ord` trait in such a way that it produces
/// deterministically-sorted result
impl<T, const MIN: usize> ConfinedEncode
    for Confined<BTreeSet<T>, MIN, { u8::MAX as usize }>
where
    T: ConfinedEncode + Hash + Ord,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_set(self)
    }
}

/// Strict decoding of a unique value collection represented by a rust
/// `BTreeSet` type is performed alike `Vec` decoding with the only
/// exception: if the repeated value met a [Error::RepeatedValue] is
/// returned.
impl<T, const MIN: usize> ConfinedDecode
    for Confined<BTreeSet<T>, MIN, { u8::MAX as usize }>
where
    T: ConfinedDecode + Hash + Ord + Debug,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u8::confined_decode(d)?;
        let mut data = BTreeSet::new();
        for _ in 0..len {
            let val = T::confined_decode(d)?;
            if let Some(max) = data.iter().max() {
                if max > &val {
                    return Err(Error::BrokenOrder(
                        format!("{:?}", val),
                        format!("{:?}", max),
                    ));
                }
            }
            if data.contains(&val) {
                return Err(Error::RepeatedValue(format!("{:?}", val)));
            }
            data.insert(val);
        }
        let data = Confined::try_from(data)
            .expect("collection must have up to 2^8-1 items");
        Ok(data)
    }
}

impl<K, V> ConfinedType for SmallOrdMap<K, V>
where
    K: ConfinedType + Ord + Hash,
    V: ConfinedType,
{
    const TYPE_NAME: &'static str = stringify!("{", T::TYPE_NAME, "}");

    fn confined_type() -> Ty {
        Ty::map(
            K::confined_type().try_into_ty().expect("invalid key type"),
            V::confined_type(),
            Sizing::U16,
        )
    }
}

impl<K, V> ConfinedEncode for SmallOrdMap<K, V>
where
    K: ConfinedEncode + Ord + Hash,
    V: ConfinedEncode,
{
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_map(self)
    }
}

impl<K, V> ConfinedDecode for SmallOrdMap<K, V>
where
    K: ConfinedDecode + Ord + Hash + Debug,
    V: ConfinedDecode,
{
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let len = u16::confined_decode(d)?;
        let mut map = SmallOrdMap::<K, V>::new();
        for _ in 0..len {
            let key = K::confined_decode(d)?;
            let val = V::confined_decode(d)?;
            if let Some(max) = map.keys().max() {
                if max > &key {
                    return Err(Error::BrokenOrder(
                        format!("{:?}", key),
                        format!("{:?}", max),
                    ));
                }
            }
            if map.contains_key(&key) {
                return Err(Error::RepeatedValue(format!("{:?}", key)));
            }
            map.insert(key, val)
                .expect("SmallOrdMap must have up to 2^16-1 items");
        }
        Ok(map)
    }
}

#[cfg(test)]
pub mod test {
    use super::*;

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::None` value MUST
    /// encode as two zero bytes and it MUST be possible to decode optional
    /// of any type from two zero bytes which MUST result in `Option::None`
    /// value.
    #[test]
    fn test_option_encode_none() {
        let o1: Option<u8> = None;
        let o2: Option<u64> = None;

        let two_zero_bytes = small_vec![0u8];

        assert_eq!(o1.confined_serialize_64kb().unwrap(), two_zero_bytes);
        assert_eq!(o2.confined_serialize_64kb().unwrap(), two_zero_bytes);

        assert_eq!(
            Option::<u8>::confined_deserialize(&two_zero_bytes).unwrap(),
            None
        );
        assert_eq!(
            Option::<u64>::confined_deserialize(&two_zero_bytes).unwrap(),
            None
        );
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// `Option<T>` of any type T, which are set to `Option::Some<T>` value MUST
    /// encode as a `Vec<T>` structure containing a single item equal to the
    /// `Option::unwrap()` value.
    #[test]
    fn test_option_encode_some() {
        let o1: Option<u8> = Some(0);
        let o2: Option<u8> = Some(13);
        let o3: Option<u8> = Some(0xFF);
        let o4: Option<u64> = Some(13);
        let o5: Option<u64> = Some(0x1FF);
        let o6: Option<u64> = Some(0xFFFFFFFFFFFFFFFF);
        let o7: Option<u32> = Some(13);

        let byte_0 = small_vec![1u8, 0u8];
        let byte_13 = small_vec![1u8, 13u8];
        let byte_255 = small_vec![1u8, 0xFFu8];
        let word_13 = small_vec![1u8, 13u8, 0u8, 0u8, 0u8];
        let qword_13 = small_vec![1u8, 13u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let qword_256 =
            small_vec![1u8, 0xFFu8, 0x01u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8];
        let qword_max = small_vec![
            1u8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8, 0xFFu8,
            0xFFu8,
        ];

        assert_eq!(o1.confined_serialize_64kb().unwrap(), byte_0);
        assert_eq!(o2.confined_serialize_64kb().unwrap(), byte_13);
        assert_eq!(o3.confined_serialize_64kb().unwrap(), byte_255);
        assert_eq!(o4.confined_serialize_64kb().unwrap(), qword_13);
        assert_eq!(o5.confined_serialize_64kb().unwrap(), qword_256);
        assert_eq!(o6.confined_serialize_64kb().unwrap(), qword_max);
        assert_eq!(o7.confined_serialize_64kb().unwrap(), word_13);

        assert_eq!(
            Option::<u8>::confined_deserialize(&byte_0).unwrap(),
            Some(0)
        );
        assert_eq!(
            Option::<u8>::confined_deserialize(&byte_13).unwrap(),
            Some(13)
        );
        assert_eq!(
            Option::<u8>::confined_deserialize(&byte_255).unwrap(),
            Some(0xFF)
        );
        assert_eq!(
            Option::<u64>::confined_deserialize(&qword_13).unwrap(),
            Some(13)
        );
        assert_eq!(
            Option::<u64>::confined_deserialize(&qword_256).unwrap(),
            Some(0x1FF)
        );
        assert_eq!(
            Option::<u64>::confined_deserialize(&qword_max).unwrap(),
            Some(0xFFFFFFFFFFFFFFFF)
        );
        assert_eq!(
            Option::<u32>::confined_deserialize(&word_13).unwrap(),
            Some(13)
        );
    }

    /// Test trying decoding of non-zero and non-single item vector structures,
    /// which MUST fail with a specific error.
    #[test]
    fn test_option_decode_vec() {
        assert!(Option::<u8>::confined_deserialize(&tiny_vec![
            2u8, 0u8, 0u8, 0u8
        ])
        .err()
        .is_some());
        assert!(Option::<u8>::confined_deserialize(&tiny_vec![
            3u8, 0u8, 0u8, 0u8
        ])
        .err()
        .is_some());
        assert!(Option::<u8>::confined_deserialize(&tiny_vec![
            0xFFu8, 0u8, 0u8, 0u8
        ])
        .err()
        .is_some());
    }

    /// Test for checking the following rule from LNPBP-5:
    ///
    /// Array of any commitment-serializable type T MUST contain strictly less
    /// than `0x10000` items and must encode as 16-bit little-endian value
    /// corresponding to the number of items followed by a direct encoding
    /// of each of the items.
    #[test]
    fn test_vec_encode() {
        let v1 = tiny_vec![0u8, 13, 0xFF];
        let v2 = tiny_vec![13u8];
        let v3 = tiny_vec![0u64, 13, 13, 0x1FF, 0xFFFFFFFFFFFFFFFF];
        let v4 = SmallVec::try_from_iter(
            (0u16..0x1FFF).map(|item| (item % 0xFF) as u8),
        )
        .unwrap();

        let s1 = tiny_vec![3u8, 0u8, 13u8, 0xFFu8];
        let s2 = tiny_vec![1u8, 13u8];
        let s3 = tiny_vec![
            5u8, 0, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0,
            0, 0, 0, 0, 0xFF, 1, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF,
        ];

        assert_eq!(v1.confined_serialize().unwrap(), s1);
        assert_eq!(v2.confined_serialize().unwrap(), s2);
        assert_eq!(v3.confined_serialize().unwrap(), s3);
        v4.confined_serialize_64kb().unwrap();

        assert_eq!(TinyVec::<u8>::confined_deserialize(&s1).unwrap(), v1);
        assert_eq!(TinyVec::<u8>::confined_deserialize(&s2).unwrap(), v2);
        assert_eq!(TinyVec::<u64>::confined_deserialize(&s3).unwrap(), v3);
    }
}
