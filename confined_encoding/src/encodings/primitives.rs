// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

//! Taking implementation of little-endian integer encoding
use std::io;

use amplify::num::apfloat::{ieee, Float};
use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
use half::bf16;

use crate::{ConfinedDecode, ConfinedEncode, Error};

impl ConfinedEncode for () {
    fn confined_encode(&self, _: &mut impl io::Write) -> Result<(), Error> {
        Ok(())
    }
}

impl ConfinedDecode for () {
    fn confined_decode(_: &mut impl io::Read) -> Result<Self, Error> { Ok(()) }
}

impl ConfinedEncode for bool {
    fn confined_encode(&self, e: &mut impl io::Write) -> Result<(), Error> {
        (*self as u8).confined_encode(e)
    }
}

impl ConfinedDecode for bool {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        match u8::confined_decode(d)? {
            0 => Ok(false),
            1 => Ok(true),
            v => Err(Error::ValueOutOfRange("boolean", 0..1, v as u128)),
        }
    }
}

macro_rules! encoding_int {
    ($ty:ty, $l:literal) => {
        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                e: &mut impl io::Write,
            ) -> Result<(), Error> {
                e.write_all(&self.to_le_bytes())?;
                Ok(())
            }
        }

        impl ConfinedDecode for $ty {
            fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
                let mut buf = [0u8; $l];
                d.read_exact(&mut buf)?;
                Ok(Self::from_le_bytes(buf))
            }
        }
    };
}

encoding_int!(u8, 1);
encoding_int!(u16, 2);
encoding_int!(u24, 3);
encoding_int!(u32, 4);
encoding_int!(u64, 8);
encoding_int!(u128, 16);
encoding_int!(u256, 32);
encoding_int!(u512, 64);
encoding_int!(u1024, 128);

encoding_int!(i8, 1);
encoding_int!(i16, 2);
// TODO: Add i24 encoding once the type will be in amplify::num
//encoding_int!(i24, 3);
encoding_int!(i32, 4);
encoding_int!(i64, 8);
encoding_int!(i128, 16);
encoding_int!(i256, 32);
encoding_int!(i512, 64);
encoding_int!(i1024, 128);

impl ConfinedEncode for bf16 {
    fn confined_encode(&self, e: &mut impl io::Write) -> Result<(), Error> {
        self.to_bits().confined_encode(e)
    }
}

impl ConfinedDecode for bf16 {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        Ok(bf16::from_bits(u16::confined_decode(d)?))
    }
}

macro_rules! encoding_float {
    ($ty:ty, $l:literal) => {
        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                e: &mut impl io::Write,
            ) -> Result<(), Error> {
                let bytes = self.to_bits().to_le_bytes(); // this gives 32-byte slice
                e.write_all(&bytes[..2])?;
                Ok(())
            }
        }

        impl ConfinedDecode for $ty {
            fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
                let mut buf = [0u8; 32];
                d.read_exact(&mut buf[..$l])?;
                // Constructing inner representation
                let inner = u256::from_le_bytes(buf);
                Ok(Self::from_bits(inner))
            }
        }
    };
}

encoding_float!(ieee::Half, 2);
encoding_float!(ieee::Single, 4);
encoding_float!(ieee::Double, 8);
encoding_float!(ieee::X87DoubleExtended, 10);
encoding_float!(ieee::Quad, 16);
encoding_float!(ieee::Oct, 32);

#[cfg(test)]
pub mod test {
    use chrono::{NaiveDateTime, Utc};
    use confined_encoding_test::test_encoding_roundtrip;

    use super::*;
    use crate::confined_deserialize;

    #[test]
    fn test_u_encoding() {
        test_encoding_roundtrip(&0_u8, [0]).unwrap();
        test_encoding_roundtrip(&1_u8, [1]).unwrap();
        test_encoding_roundtrip(&0x10_u8, [0x10]).unwrap();
        test_encoding_roundtrip(&0xFE_u8, [0xFE]).unwrap();
        test_encoding_roundtrip(&0xFF_u8, [0xFF]).unwrap();
        test_encoding_roundtrip(&54_u16, [54, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_u16, [0xa6, 0x45]).unwrap();
        test_encoding_roundtrip(&54_usize, [54, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_usize, [0xa6, 0x45]).unwrap();
        test_encoding_roundtrip(&54_u32, [54, 0, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_u32, [0xa6, 0x45, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x56fe45a6_u32, [0xa6, 0x45, 0xfe, 0x56])
            .unwrap();
        test_encoding_roundtrip(&54_u64, [54, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_u64, [0xa6, 0x45, 0, 0, 0, 0, 0, 0])
            .unwrap();
        test_encoding_roundtrip(&0x56fe45a6_u64, [
            0xa6, 0x45, 0xfe, 0x56, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0xcafedead56fe45a6_u64, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0xca,
        ])
        .unwrap();
        test_encoding_roundtrip(&54_u128, [
            54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x45a6_u128, [
            0xa6, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x56fe45a6_u128, [
            0xa6, 0x45, 0xfe, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0xcafedead56fe45a6_u128, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0xca, 0, 0, 0, 0, 0, 0,
            0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0xbadefeed65671331cafedead56fe45a6_u128, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0xca, 0x31, 0x13, 0x67,
            0x65, 0xed, 0xfe, 0xde, 0xba,
        ])
        .unwrap();
    }

    #[test]
    fn test_i_encoding() {
        test_encoding_roundtrip(&0_i8, [0]).unwrap();
        test_encoding_roundtrip(&1_i8, [1]).unwrap();
        test_encoding_roundtrip(&0x10_i8, [0x10]).unwrap();
        test_encoding_roundtrip(&0x7E_i8, [0x7E]).unwrap();
        test_encoding_roundtrip(&0x7F_i8, [0x7F]).unwrap();
        test_encoding_roundtrip(&-0x7F_i8, [0x81]).unwrap();
        test_encoding_roundtrip(&54_i16, [54, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_i16, [0xa6, 0x45]).unwrap();
        test_encoding_roundtrip(&54_i32, [54, 0, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_i32, [0xa6, 0x45, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x56fe45a6_i32, [0xa6, 0x45, 0xfe, 0x56])
            .unwrap();
        test_encoding_roundtrip(&54_i64, [54, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_i64, [0xa6, 0x45, 0, 0, 0, 0, 0, 0])
            .unwrap();
        test_encoding_roundtrip(&0x56fe45a6_i64, [
            0xa6, 0x45, 0xfe, 0x56, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x7afedead56fe45a6_i64, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0x7a,
        ])
        .unwrap();
        test_encoding_roundtrip(&54_i128, [
            54, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x45a6_i128, [
            0xa6, 0x45, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x56fe45a6_i128, [
            0xa6, 0x45, 0xfe, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0xcafedead56fe45a6_i128, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0xca, 0, 0, 0, 0, 0, 0,
            0, 0,
        ])
        .unwrap();
        test_encoding_roundtrip(&0x1adefeed65671331cafedead56fe45a6_i128, [
            0xa6, 0x45, 0xfe, 0x56, 0xad, 0xde, 0xfe, 0xca, 0x31, 0x13, 0x67,
            0x65, 0xed, 0xfe, 0xde, 0x1a,
        ])
        .unwrap();
    }

    #[test]
    fn test_bool_encoding() {
        test_encoding_roundtrip(&true, [0x01]).unwrap();
        test_encoding_roundtrip(&false, [0x00]).unwrap();

        assert_eq!(
            bool::confined_decode(&[0x20][..]),
            Err(Error::ValueOutOfRange("boolean", 0..1, 0x20))
        );
    }

    #[test]
    fn test_large_uints() {
        test_encoding_roundtrip(&u256::from(0x_dead_cafe_4bad_beef_u64), [
            0xef, 0xbe, 0xad, 0x4b, 0xfe, 0xca, 0xad, 0xde, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();

        test_encoding_roundtrip(&u512::from(0x_dead_cafe_4bad_beef_u64), [
            0xef, 0xbe, 0xad, 0x4b, 0xfe, 0xca, 0xad, 0xde, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();

        test_encoding_roundtrip(&u1024::from(0x_dead_cafe_4bad_beef_u64), [
            0xef, 0xbe, 0xad, 0x4b, 0xfe, 0xca, 0xad, 0xde, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ])
        .unwrap();
    }
}
