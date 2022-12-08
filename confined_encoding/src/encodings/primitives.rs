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

//! Taking implementation of little-endian integer encoding
use std::io;

use amplify::ascii::AsciiChar;
use amplify::num::apfloat::{ieee, Float};
use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
use half::bf16;

use crate::schema::{self, Ty};
use crate::{
    variants, ConfinedDecode, ConfinedEncode, ConfinedType, ConfinedWrite,
    Error,
};

impl ConfinedType for () {
    const TYPE_NAME: &'static str = "()";

    fn confined_type() -> Ty { Ty::unit() }
}

impl ConfinedEncode for () {
    fn confined_encode(&self, _: &mut impl ConfinedWrite) -> Result<(), Error> {
        Ok(())
    }
}

impl ConfinedDecode for () {
    fn confined_decode(_: &mut impl io::Read) -> Result<Self, Error> { Ok(()) }
}

impl ConfinedType for bool {
    const TYPE_NAME: &'static str = "Bool";

    fn confined_type() -> Ty {
        Ty::enumerate(variants! {
            "False" => 0,
            "True" => 1
        })
    }
}

impl ConfinedEncode for bool {
    fn confined_encode(&self, e: &mut impl ConfinedWrite) -> Result<(), Error> {
        e.write_enum(*self as u8, Self::confined_type())
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

impl ConfinedType for AsciiChar {
    const TYPE_NAME: &'static str = "AsciiChar";

    fn confined_type() -> Ty { Ty::char() }
}

impl ConfinedEncode for AsciiChar {
    fn confined_encode(&self, e: &mut impl ConfinedWrite) -> Result<(), Error> {
        e.write_u8(*self as u8)
    }
}

impl ConfinedDecode for AsciiChar {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let c = u8::confined_decode(d)?;
        AsciiChar::from_ascii(c).map_err(|_| Error::NonAsciiChar(c))
    }
}

macro_rules! encoding_int {
    ($ty:ty, $l:literal, $prim:ident, $write:ident) => {
        impl ConfinedType for $ty {
            const TYPE_NAME: &'static str = stringify!($prim);

            fn confined_type() -> Ty { Ty::Primitive(schema::$prim) }
        }

        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                e: &mut impl ConfinedWrite,
            ) -> Result<(), Error> {
                e.$write(*self)
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

encoding_int!(u8, 1, U8, write_u8);
encoding_int!(u16, 2, U16, write_u16);
encoding_int!(u24, 3, U24, write_u24);
encoding_int!(u32, 4, U32, write_u32);
encoding_int!(u64, 8, U64, write_u64);
encoding_int!(u128, 16, U128, write_u128);
encoding_int!(u256, 32, U256, write_u256);
encoding_int!(u512, 64, U512, write_u512);
encoding_int!(u1024, 128, U1024, write_u1024);

encoding_int!(i8, 1, I8, write_i8);
encoding_int!(i16, 2, I16, write_i16);
// TODO: Add i24 encoding once the type will be in amplify::num
//encoding_int!(i24, 3, I24, write_i24);
encoding_int!(i32, 4, I32, write_i32);
encoding_int!(i64, 8, I64, write_i64);
encoding_int!(i128, 16, I128, write_i128);
encoding_int!(i256, 32, I256, write_i256);
encoding_int!(i512, 64, I512, write_i512);
encoding_int!(i1024, 128, I1024, write_i1024);

impl ConfinedType for bf16 {
    const TYPE_NAME: &'static str = "F16b";

    fn confined_type() -> Ty { Ty::f16b() }
}

impl ConfinedEncode for bf16 {
    fn confined_encode(&self, e: &mut impl ConfinedWrite) -> Result<(), Error> {
        e.write_f16b(*self)
    }
}

impl ConfinedDecode for bf16 {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        Ok(bf16::from_bits(u16::confined_decode(d)?))
    }
}

macro_rules! encoding_float {
    ($ty:ty, $l:literal, $prim:ident, $write:ident) => {
        impl ConfinedType for $ty {
            const TYPE_NAME: &'static str = stringify!($prim);

            fn confined_type() -> Ty { Ty::Primitive(schema::$prim) }
        }

        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                e: &mut impl ConfinedWrite,
            ) -> Result<(), Error> {
                e.$write(*self)
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

encoding_float!(ieee::Half, 2, F16, write_f16);
encoding_float!(ieee::Single, 4, F32, write_f32);
encoding_float!(ieee::Double, 8, F64, write_f64);
encoding_float!(ieee::X87DoubleExtended, 10, F80, write_f80);
encoding_float!(ieee::Quad, 16, F128, write_f128);
encoding_float!(ieee::Oct, 32, F256, write_f256);

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
