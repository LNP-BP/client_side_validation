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

use amplify::ascii::AsciiChar;
use amplify::num::apfloat::ieee;
use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
use half::bf16;

use crate::schema::{self, Ty};
use crate::{
    variants, ConfinedDecode, ConfinedEncode, ConfinedRead, ConfinedType,
    ConfinedWrite, Error,
};

impl ConfinedType for () {
    const TYPE_NAME: &'static str = "()";

    fn confined_type() -> Ty { Ty::unit() }
}

impl ConfinedEncode for () {
    fn confined_encode(&self, _: impl ConfinedWrite) -> Result<(), Error> {
        Ok(())
    }
}

impl ConfinedDecode for () {
    fn confined_decode(_: impl ConfinedRead) -> Result<Self, Error> { Ok(()) }
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
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_enum(*self as u8, Self::confined_type())
    }
}

impl ConfinedDecode for bool {
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        Ok(match d.read_enum(Self::TYPE_NAME, Self::confined_type())? {
            0 => false,
            1 => true,
            _ => unreachable!("guaranteed by type system"),
        })
    }
}

impl ConfinedType for AsciiChar {
    const TYPE_NAME: &'static str = "AsciiChar";

    fn confined_type() -> Ty { Ty::char() }
}

impl ConfinedEncode for AsciiChar {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_u8(*self as u8)
    }
}

impl ConfinedDecode for AsciiChar {
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        let c = d.read_u8()?;
        AsciiChar::from_ascii(c).map_err(|_| Error::NonAsciiChar(c))
    }
}

macro_rules! encoding_int {
    ($ty:ty, $prim:ident, $read:ident, $write:ident) => {
        impl ConfinedType for $ty {
            const TYPE_NAME: &'static str = stringify!($prim);

            fn confined_type() -> Ty { Ty::Primitive(schema::$prim) }
        }

        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                mut e: impl ConfinedWrite,
            ) -> Result<(), Error> {
                e.$write(*self)
            }
        }

        impl ConfinedDecode for $ty {
            fn confined_decode(
                mut d: impl ConfinedRead,
            ) -> Result<Self, Error> {
                d.$read()
            }
        }
    };
}

encoding_int!(u8, U8, read_u8, write_u8);
encoding_int!(u16, U16, read_u16, write_u16);
encoding_int!(u24, U24, read_u24, write_u24);
encoding_int!(u32, U32, read_u32, write_u32);
encoding_int!(u64, U64, read_u64, write_u64);
encoding_int!(u128, U128, read_u128, write_u128);
encoding_int!(u256, U256, read_u256, write_u256);
encoding_int!(u512, U512, read_u512, write_u512);
encoding_int!(u1024, U1024, read_u1024, write_u1024);

encoding_int!(i8, I8, read_i8, write_i8);
encoding_int!(i16, I16, read_i16, write_i16);
// TODO: Add i24 encoding once the type will be in amplify::num
//encoding_int!(i24, I24, read_i24, write_i24);
encoding_int!(i32, I32, read_i32, write_i32);
encoding_int!(i64, I64, read_i64, write_i64);
encoding_int!(i128, I128, read_i128, write_i128);
encoding_int!(i256, I256, read_i256, write_i256);
encoding_int!(i512, I512, read_i512, write_i512);
encoding_int!(i1024, I1024, read_i1024, write_i1024);

impl ConfinedType for bf16 {
    const TYPE_NAME: &'static str = "F16b";

    fn confined_type() -> Ty { Ty::f16b() }
}

impl ConfinedEncode for bf16 {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_f16b(*self)
    }
}

impl ConfinedDecode for bf16 {
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        d.read_f16b()
    }
}

macro_rules! encoding_float {
    ($ty:ty, $prim:ident, $read:ident, $write:ident) => {
        impl ConfinedType for $ty {
            const TYPE_NAME: &'static str = stringify!($prim);

            fn confined_type() -> Ty { Ty::Primitive(schema::$prim) }
        }

        impl ConfinedEncode for $ty {
            fn confined_encode(
                &self,
                mut e: impl ConfinedWrite,
            ) -> Result<(), Error> {
                e.$write(*self)
            }
        }

        impl ConfinedDecode for $ty {
            fn confined_decode(
                mut d: impl ConfinedRead,
            ) -> Result<Self, Error> {
                d.$read()
            }
        }
    };
}

encoding_float!(ieee::Half, F16, read_f16, write_f16);
encoding_float!(ieee::Single, F32, read_f32, write_f32);
encoding_float!(ieee::Double, F64, read_f64, write_f64);
encoding_float!(ieee::X87DoubleExtended, F80, read_f80, write_f80);
encoding_float!(ieee::Quad, F128, read_f128, write_f128);
encoding_float!(ieee::Oct, F256, read_f256, write_f256);

#[cfg(test)]
pub mod test {
    use amplify::confinement::Confined;
    use confined_encoding_test::test_encoding_roundtrip;

    use super::*;
    use crate::schema::Variant;

    #[test]
    fn test_u_encoding() {
        test_encoding_roundtrip(&0_u8, [0]).unwrap();
        test_encoding_roundtrip(&1_u8, [1]).unwrap();
        test_encoding_roundtrip(&0x10_u8, [0x10]).unwrap();
        test_encoding_roundtrip(&0xFE_u8, [0xFE]).unwrap();
        test_encoding_roundtrip(&0xFF_u8, [0xFF]).unwrap();
        test_encoding_roundtrip(&54_u16, [54, 0]).unwrap();
        test_encoding_roundtrip(&0x45a6_u16, [0xa6, 0x45]).unwrap();
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
            bool::confined_deserialize(&tiny_vec![0x20]).unwrap_err(),
            Error::EnumValueNotKnown(
                "Bool",
                32,
                Confined::try_from(
                    bset! { Variant::new("False", 0), Variant::new("True", 1)}
                )
                .unwrap()
            )
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
