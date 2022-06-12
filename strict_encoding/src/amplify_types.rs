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

use std::io;

use amplify::flags::FlagVec;
#[cfg(feature = "float")]
use amplify::num::apfloat::{ieee, Float};
use amplify::num::{i1024, i256, i512, u1024, u256, u512};
#[cfg(feature = "float")]
use half::bf16;

use crate::{Error, StrictDecode, StrictEncode};

impl StrictEncode for FlagVec {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.shrunk().as_inner().strict_encode(e)
    }
}

impl StrictDecode for FlagVec {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(StrictDecode::strict_decode(d)?))
    }
}

impl StrictEncode for u256 {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_le_bytes().strict_encode(e)
    }
}

impl StrictDecode for u256 {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(u256::from_le_bytes(<[u8; 32]>::strict_decode(d)?))
    }
}

impl StrictEncode for u512 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl StrictDecode for u512 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes)?;
        Ok(u512::from_le_bytes(bytes))
    }
}

impl StrictEncode for u1024 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl StrictDecode for u1024 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 128];
        d.read_exact(&mut bytes)?;
        Ok(u1024::from_le_bytes(bytes))
    }
}

impl StrictEncode for i256 {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_le_bytes().strict_encode(e)
    }
}

impl StrictDecode for i256 {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(i256::from_le_bytes(<[u8; 32]>::strict_decode(d)?))
    }
}

impl StrictEncode for i512 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl StrictDecode for i512 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes)?;
        Ok(i512::from_le_bytes(bytes))
    }
}

impl StrictEncode for i1024 {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl StrictDecode for i1024 {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 128];
        d.read_exact(&mut bytes)?;
        Ok(i1024::from_le_bytes(bytes))
    }
}

#[cfg(feature = "float")]
impl StrictEncode for bf16 {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().strict_encode(e)
    }
}

#[cfg(feature = "float")]
impl StrictDecode for bf16 {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(bf16::from_bits(u16::strict_decode(d)?))
    }
}

#[cfg(feature = "float")]
impl StrictEncode for ieee::Half {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().to_le_bytes()[..2].strict_encode(e)
    }
}

#[cfg(feature = "float")]
impl StrictDecode for ieee::Half {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..2])?;
        Ok(ieee::Half::from_bits(u256::from_le_bytes(buf)))
    }
}

#[cfg(feature = "float")]
impl StrictEncode for ieee::Quad {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().to_le_bytes()[..16].strict_encode(e)
    }
}

#[cfg(feature = "float")]
impl StrictDecode for ieee::Oct {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..])?;
        Ok(ieee::Oct::from_bits(u256::from_le_bytes(buf)))
    }
}

#[cfg(feature = "float")]
impl StrictEncode for ieee::Oct {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().to_le_bytes().strict_encode(e)
    }
}

#[cfg(feature = "float")]
impl StrictDecode for ieee::Quad {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..16])?;
        Ok(ieee::Quad::from_bits(u256::from_le_bytes(buf)))
    }
}

#[cfg(feature = "float")]
impl StrictEncode for ieee::X87DoubleExtended {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().to_le_bytes()[..10].strict_encode(e)
    }
}

#[cfg(feature = "float")]
impl StrictDecode for ieee::X87DoubleExtended {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..10])?;
        Ok(ieee::X87DoubleExtended::from_bits(u256::from_le_bytes(buf)))
    }
}

#[cfg(test)]
mod test {
    use strict_encoding_test::test_encoding_roundtrip;

    use super::*;

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
