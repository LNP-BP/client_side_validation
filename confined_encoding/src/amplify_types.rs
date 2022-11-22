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
use amplify::num::apfloat::{ieee, Float};
use amplify::num::{i1024, i256, i512, u1024, u256, u512};
use amplify::{Bytes32, Wrapper};
use bitcoin::hashes::{sha256, Hash};
use half::bf16;

use crate::{ConfinedDecode, ConfinedEncode, Error};

impl ConfinedEncode for Bytes32 {
    fn confined_encode<E: io::Write>(
        &self,
        e: E,
    ) -> Result<usize, crate::Error> {
        // We use the same encoding as used by hashes - and ensure this by
        // cross-converting with hash
        sha256::Hash::from_inner(self.to_inner()).confined_encode(e)
    }
}

impl ConfinedDecode for Bytes32 {
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, crate::Error> {
        let hash = sha256::Hash::confined_decode(d)?;
        Ok(Bytes32::from_inner(hash.into_inner()))
    }
}

impl ConfinedEncode for FlagVec {
    #[inline]
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.shrunk().as_inner().confined_encode(e)
    }
}

impl ConfinedDecode for FlagVec {
    #[inline]
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from_inner(ConfinedDecode::confined_decode(d)?))
    }
}

impl ConfinedEncode for u256 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for u256 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        Ok(u256::from_le_bytes(buf))
    }
}

impl ConfinedEncode for u512 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for u512 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes)?;
        Ok(u512::from_le_bytes(bytes))
    }
}

impl ConfinedEncode for u1024 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for u1024 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 128];
        d.read_exact(&mut bytes)?;
        Ok(u1024::from_le_bytes(bytes))
    }
}

impl ConfinedEncode for i256 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for i256 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 32];
        d.read_exact(&mut bytes)?;
        Ok(i256::from_le_bytes(bytes))
    }
}

impl ConfinedEncode for i512 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for i512 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 64];
        d.read_exact(&mut bytes)?;
        Ok(i512::from_le_bytes(bytes))
    }
}

impl ConfinedEncode for i1024 {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let bytes = self.to_le_bytes();
        e.write_all(&bytes)?;
        Ok(bytes.len())
    }
}

impl ConfinedDecode for i1024 {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut bytes = [0u8; 128];
        d.read_exact(&mut bytes)?;
        Ok(i1024::from_le_bytes(bytes))
    }
}

impl ConfinedEncode for bf16 {
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bits().confined_encode(e)
    }
}

impl ConfinedDecode for bf16 {
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(bf16::from_bits(u16::confined_decode(d)?))
    }
}

impl ConfinedEncode for ieee::Half {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_bits().to_le_bytes()[..2])?;
        Ok(2)
    }
}

impl ConfinedDecode for ieee::Half {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..2])?;
        Ok(ieee::Half::from_bits(u256::from_le_bytes(buf)))
    }
}

impl ConfinedEncode for ieee::Quad {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_bits().to_le_bytes()[..16])?;
        Ok(16)
    }
}

impl ConfinedDecode for ieee::Oct {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..])?;
        Ok(ieee::Oct::from_bits(u256::from_le_bytes(buf)))
    }
}

impl ConfinedEncode for ieee::Oct {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_bits().to_le_bytes()[..32])?;
        Ok(32)
    }
}

impl ConfinedDecode for ieee::Quad {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..16])?;
        Ok(ieee::Quad::from_bits(u256::from_le_bytes(buf)))
    }
}

impl ConfinedEncode for ieee::X87DoubleExtended {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.to_bits().to_le_bytes()[..10])?;
        Ok(10)
    }
}

impl ConfinedDecode for ieee::X87DoubleExtended {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf[..10])?;
        Ok(ieee::X87DoubleExtended::from_bits(u256::from_le_bytes(buf)))
    }
}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use confined_encoding_test::test_encoding_roundtrip;

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

    #[test]
    fn test_encoding() {
        let s =
            "a3401bcceb26201b55978ff705fecf7d8a0a03598ebeccf2a947030b91a0ff53";
        let slice32 = Bytes32::from_hex(s).unwrap();
        let ser = slice32.confined_serialize().unwrap();

        let data = [
            0xa3, 0x40, 0x1b, 0xcc, 0xeb, 0x26, 0x20, 0x1b, 0x55, 0x97, 0x8f,
            0xf7, 0x05, 0xfe, 0xcf, 0x7d, 0x8a, 0x0a, 0x03, 0x59, 0x8e, 0xbe,
            0xcc, 0xf2, 0xa9, 0x47, 0x03, 0x0b, 0x91, 0xa0, 0xff, 0x53,
        ];

        assert_eq!(ser.len(), 32);
        assert_eq!(&ser, &data);
        assert_eq!(Bytes32::confined_deserialize(&ser), Ok(slice32));

        assert_eq!(Bytes32::from_slice(data), Some(slice32));
        assert_eq!(Bytes32::from_slice(&data[..30]), None);
        assert_eq!(&slice32.to_vec(), &data);
        assert_eq!(&slice32.as_inner()[..], &data);
        assert_eq!(slice32.to_inner(), data);
        assert_eq!(slice32.into_inner(), data);
    }
}
