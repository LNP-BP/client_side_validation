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
use amplify::{Bytes32, Wrapper};
use bitcoin::hashes::{sha256, Hash};

use crate::{ConfinedDecode, ConfinedEncode, Error};

impl ConfinedEncode for Bytes32 {
    fn confined_encode(&self, e: &mut impl io::Write) -> Result<(), Error> {
        // We use the same encoding as used by hashes - and ensure this by
        // cross-converting with hash
        sha256::Hash::from_inner(self.to_inner()).confined_encode(e)
    }
}

impl ConfinedDecode for Bytes32 {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let hash = sha256::Hash::confined_decode(d)?;
        Ok(Bytes32::from_inner(hash.into_inner()))
    }
}

impl ConfinedEncode for FlagVec {
    #[inline]
    fn confined_encode(&self, e: &mut impl io::Write) -> Result<(), Error> {
        // to_inner does the shrunk operation internally
        // TODO: Remove clone on amplify fix
        let shrunk = self.clone().to_inner();
        shrunk.confined_encode(e)
    }
}

impl ConfinedDecode for FlagVec {
    #[inline]
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let tiny_vec = ConfinedDecode::confined_decode(d)?;
        Ok(Self::from_inner(tiny_vec))
    }
}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;
    use confined_encoding_test::test_encoding_roundtrip;

    use super::*;

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
