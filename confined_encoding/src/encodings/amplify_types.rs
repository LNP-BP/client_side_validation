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

use amplify::flags::FlagVec;
use amplify::{Bytes32, Wrapper};

use crate::schema::Ty;
use crate::{
    ConfinedDecode, ConfinedEncode, ConfinedRead, ConfinedType, ConfinedWrite,
    Error,
};

impl ConfinedType for Bytes32 {
    const TYPE_NAME: &'static str = "Bytes32";

    fn confined_type() -> Ty { Ty::byte_array(32) }
}

impl ConfinedEncode for Bytes32 {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.into_inner())
    }
}

impl ConfinedDecode for Bytes32 {
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        d.read_byte_array().map(Bytes32::from_inner)
    }
}

impl ConfinedType for FlagVec {
    const TYPE_NAME: &'static str = "FlagVec";

    fn confined_type() -> Ty { Ty::bytes() }
}

impl ConfinedEncode for FlagVec {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_list(self.clone().as_inner())
    }
}

impl ConfinedDecode for FlagVec {
    #[inline]
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        let inner = d.read_list()?;
        let mut flag_vec = FlagVec::from_inner(inner);
        if flag_vec.shrink() {
            return Err(Error::DataIntegrityError(s!(
                "FlagVec stored in a non-minimal format"
            )));
        }
        Ok(flag_vec)
    }
}

#[cfg(test)]
mod test {
    use amplify::hex::FromHex;

    use super::*;

    #[test]
    fn test_encoding() {
        let s =
            "a3401bcceb26201b55978ff705fecf7d8a0a03598ebeccf2a947030b91a0ff53";
        let slice32 = Bytes32::from_hex(s).unwrap();
        let ser = slice32.confined_serialize().unwrap();

        let data = small_vec![
            0xa3, 0x40, 0x1b, 0xcc, 0xeb, 0x26, 0x20, 0x1b, 0x55, 0x97, 0x8f,
            0xf7, 0x05, 0xfe, 0xcf, 0x7d, 0x8a, 0x0a, 0x03, 0x59, 0x8e, 0xbe,
            0xcc, 0xf2, 0xa9, 0x47, 0x03, 0x0b, 0x91, 0xa0, 0xff, 0x53,
        ];

        assert_eq!(ser.len(), 32);
        assert_eq!(&ser, &data);
        assert_eq!(Bytes32::confined_deserialize(&ser).unwrap(), slice32);
        assert_eq!(&slice32[..], &data[..]);
    }
}
