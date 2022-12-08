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

use std::io::{self, Read};

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, sha256t, Hash};
use bitcoin::util::taproot::{
    FutureLeafVersion, LeafVersion, TapBranchHash, TapLeafHash, TapTweakHash,
};
use bitcoin::{schnorr as bip340, secp256k1, OutPoint, Txid, XOnlyPublicKey};

use crate::schema::Ty;
use crate::{
    fields, ConfinedDecode, ConfinedEncode, ConfinedType, ConfinedWrite, Error,
    StructBuilder,
};

hash_encoding!(sha256::Hash, "Sha256");
hash_encoding!(sha256d::Hash, "Sha256D");
hash_encoding!(ripemd160::Hash, "Ripemd160");
hash_encoding!(hash160::Hash, "Hash160");

hash_encoding!(Txid);
hash_encoding!(TapBranchHash);
hash_encoding!(TapLeafHash);
hash_encoding!(TapTweakHash);

/// Marker trait for hash tags which should be confined-encoded
pub trait ConfinedTag: sha256t::Tag {
    /// Type name for strict encoding schema
    const TYPE_NAME: &'static str;
}

impl<T: ConfinedTag> ConfinedType for sha256t::Hash<T> {
    const TYPE_NAME: &'static str = stringify!(T::TYPE_NAME, "Hash");

    fn confined_type() -> Ty { Ty::byte_array(32) }
}

impl<T: ConfinedTag> ConfinedEncode for sha256t::Hash<T> {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.into_inner())
    }
}

impl<T: ConfinedTag> ConfinedDecode for sha256t::Hash<T> {
    fn confined_decode(d: &mut impl Read) -> Result<Self, Error> {
        let mut buf = [0u8; 32];
        d.read_exact(&mut buf)?;
        Ok(Self::from_slice(&buf)
            .expect("bitcoin hashes inner structure is broken"))
    }
}

impl ConfinedType for LeafVersion {
    const TYPE_NAME: &'static str = "LeafVersion";

    fn confined_type() -> Ty { Ty::u8() }
}

impl ConfinedEncode for LeafVersion {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_u8(self.to_consensus())
    }
}

impl ConfinedDecode for LeafVersion {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let leaf_version = u8::confined_decode(d)?;
        LeafVersion::from_consensus(leaf_version).map_err(|_| {
            Error::DataIntegrityError(format!(
                "incorrect LeafVersion `{}`",
                leaf_version
            ))
        })
    }
}

impl ConfinedType for FutureLeafVersion {
    const TYPE_NAME: &'static str = "FutureLeafVersion";

    fn confined_type() -> Ty { Ty::u8() }
}

impl ConfinedEncode for FutureLeafVersion {
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_u8(self.to_consensus())
    }
}

impl ConfinedDecode for FutureLeafVersion {
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        match LeafVersion::confined_decode(d)? {
            LeafVersion::TapScript => {
                Err(Error::DataIntegrityError(s!("known LeafVersion was \
                                                  found while decoding \
                                                  FutureLeafVersion")))
            }
            LeafVersion::Future(version) => Ok(version),
        }
    }
}

impl ConfinedType for secp256k1::PublicKey {
    const TYPE_NAME: &'static str = "CompressedPubkey";

    fn confined_type() -> Ty { Ty::byte_array(32) }
}

impl ConfinedEncode for secp256k1::PublicKey {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.serialize())
    }
}

impl ConfinedDecode for secp256k1::PublicKey {
    #[inline]
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        if buf[0] != 0x02 || buf[1] != 0x03 {
            return Err(Error::DataIntegrityError(s!("invalid public key \
                                                     data: only \
                                                     compressed Secp256k1 \
                                                     public keys are \
                                                     allowed")));
        }
        Self::from_slice(&buf).map_err(|_| {
            Error::DataIntegrityError(s!("invalid public key data"))
        })
    }
}

impl ConfinedType for XOnlyPublicKey {
    const TYPE_NAME: &'static str = "XOnlyPubkey";

    fn confined_type() -> Ty { Ty::byte_array(32) }
}

impl ConfinedEncode for XOnlyPublicKey {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.serialize())
    }
}

impl ConfinedDecode for XOnlyPublicKey {
    #[inline]
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Self::from_slice(&buf[..]).map_err(|err| {
            Error::DataIntegrityError(format!(
                "invalid public key data: {}",
                err
            ))
        })
    }
}

impl ConfinedType for bip340::TweakedPublicKey {
    const TYPE_NAME: &'static str = "TweakedPublicKey";

    fn confined_type() -> Ty { Ty::byte_array(32) }
}

impl ConfinedEncode for bip340::TweakedPublicKey {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.serialize())
    }
}

impl ConfinedDecode for bip340::TweakedPublicKey {
    #[inline]
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::dangerous_assume_tweaked(
            XOnlyPublicKey::from_slice(&buf[..]).map_err(|err| {
                Error::DataIntegrityError(format!(
                    "invalid public key data: {}",
                    err
                ))
            })?,
        ))
    }
}

impl ConfinedType for OutPoint {
    const TYPE_NAME: &'static str = "OutPoint";

    fn confined_type() -> Ty {
        Ty::Struct(fields![
            "txid" => Txid::confined_type(),
            "vout" => Ty::u16()
        ])
    }
}

impl ConfinedEncode for OutPoint {
    #[inline]
    fn confined_encode(&self, e: impl ConfinedWrite) -> Result<(), Error> {
        StructBuilder::start(e)
            .field("txid", &self.txid)?
            .field("vout", &self.vout)?
            .finish();
        Ok(())
    }
}

impl ConfinedDecode for OutPoint {
    #[inline]
    fn confined_decode(d: &mut impl io::Read) -> Result<Self, Error> {
        Ok(confined_decode_self!(d; txid, vout))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d, Hash};
    use confined_encoding_test::*;

    use super::*;

    #[test]
    fn test_encoding_hashes() {
        static HASH256_BYTES: [u8; 32] = [
            0x15, 0x2d, 0x1c, 0x97, 0x61, 0xd4, 0x64, 0x66, 0x68, 0xdf, 0xcd,
            0xeb, 0x11, 0x98, 0x70, 0x84, 0x4e, 0xdb, 0x25, 0xa0, 0xea, 0x1e,
            0x35, 0x20, 0x7f, 0xaa, 0x44, 0xa9, 0x67, 0xa6, 0xa6, 0x61,
        ];
        static HASH160_BYTES: [u8; 20] = [
            0x15, 0x2d, 0x1c, 0x97, 0x61, 0xd4, 0x64, 0x66, 0x68, 0xdf, 0xcd,
            0xeb, 0x11, 0x98, 0x4e, 0xdb, 0x25, 0xa0, 0xea, 0x1e,
        ];

        test_encoding_roundtrip(
            &ripemd160::Hash::from_inner(HASH160_BYTES),
            HASH160_BYTES,
        )
        .unwrap();
        test_encoding_roundtrip(
            &hash160::Hash::from_inner(HASH160_BYTES),
            HASH160_BYTES,
        )
        .unwrap();
        test_encoding_roundtrip(
            &sha256::Hash::from_inner(HASH256_BYTES),
            HASH256_BYTES,
        )
        .unwrap();
        test_encoding_roundtrip(
            &sha256d::Hash::from_inner(HASH256_BYTES),
            HASH256_BYTES,
        )
        .unwrap();
        test_encoding_roundtrip(
            &Txid::from_slice(&HASH256_BYTES).unwrap(),
            HASH256_BYTES,
        )
        .unwrap();
    }

    #[test]
    fn test_encoding_pubkey() {
        static PK_BYTES_02: [u8; 33] = [
            0x02, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_03: [u8; 33] = [
            0x03, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        static PK_BYTES_ONEKEY: [u8; 32] = [
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
            0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce,
            0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];

        let secp_pk_02 =
            secp256k1::PublicKey::from_slice(&PK_BYTES_02).unwrap();
        let secp_pk_03 =
            secp256k1::PublicKey::from_slice(&PK_BYTES_03).unwrap();
        let secp_pk_one = XOnlyPublicKey::from_slice(&PK_BYTES_ONEKEY).unwrap();
        test_encoding_roundtrip(&secp_pk_02, PK_BYTES_02).unwrap();
        test_encoding_roundtrip(&secp_pk_03, PK_BYTES_03).unwrap();
        test_encoding_roundtrip(&secp_pk_one, PK_BYTES_ONEKEY).unwrap();
        assert_eq!(
            secp256k1::PublicKey::confined_deserialize(&tiny_vec![
                0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93,
                0x82, 0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28,
                0x3e, 0xe9, 0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f,
                0x46, 0x79, 0xef, 0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f,
                0xc4, 0xf5, 0xc7, 0x9d, 0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c,
                0xff, 0x3a, 0xff, 0x6e, 0x81, 0x9e, 0x4e, 0xe9, 0x71, 0xd8,
                0x6b, 0x5e, 0x61, 0x87, 0x5d,
            ]),
            Err(Error::DataIntegrityError(s!("invalid public key data: \
                                              uncompressed Secp256k1 \
                                              public key format is not \
                                              allowed, use compressed \
                                              form instead")))
        );

        let xcoordonly_02 =
            XOnlyPublicKey::from_slice(&PK_BYTES_02[1..]).unwrap();
        let xcoordonly_one =
            XOnlyPublicKey::from_slice(&PK_BYTES_ONEKEY[..]).unwrap();
        test_encoding_roundtrip(&xcoordonly_02, &PK_BYTES_02[1..]).unwrap();
        test_encoding_roundtrip(&xcoordonly_one, PK_BYTES_ONEKEY).unwrap();
        assert_eq!(xcoordonly_02.serialize(), secp_pk_02.serialize()[1..]);
        assert_eq!(xcoordonly_02.serialize(), secp_pk_03.serialize()[1..]);
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_garbagedata_pubkey() {
        secp256k1::PublicKey::confined_deserialize(&tiny_vec![
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d,
            0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81,
            0x9e, 0x4e, 0xe9, 0x71, 0xd8,
        ])
        .unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_grabagedata_pubkey2() {
        secp256k1::PublicKey::confined_deserialize(&tiny_vec![
            0xa5, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ])
        .unwrap();
    }

    #[test]
    fn test_encoding_outpoint() {
        static OUTPOINT: [u8; 36] = [
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
            0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d,
            0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21, 0x4,
            0x0, 0x0, 0x0,
        ];
        static OUTPOINT_NULL: [u8; 36] = [
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
            0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xff, 0xff,
        ];

        let txid = Txid::from_hex(
            "217861d1a487f8e7140b9da48385e3e5d64d1ffdcd8edf0afc6818ed1331c653",
        )
        .unwrap();
        let vout = 4u32;

        // test random and null outpoints
        let outpoint = OutPoint::new(txid, vout);
        test_encoding_roundtrip(&outpoint, OUTPOINT).unwrap();
        let null = OutPoint::null();
        test_encoding_roundtrip(&null, OUTPOINT_NULL).unwrap();

        assert_eq!(&OUTPOINT[..], bitcoin::consensus::serialize(&outpoint));
        assert_eq!(&OUTPOINT_NULL[..], bitcoin::consensus::serialize(&null));
    }

    #[test]
    #[should_panic(expected = "UnexpectedEof")]
    fn test_garbagedata_outpoint() {
        OutPoint::confined_deserialize(&tiny_vec![
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
            0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d,
            0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21,
        ])
        .unwrap();
    }
}
