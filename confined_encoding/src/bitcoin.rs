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
use std::io::{Read, Write};

use bitcoin::hashes::{
    hash160, hmac, ripemd160, sha256, sha256d, sha256t, sha512, Hash,
};
use bitcoin::util::taproot::{
    FutureLeafVersion, LeafVersion, TapBranchHash, TapLeafHash, TapTweakHash,
    TaprootMerkleBranch,
};
use bitcoin::{schnorr as bip340, secp256k1, OutPoint, Txid, XOnlyPublicKey};

use crate::{strategies, ConfinedDecode, ConfinedEncode, Error, Strategy};

impl Strategy for sha256::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for sha256d::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl<T> Strategy for sha256t::Hash<T>
where
    T: sha256t::Tag,
{
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for sha512::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for ripemd160::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for hash160::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl<T> Strategy for hmac::Hmac<T>
where
    T: Hash,
{
    type Strategy = strategies::HashFixedBytes;
}

impl Strategy for Txid {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for TapBranchHash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for TapLeafHash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for TapTweakHash {
    type Strategy = strategies::HashFixedBytes;
}

impl ConfinedEncode for LeafVersion {
    fn confined_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.to_consensus().confined_encode(e)
    }
}

impl ConfinedDecode for LeafVersion {
    fn confined_decode<D: Read>(d: D) -> Result<Self, Error> {
        let leaf_version = u8::confined_decode(d)?;
        LeafVersion::from_consensus(leaf_version).map_err(|_| {
            Error::DataIntegrityError(format!(
                "incorrect LeafVersion `{}`",
                leaf_version
            ))
        })
    }
}

impl ConfinedEncode for FutureLeafVersion {
    fn confined_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.to_consensus().confined_encode(e)
    }
}

impl ConfinedDecode for FutureLeafVersion {
    fn confined_decode<D: Read>(d: D) -> Result<Self, Error> {
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

impl ConfinedEncode for TaprootMerkleBranch {
    fn confined_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        let vec = self.as_inner();
        // Merkle branch always has length less than 128
        let count: u8 = vec.len().try_into().map_err(|_| {
            Error::DataIntegrityError(s!(
                "Taproot Merkle branch with more than 128 elements"
            ))
        })?;
        let mut len = count.confined_encode(&mut e)?;
        for elem in vec {
            len += elem.confined_encode(&mut e)?;
        }
        Ok(len)
    }
}

impl ConfinedDecode for TaprootMerkleBranch {
    fn confined_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        let count = u8::confined_decode(&mut d)?;
        let mut vec = Vec::with_capacity(count as usize);
        for _ in 0..count {
            vec.push(sha256::Hash::confined_decode(&mut d)?);
        }
        TaprootMerkleBranch::try_from(vec).map_err(|_| {
            Error::DataIntegrityError(s!(
                "taproot merkle branch length exceeds 128 consensus limit"
            ))
        })
    }
}

impl ConfinedEncode for secp256k1::PublicKey {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let data = self.serialize();
        e.write_all(&data[..])?;
        Ok(33)
    }
}

impl ConfinedDecode for secp256k1::PublicKey {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        if buf[0] == 0x04 {
            return Err(Error::DataIntegrityError(s!("invalid public key \
                                                     data: uncompressed \
                                                     Secp256k1 public key \
                                                     format is not \
                                                     allowed, use \
                                                     compressed form \
                                                     instead")));
        }
        Self::from_slice(&buf).map_err(|_| {
            Error::DataIntegrityError(s!("invalid public key data"))
        })
    }
}

impl ConfinedEncode for XOnlyPublicKey {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.serialize())?;
        Ok(32)
    }
}

impl ConfinedDecode for XOnlyPublicKey {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Self::from_slice(&buf[..]).map_err(|_| {
            Error::DataIntegrityError(s!("invalid public key data"))
        })
    }
}

impl ConfinedEncode for bip340::TweakedPublicKey {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.serialize())?;
        Ok(32)
    }
}

impl ConfinedDecode for bip340::TweakedPublicKey {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::dangerous_assume_tweaked(
            XOnlyPublicKey::from_slice(&buf[..]).map_err(|_| {
                Error::DataIntegrityError(s!("invalid public key data"))
            })?,
        ))
    }
}

impl ConfinedEncode for OutPoint {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(confined_encode_list!(e; self.txid, self.vout))
    }
}

impl ConfinedDecode for OutPoint {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(confined_decode_self!(d; txid, vout))
    }
}

impl ConfinedEncode for bitcoin::Network {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.magic().confined_encode(&mut e)
    }
}

impl ConfinedDecode for bitcoin::Network {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let magic = u32::confined_decode(&mut d)?;
        Self::from_magic(magic).ok_or(Error::ValueOutOfRange(
            "bitcoin::Network",
            0..0,
            magic as u128,
        ))
    }
}

#[cfg(test)]
pub(crate) mod test {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::Hash;
    use bitcoin_hashes::{hash160, hmac, ripemd160, sha256, sha256d, sha256t};
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

        const TEST_MIDSTATE: [u8; 32] = [
            156, 224, 228, 230, 124, 17, 108, 57, 56, 179, 202, 242, 195, 15,
            80, 137, 211, 243, 147, 108, 71, 99, 110, 96, 125, 179, 62, 234,
            221, 198, 240, 201,
        ];

        #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
        pub struct TestHashTag;

        impl sha256t::Tag for TestHashTag {
            fn engine() -> sha256::HashEngine {
                // The TapRoot TapLeaf midstate.
                let midstate = sha256::Midstate::from_inner(TEST_MIDSTATE);
                sha256::HashEngine::from_midstate(midstate, 64)
            }
        }

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
            &hmac::Hmac::<sha256::Hash>::from_inner(HASH256_BYTES),
            HASH256_BYTES,
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
            &sha256t::Hash::<TestHashTag>::from_inner(HASH256_BYTES),
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
        static PK_BYTES_04: [u8; 65] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d,
            0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81,
            0x9e, 0x4e, 0xe9, 0x71, 0xd8, 0x6b, 0x5e, 0x61, 0x87, 0x5d,
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
            secp256k1::PublicKey::confined_deserialize(PK_BYTES_04),
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
        static PK_BYTES_04: [u8; 60] = [
            0x04, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
            0x87, 0x28, 0x8e, 0xd7, 0x3c, 0xe4, 0x7f, 0xc4, 0xf5, 0xc7, 0x9d,
            0x19, 0xeb, 0xfa, 0x57, 0xda, 0x7c, 0xff, 0x3a, 0xff, 0x6e, 0x81,
            0x9e, 0x4e, 0xe9, 0x71, 0xd8,
        ];
        secp256k1::PublicKey::confined_decode(&PK_BYTES_04[..]).unwrap();
    }

    #[test]
    #[should_panic(expected = "DataIntegrityError")]
    fn test_grabagedata_pubkey2() {
        static PK_BYTES_02: [u8; 33] = [
            0xa5, 0x9b, 0x63, 0x47, 0x39, 0x85, 0x05, 0xf5, 0xec, 0x93, 0x82,
            0x6d, 0xc6, 0x1c, 0x19, 0xf4, 0x7c, 0x66, 0xc0, 0x28, 0x3e, 0xe9,
            0xbe, 0x98, 0x0e, 0x29, 0xce, 0x32, 0x5a, 0x0f, 0x46, 0x79, 0xef,
        ];
        secp256k1::PublicKey::confined_decode(&PK_BYTES_02[..]).unwrap();
    }

    #[test]
    fn test_encoding_network(
    ) -> Result<(), DataEncodingTestFailure<bitcoin::Network>> {
        test_encoding_roundtrip(&bitcoin::Network::Bitcoin, [
            0xF9, 0xBE, 0xB4, 0xD9,
        ])?;
        test_encoding_roundtrip(&bitcoin::Network::Testnet, [
            0x0B, 0x11, 0x09, 0x07,
        ])?;
        test_encoding_roundtrip(&bitcoin::Network::Signet, [
            0x0A, 0x03, 0xCF, 0x40,
        ])?;
        test_encoding_roundtrip(&bitcoin::Network::Regtest, [
            0xFA, 0xBF, 0xB5, 0xDA,
        ])
    }

    #[test]
    #[should_panic(
        expected = r#"ValueOutOfRange("bitcoin::Network", 0..0, 2762187425)"#
    )]
    fn test_encoding_network_failure() {
        // Bitcoin Network structure do not support "Other" networks
        bitcoin::Network::confined_decode(
            &[0xA1u8, 0xA2u8, 0xA3u8, 0xA4u8][..],
        )
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
        static OUTPOINT: [u8; 32] = [
            0x53, 0xc6, 0x31, 0x13, 0xed, 0x18, 0x68, 0xfc, 0xa, 0xdf, 0x8e,
            0xcd, 0xfd, 0x1f, 0x4d, 0xd6, 0xe5, 0xe3, 0x85, 0x83, 0xa4, 0x9d,
            0xb, 0x14, 0xe7, 0xf8, 0x87, 0xa4, 0xd1, 0x61, 0x78, 0x21,
        ];
        OutPoint::confined_decode(&OUTPOINT[..]).unwrap();
    }
}
