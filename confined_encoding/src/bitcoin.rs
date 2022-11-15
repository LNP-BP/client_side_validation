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

use bitcoin::util::taproot::{
    FutureLeafVersion, LeafVersion, TapBranchHash, TapLeafHash, TapTweakHash,
    TaprootMerkleBranch,
};
use bitcoin::{
    schnorr as bip340, secp256k1, OutPoint, Script, Txid, XOnlyPublicKey,
};
use bitcoin_hashes::sha256;

use crate::{strategies, ConfinedDecode, ConfinedEncode, Error, Strategy};

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
    fn confined_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().confined_encode(e)
    }
}

impl ConfinedDecode for TaprootMerkleBranch {
    fn confined_decode<D: Read>(d: D) -> Result<Self, Error> {
        let data = Vec::<sha256::Hash>::confined_decode(d)?;
        TaprootMerkleBranch::try_from(data).map_err(|_| {
            Error::DataIntegrityError(s!(
                "taproot merkle branch length exceeds 128 consensus limit"
            ))
        })
    }
}

impl ConfinedEncode for secp256k1::PublicKey {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.serialize())?)
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
        Ok(e.write(&self.serialize())?)
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
        Ok(e.write(&self.serialize())?)
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

impl ConfinedEncode for Script {
    #[inline]
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_bytes().confined_encode(e)
    }
}

impl ConfinedDecode for Script {
    #[inline]
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::from(Vec::<u8>::confined_decode(d)?))
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

    #[test]
    fn test_encoding_script() {
        static OP_RETURN: [u8; 40] = [
            0x26, 0x0, 0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0x20, 0x28, 0xf,
            0x53, 0xf2, 0xd2, 0x16, 0x63, 0xca, 0xc8, 0x9e, 0x6b, 0xd2, 0xad,
            0x19, 0xed, 0xba, 0xbb, 0x4, 0x8c, 0xda, 0x8, 0xe7, 0x3e, 0xd1,
            0x9e, 0x92, 0x68, 0xd0, 0xaf, 0xea, 0x2a,
        ];
        static P2PK: [u8; 37] = [
            0x23, 0x0, 0x21, 0x2, 0x34, 0xe6, 0xa7, 0x9c, 0x53, 0x59, 0xc6,
            0x13, 0x76, 0x2d, 0x53, 0x7e, 0xe, 0x19, 0xd8, 0x6c, 0x77, 0xc1,
            0x66, 0x6d, 0x8c, 0x9a, 0xb0, 0x50, 0xf2, 0x3a, 0xcd, 0x19, 0x8e,
            0x97, 0xf9, 0x3e, 0xac,
        ];

        static P2PKH: [u8; 27] = [
            0x19, 0x0, 0x76, 0xa9, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a,
            0xb8, 0x66, 0xab, 0x60, 0xff, 0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70,
            0x33, 0x36, 0x5a, 0x88, 0xac,
        ];
        static P2SH: [u8; 25] = [
            0x17, 0x0, 0xa9, 0x14, 0x4d, 0xa3, 0x4a, 0xe8, 0x19, 0x9d, 0xbf,
            0x68, 0x4f, 0xe9, 0x7a, 0xf8, 0x70, 0x3f, 0x12, 0xe9, 0xf7, 0xaa,
            0xe6, 0x62, 0x87,
        ];
        static P2WPKH: [u8; 24] = [
            0x16, 0x0, 0x0, 0x14, 0xaa, 0xca, 0x99, 0x1e, 0x29, 0x8a, 0xb8,
            0x66, 0xab, 0x60, 0xff, 0x45, 0x22, 0x1b, 0x45, 0x8c, 0x70, 0x33,
            0x36, 0x5a,
        ];
        static P2WSH: [u8; 36] = [
            0x22, 0x0, 0x0, 0x20, 0x9d, 0x27, 0x71, 0x75, 0x73, 0x7f, 0xb5,
            0x0, 0x41, 0xe7, 0x5f, 0x64, 0x1a, 0xcf, 0x94, 0xd1, 0xd, 0xf9,
            0xb9, 0x72, 0x1d, 0xb8, 0xff, 0xfe, 0x87, 0x4a, 0xb5, 0x7f, 0x8f,
            0xfb, 0x6, 0x2e,
        ];

        // OP_RETURN
        let op_return: Script = test_vec_decoding_roundtrip(OP_RETURN).unwrap();
        assert!(op_return.is_op_return());

        // P2PK
        let p2pk: Script = test_vec_decoding_roundtrip(P2PK).unwrap();
        assert!(p2pk.is_p2pk());

        //P2PKH
        let p2pkh: Script = test_vec_decoding_roundtrip(P2PKH).unwrap();
        assert!(p2pkh.is_p2pkh());

        //P2SH
        let p2sh: Script = test_vec_decoding_roundtrip(P2SH).unwrap();
        assert!(p2sh.is_p2sh());

        //P2WPKH
        let p2wpkh: Script = test_vec_decoding_roundtrip(P2WPKH).unwrap();
        assert!(p2wpkh.is_v0_p2wpkh());

        //P2WSH
        let p2wsh: Script = test_vec_decoding_roundtrip(P2WSH).unwrap();
        assert!(p2wsh.is_v0_p2wsh());
    }
}
