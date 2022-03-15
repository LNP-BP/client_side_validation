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

#[cfg(feature = "ed25519-dalek")]
use ed25519_dalek::ed25519::signature::Signature;

use crate::{Error, StrictDecode, StrictEncode};

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::PublicKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self.as_bytes()[..])?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::PublicKey {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::PUBLIC_KEY_LENGTH];
        d.read_exact(&mut buf)?;
        Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Curve25519 public key data".to_string(),
            )
        })
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictEncode for ed25519_dalek::Signature {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(self.as_bytes())?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl StrictDecode for ed25519_dalek::Signature {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; ed25519_dalek::SIGNATURE_LENGTH];
        d.read_exact(&mut buf)?;
        Self::from_bytes(&buf).map_err(|_| {
            Error::DataIntegrityError(
                "invalid Ed25519 signature data".to_string(),
            )
        })
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictEncode for secp256k1zkp::Error {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        let code: u8 = match self {
            secp256k1zkp::Error::IncapableContext => 0,
            secp256k1zkp::Error::IncorrectSignature => 1,
            secp256k1zkp::Error::InvalidMessage => 2,
            secp256k1zkp::Error::InvalidPublicKey => 3,
            secp256k1zkp::Error::InvalidCommit => 4,
            secp256k1zkp::Error::InvalidSignature => 5,
            secp256k1zkp::Error::InvalidSecretKey => 6,
            secp256k1zkp::Error::InvalidRecoveryId => 7,
            secp256k1zkp::Error::IncorrectCommitSum => 8,
            secp256k1zkp::Error::InvalidRangeProof => 9,
            secp256k1zkp::Error::PartialSigFailure => 10,
        };
        code.strict_encode(e)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictDecode for secp256k1zkp::Error {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(d)? {
            0 => secp256k1zkp::Error::IncapableContext,
            1 => secp256k1zkp::Error::IncorrectSignature,
            2 => secp256k1zkp::Error::InvalidMessage,
            3 => secp256k1zkp::Error::InvalidPublicKey,
            4 => secp256k1zkp::Error::InvalidCommit,
            5 => secp256k1zkp::Error::InvalidSignature,
            6 => secp256k1zkp::Error::InvalidSecretKey,
            7 => secp256k1zkp::Error::InvalidRecoveryId,
            8 => secp256k1zkp::Error::IncorrectCommitSum,
            9 => secp256k1zkp::Error::InvalidRangeProof,
            10 => secp256k1zkp::Error::PartialSigFailure,
            unknown => {
                return Err(Error::EnumValueNotKnown(
                    "secp256k1zkp::Error",
                    unknown as usize,
                ))
            }
        })
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictEncode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self[..])?)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictDecode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_vec(buf.to_vec()))
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictEncode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.proof[..self.plen].as_ref().strict_encode(e)
    }
}

#[cfg(feature = "grin_secp256k1zkp")]
impl StrictDecode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        use secp256k1zkp::constants::MAX_PROOF_SIZE;
        let data = Vec::<u8>::strict_decode(d)?;
        match data.len() {
            len if len < MAX_PROOF_SIZE => {
                let mut buf = [0; MAX_PROOF_SIZE];
                buf[..len].copy_from_slice(&data);
                Ok(Self {
                    proof: buf,
                    plen: len,
                })
            }
            invalid_len => Err(Error::DataIntegrityError(format!(
                "Wrong bulletproof data size: expected no more than {}, got {}",
                MAX_PROOF_SIZE, invalid_len
            ))),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    #[cfg(feature = "ed25519-dalek")]
    fn ed25519() {
        let keypair = ed25519_dalek::Keypair::generate(&mut rand::thread_rng());

        let ser = keypair.public.strict_serialize().unwrap();
        assert_eq!(ser.len(), 32);
        assert_eq!(
            ed25519_dalek::PublicKey::strict_deserialize(ser).unwrap(),
            keypair.public
        );
    }

    #[test]
    #[cfg(feature = "ed25519-dalek")]
    fn x25519() {
        use ed25519_dalek::Signer;

        let keypair = ed25519_dalek::Keypair::generate(&mut rand::thread_rng());
        let message: &[u8] = b"This is a test of the tsunami alert system.";
        let signature = keypair.sign(message);

        let ser = signature.strict_serialize().unwrap();
        assert_eq!(ser.len(), 64);
        assert_eq!(
            ed25519_dalek::Signature::strict_deserialize(ser).unwrap(),
            signature
        );
    }

    #[test]
    #[cfg(all(feature = "grin_secp256k1zkp", feature = "bitcoin"))]
    fn pedersen() {
        use std::str::FromStr;

        use bitcoin::secp256k1::PublicKey;

        let pk = PublicKey::from_str("02d1780dd0e08f4d873f94faf49d878d909a1174291d3fcac3e02a6c45e7eda744").unwrap();
        let secp = secp256k1zkp::Secp256k1::new();
        let pedersen = secp256k1zkp::pedersen::Commitment::from_pubkey(
            &secp,
            &secp256k1zkp::PublicKey::from_slice(&secp, &pk.serialize())
                .unwrap(),
        )
        .unwrap();

        let ser = pedersen.strict_serialize().unwrap();
        assert_eq!(ser.len(), 33);
        assert_eq!(
            secp256k1zkp::pedersen::Commitment::strict_deserialize(ser)
                .unwrap(),
            pedersen
        );
    }

    #[test]
    #[cfg(feature = "grin_secp256k1zkp")]
    fn bulletproof() {
        let secp = secp256k1zkp::Secp256k1::new();
        let blind = secp256k1zkp::SecretKey::new(
            &secp,
            &mut secp256k1zkp::rand::thread_rng(),
        );
        let bulletproof = secp.bullet_proof(
            0x79833565,
            blind.clone(),
            blind.clone(),
            blind.clone(),
            None,
            None,
        );

        let ser = bulletproof.strict_serialize().unwrap();
        assert_eq!(ser.len(), bulletproof.plen + 2);
        assert_eq!(
            secp256k1zkp::pedersen::RangeProof::strict_deserialize(ser)
                .unwrap(),
            bulletproof
        );
    }

    /* TODO: #25 Uncomment this test once `grin_secp256k1zkp::Error` impl `Ord`
    #[test]
    #[cfg(feature = "grin_secp256k1zkp")]
    fn error_encoding() {
        test_encoding_enum_u8_exhaustive!(crate => secp256k1zkp::Error;
            secp256k1zkp::Error::IncapableContext => 0u8,
            secp256k1zkp::Error::IncorrectSignature => 1u8,
            secp256k1zkp::Error::InvalidMessage => 2u8,
            secp256k1zkp::Error::InvalidPublicKey => 3u8,
            secp256k1zkp::Error::InvalidCommit => 4u8,
            secp256k1zkp::Error::InvalidSignature => 5u8,
            secp256k1zkp::Error::InvalidSecretKey => 6u8,
            secp256k1zkp::Error::InvalidRecoveryId => 7u8,
            secp256k1zkp::Error::IncorrectCommitSum => 8u8,
            secp256k1zkp::Error::InvalidRangeProof => 9u8,
            secp256k1zkp::Error::PartialSigFailure => 10u8
        )
        .unwrap()
    }
     */
}
