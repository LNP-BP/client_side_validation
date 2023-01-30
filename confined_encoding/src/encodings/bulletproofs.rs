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

use secp256k1zkp::constants::MAX_PROOF_SIZE;

use crate::schema::Ty;
use crate::{
    ConfinedDecode, ConfinedEncode, ConfinedRead, ConfinedType, ConfinedWrite,
    Error,
};

impl ConfinedType for secp256k1zkp::pedersen::Commitment {
    const TYPE_NAME: &'static str = "PedersenCommitment";

    fn confined_type() -> Ty { Ty::byte_array(33) }
}

impl ConfinedEncode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_byte_array(self.0)
    }
}

impl ConfinedDecode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        let buf: [u8; secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE] =
            d.read_byte_array()?;
        Ok(Self(buf))
    }
}

impl ConfinedType for secp256k1zkp::pedersen::RangeProof {
    const TYPE_NAME: &'static str = "BulletProof";

    fn confined_type() -> Ty { Ty::bytes() }
}

impl ConfinedEncode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn confined_encode(&self, mut e: impl ConfinedWrite) -> Result<(), Error> {
        e.write_bytes::<0, { u16::MAX as usize }>(&self.proof[..self.plen])
    }
}

impl ConfinedDecode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn confined_decode(mut d: impl ConfinedRead) -> Result<Self, Error> {
        let proof = d.read_bytes::<0, { u16::MAX as usize }>()?;
        let len = proof.len();
        if len as usize >= MAX_PROOF_SIZE {
            return Err(Error::DataIntegrityError(format!(
                "Wrong bulletproof data size: expected no more than {}, got {}",
                MAX_PROOF_SIZE, len
            )));
        }
        let mut buf = [0; MAX_PROOF_SIZE];
        buf.copy_from_slice(proof.as_ref());
        Ok(Self {
            proof: buf,
            plen: len,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
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

        let ser = pedersen.confined_serialize().unwrap();
        assert_eq!(ser.len(), 33);
        assert_eq!(
            secp256k1zkp::pedersen::Commitment::confined_deserialize(ser)
                .unwrap(),
            pedersen
        );
    }

    #[test]
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
            blind,
            None,
            None,
        );

        let ser = bulletproof.confined_serialize().unwrap();
        assert_eq!(ser.len(), bulletproof.plen + 2);
        assert_eq!(
            secp256k1zkp::pedersen::RangeProof::confined_deserialize(ser)
                .unwrap(),
            bulletproof
        );
    }
}
