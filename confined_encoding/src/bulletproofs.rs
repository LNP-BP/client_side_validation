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

use crate::{ConfinedDecode, ConfinedEncode, Error};

impl ConfinedEncode for secp256k1zkp::Error {
    #[inline]
    fn confined_encode<E: io::Write>(&self, _: E) -> Result<usize, Error> {
        unreachable!(
            "rust compiler requires confined encoding due to derivation \
             macros, but its code must be unreachable"
        )
    }
}

impl ConfinedDecode for secp256k1zkp::Error {
    #[inline]
    fn confined_decode<D: io::Read>(_: D) -> Result<Self, Error> {
        unreachable!(
            "rust compiler requires confined encoding due to derivation \
             macros, but its code must be unreachable"
        )
    }
}

impl ConfinedEncode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(e.write(&self[..])?)
    }
}

impl ConfinedDecode for secp256k1zkp::pedersen::Commitment {
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = [0u8; secp256k1zkp::constants::PEDERSEN_COMMITMENT_SIZE];
        d.read_exact(&mut buf)?;
        Ok(Self::from_vec(buf.to_vec()))
    }
}

impl ConfinedEncode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.proof[..self.plen].as_ref().confined_encode(e)
    }
}

impl ConfinedDecode for secp256k1zkp::pedersen::RangeProof {
    #[inline]
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        use secp256k1zkp::constants::MAX_PROOF_SIZE;
        let data = Vec::<u8>::confined_decode(d)?;
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
