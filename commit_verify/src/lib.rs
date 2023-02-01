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

#[macro_use]
extern crate amplify;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

pub(self) mod commit;
mod conceal;
mod convolve;
pub(self) mod embed;
mod encode;
// mod merkle;
pub mod mpc;

pub use commit::{CommitVerify, TryCommitVerify};
pub use conceal::Conceal;
pub use convolve::{ConvolveCommit, ConvolveCommitProof};
pub use embed::{EmbedCommitProof, EmbedCommitVerify, VerifyEq};
pub use encode::CommitEncode;

/// Marker trait for specific commitment protocols.
///
/// Generic parameter `Protocol` used in commitment scheme traits provides a
/// context & configuration for the concrete implementations.
///
/// Introduction of such generic allows to:
/// - implement trait for foreign data types;
/// - add multiple implementations under different commitment protocols to the
///   combination of the same message and container type (each of each will have
///   its own `Proof` type defined as an associated generic).
///
/// Each of the commitment protocols should use [`Self::HASH_TAG_MIDSTATE`] as a
/// part of tagged hashing of the message as a part of the commitment procedure.
pub trait CommitmentProtocol {
    /// Midstate for the protocol-specific tagged hash.
    const HASH_TAG_MIDSTATE: Option<bitcoin_hashes::sha256::Midstate>;
}

/// Protocol defining commits created by using externally created hash value
/// *optionally pretagged).
pub struct PrehashedProtocol;
impl CommitmentProtocol for PrehashedProtocol {
    const HASH_TAG_MIDSTATE: Option<bitcoin_hashes::sha256::Midstate> = None;
}

/// Helpers for writing test functions working with commit schemes
#[cfg(test)]
pub mod test_helpers {
    use amplify::hex::FromHex;

    pub use super::commit::test_helpers::*;
    pub use super::embed::test_helpers::*;
    use super::*;

    /// Generates a set of messages for testing purposes
    ///
    /// All of these messages MUST produce different commitments, otherwise the
    /// commitment algorithm is not collision-resistant
    pub fn gen_messages() -> Vec<Vec<u8>> {
        vec![
            // empty message
            b"".to_vec(),
            // zero byte message
            b"\x00".to_vec(),
            // text message
            b"test".to_vec(),
            // text length-extended message
            b"test*".to_vec(),
            // short binary message
            Vec::from_hex("deadbeef").unwrap(),
            // length-extended version
            Vec::from_hex("deadbeef00").unwrap(),
            // prefixed version
            Vec::from_hex("00deadbeef").unwrap(),
            // serialized public key as text
            b"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_vec(),
            // the same public key binary data
            Vec::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
            // different public key
            Vec::from_hex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .unwrap(),
        ]
    }
}
