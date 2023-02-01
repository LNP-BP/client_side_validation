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

//! Embedded commitments (commit-embed-verify scheme).

use crate::{CommitEncode, CommitmentProtocol};

/// Trait for equivalence verification. Implemented for all types implemeting
/// `Eq`. For non-`Eq` types this trait provides way to implement custom
/// equivalence verification used during commitment verification procedure.
pub trait VerifyEq {
    /// Verifies commit-equivalence of two instances of the same type.
    fn verify_eq(&self, other: &Self) -> bool;
}

impl<T> VerifyEq for T
where
    T: Eq,
{
    fn verify_eq(&self, other: &Self) -> bool { self == other }
}

/// Proofs produced by [`EmbedCommitVerify::embed_commit`] procedure.
pub trait EmbedCommitProof<Msg, Container, Protocol>
where
    Self: Sized + VerifyEq,
    Container: EmbedCommitVerify<Msg, Protocol>,
    Msg: CommitEncode,
    Protocol: CommitmentProtocol,
{
    /// Restores original container before the commitment from the proof data
    /// and a container containing embedded commitment.
    fn restore_original_container(
        &self,
        commit_container: &Container,
    ) -> Result<Container, Container::VerifyError>;
}

/// Trait for *embed-commit-verify scheme*, where some data structure (named
/// *container*) may commit to existing *message* (producing *commitment* data
/// structure and a *proof*) in such way that the original message can't be
/// restored from the commitment, however the fact of the commitment may be
/// deterministically *verified* when the message and the proof are *revealed*.
///
/// To use *embed-commit-verify scheme* one needs to implement this trait for
/// a data structure acting as a container for a specific commitment under
/// certain protocol, specified as generic parameter. The container type must
/// specify as associated types proof and commitment types.
///
/// Operations with *embed-commit-verify scheme* may be represented in form of
/// `EmbedCommit: (Container, Message) -> (Container', Proof)` (see
/// [`Self::embed_commit`] and `Verify: (Container', Message, Proof) -> bool`
/// (see [`Self::verify`]).
///
/// This trait is heavily used in **deterministic bitcoin commitments**.
///
/// # Protocol definition
///
/// Generic parameter `Protocol` provides context & configuration for commitment
/// scheme protocol used for this container type.
///
/// Introduction of this generic allows to:
/// - implement trait for foreign data types;
/// - add multiple implementations under different commitment protocols to the
///   combination of the same message and container type (each of each will have
///   its own `Proof` type defined as an associated generic).
///
/// Usually represents an uninstantiable type, but may be a structure
/// containing commitment protocol configuration or context objects.
///
/// ```
/// # use bitcoin_hashes::sha256::Midstate;
/// # use lnpbp_secp256k1zkp::Secp256k1;
/// # use commit_verify::CommitmentProtocol;
///
/// // Uninstantiable type
/// pub enum Lnpbp6 {}
///
/// impl CommitmentProtocol for Lnpbp6 {
///     const HASH_TAG_MIDSTATE: Option<Midstate> = Some(Midstate(
///         [0u8; 32], // replace with the actual midstate constant
///     ));
/// }
///
/// // Protocol definition containing context object
/// pub struct Lnpbp1 {
///     pub secp: Secp256k1,
/// }
/// // ...
/// ```
pub trait EmbedCommitVerify<Msg, Protocol>
where
    Self: Sized,
    Msg: CommitEncode,
    Protocol: CommitmentProtocol,
{
    /// The proof of the commitment produced as a result of
    /// [`Self::embed_commit`] procedure. This proof is later used
    /// for verification.
    type Proof: EmbedCommitProof<Msg, Self, Protocol>;

    /// Error type that may be reported during [`Self::embed_commit`] procedure.
    /// It may also be returned from [`Self::verify`] in case the proof data are
    /// invalid and the commitment can't be re-created.
    type CommitError: std::error::Error;

    /// Error type that may be reported during [`Self::verify`] procedure.
    /// It must be a subset of [`Self::CommitError`].
    type VerifyError: std::error::Error + From<Self::CommitError>;

    /// Creates a commitment to a message and embeds it into the provided
    /// container (`self`) by mutating it and returning commitment proof.
    ///
    /// Implementations must error with a dedicated error type enumerating
    /// commitment procedure mistakes.
    fn embed_commit(
        &mut self,
        msg: &Msg,
    ) -> Result<Self::Proof, Self::CommitError>;

    /// Verifies commitment with commitment proof against the message.
    ///
    /// Default implementation reconstructs original container with the
    /// [`EmbedCommitProof::restore_original_container`] method and repeats
    /// [`Self::embed_commit`] procedure checking that the resulting proof and
    /// commitment matches the provided `self` and `proof`.
    ///
    /// Errors if the provided commitment can't be created, i.e. the
    /// [`Self::embed_commit`] procedure for the original container, restored
    /// from the proof and current container, can't be performed. This means
    /// that the verification has failed and the commitment and proof are
    /// invalid. The function returns error in this case (ano not simply
    /// `false`) since this usually means the software error in managing
    /// container and proof data, or selection of a different commitment
    /// protocol parameters comparing to the ones used during commitment
    /// creation. In all these cases we'd like to provide devs with more
    /// information for debugging.
    ///
    /// The proper way of using the function in a well-debugged software should
    /// be `if commitment.verify(...).expect("proof managing system") { .. }`.
    /// However if the proofs are provided by some sort of user/network input
    /// from an untrusted party, a proper form would be
    /// `if commitment.verify(...).unwrap_or(false) { .. }`.
    #[inline]
    fn verify(
        &self,
        msg: &Msg,
        proof: Self::Proof,
    ) -> Result<bool, Self::VerifyError>
    where
        Self: VerifyEq,
        Self::Proof: VerifyEq,
    {
        let mut container_prime = proof.restore_original_container(self)?;
        let proof_prime = container_prime.embed_commit(msg)?;
        Ok(proof_prime.verify_eq(&proof) && self.verify_eq(&container_prime))
    }

    /// Phantom method used to add `Protocol` generic parameter to the trait.
    ///
    /// # Panics
    ///
    /// Always panics when called.
    #[doc(hidden)]
    fn _phantom(_: Protocol) {
        unimplemented!(
            "EmbedCommitVerify::_phantom is a marker method which must not be \
             used"
        )
    }
}

/// Helpers for writing test functions working with embed-commit-verify scheme.
#[cfg(test)]
pub(crate) mod test_helpers {
    use core::fmt::Debug;
    use core::hash::Hash;
    use std::collections::HashSet;

    use bitcoin_hashes::sha256::Midstate;

    use super::*;
    use crate::{ConvolveCommit, ConvolveCommitProof};

    pub enum TestProtocol {}
    impl CommitmentProtocol for TestProtocol {
        const HASH_TAG_MIDSTATE: Option<Midstate> = Some(Midstate([0u8; 32]));
    }

    pub const SUPPLEMENT: [u8; 32] = [0xFFu8; 32];

    /// Runs round-trip of commitment-embed-verify for a given set of messages
    /// and provided container.
    pub fn embed_commit_verify_suite<Msg, Container>(
        messages: Vec<Msg>,
        container: Container,
    ) where
        Msg: AsRef<[u8]> + CommitEncode + Eq + Clone,
        Container:
            EmbedCommitVerify<Msg, TestProtocol> + Eq + Hash + Debug + Clone,
        Container::Proof: Clone,
    {
        messages.iter().fold(
            HashSet::<Container>::with_capacity(messages.len()),
            |mut acc, msg| {
                let mut commitment = container.clone();
                let proof = commitment.embed_commit(msg).unwrap();

                // Commitments MUST be deterministic: the same message must
                // always produce the same commitment
                (1..10).for_each(|_| {
                    let mut commitment_prime = container.clone();
                    commitment_prime.embed_commit(msg).unwrap();
                    assert_eq!(commitment_prime, commitment);
                });

                // Testing verification
                assert!(commitment.clone().verify(msg, proof.clone()).unwrap());

                messages.iter().for_each(|m| {
                    // Testing that commitment verification succeeds only
                    // for the original message and fails for the rest
                    assert_eq!(
                        commitment.clone().verify(m, proof.clone()).unwrap(),
                        m == msg
                    );
                });

                acc.iter().for_each(|cmt| {
                    // Testing that verification against other commitments
                    // returns `false`
                    assert!(!cmt.clone().verify(msg, proof.clone()).unwrap());
                });

                // Detecting collision: each message should produce a unique
                // commitment even if the same container is used
                assert!(acc.insert(commitment));

                acc
            },
        );
    }

    /// Runs round-trip of commitment-embed-verify for a given set of messages
    /// and provided container.
    pub fn convolve_commit_verify_suite<Msg, Source>(
        messages: Vec<Msg>,
        container: Source,
    ) where
        Msg: AsRef<[u8]> + CommitEncode + Eq + Clone,
        Source: ConvolveCommit<Msg, [u8; 32], TestProtocol>
            + VerifyEq
            + Eq
            + Hash
            + Debug
            + Clone,
        Source::Commitment: Clone + Debug + Hash + VerifyEq + Eq,
        [u8; 32]:
            ConvolveCommitProof<Msg, Source, TestProtocol, Suppl = [u8; 32]>,
    {
        messages.iter().fold(
            HashSet::<Source::Commitment>::with_capacity(messages.len()),
            |mut acc, msg| {
                let (commitment, _) =
                    container.convolve_commit(&SUPPLEMENT, msg).unwrap();

                // Commitments MUST be deterministic: the same message must
                // always produce the same commitment
                (1..10).for_each(|_| {
                    let (commitment_prime, _) =
                        container.convolve_commit(&SUPPLEMENT, msg).unwrap();
                    assert_eq!(commitment_prime, commitment);
                });

                // Testing verification
                assert!(SUPPLEMENT.verify(msg, commitment.clone()).unwrap());

                messages.iter().for_each(|m| {
                    // Testing that commitment verification succeeds only
                    // for the original message and fails for the rest
                    assert_eq!(
                        SUPPLEMENT.verify(m, commitment.clone()).unwrap(),
                        m == msg
                    );
                });

                acc.iter().for_each(|commitment| {
                    // Testing that verification against other commitments
                    // returns `false`
                    assert!(!SUPPLEMENT
                        .verify(msg, commitment.clone())
                        .unwrap());
                });

                // Detecting collision: each message should produce a unique
                // commitment even if the same container is used
                assert!(acc.insert(commitment));

                acc
            },
        );
    }
}

#[cfg(test)]
mod test {
    use core::fmt::Debug;

    use bitcoin_hashes::{sha256, Hash, HashEngine};

    use super::test_helpers::*;
    use super::*;
    use crate::test_helpers::gen_messages;
    use crate::{ConvolveCommit, ConvolveCommitProof};

    #[derive(Clone, PartialEq, Eq, Debug, Hash, Error, Display)]
    #[display("error")]
    struct Error;

    #[derive(Clone, PartialEq, Eq, Debug, Hash)]
    struct DummyVec(Vec<u8>);

    #[derive(Clone, PartialEq, Eq, Debug, Hash)]
    struct DummyProof(Vec<u8>);

    impl<T> EmbedCommitProof<T, DummyVec, TestProtocol> for DummyProof
    where
        T: AsRef<[u8]> + Clone + CommitEncode,
    {
        fn restore_original_container(
            &self,
            _: &DummyVec,
        ) -> Result<DummyVec, Error> {
            Ok(DummyVec(self.0.clone()))
        }
    }

    impl<T> EmbedCommitVerify<T, TestProtocol> for DummyVec
    where
        T: AsRef<[u8]> + Clone + CommitEncode,
    {
        type Proof = DummyProof;
        type CommitError = Error;
        type VerifyError = Error;

        fn embed_commit(
            &mut self,
            msg: &T,
        ) -> Result<Self::Proof, Self::CommitError> {
            let proof = self.0.clone();
            let result = &mut self.0;
            result.extend(msg.as_ref());
            Ok(DummyProof(proof))
        }
    }

    impl<T> ConvolveCommit<T, [u8; 32], TestProtocol> for DummyVec
    where
        T: AsRef<[u8]> + Clone + CommitEncode,
    {
        type Commitment = sha256::Hash;
        type CommitError = Error;

        fn convolve_commit(
            &self,
            supplement: &[u8; 32],
            msg: &T,
        ) -> Result<(Self::Commitment, [u8; 32]), Self::CommitError> {
            let mut engine = sha256::Hash::engine();
            engine.input(TestProtocol::HASH_TAG_MIDSTATE.unwrap().as_ref());
            engine.input(supplement);
            engine.input(msg.as_ref());
            Ok((sha256::Hash::from_engine(engine), *supplement))
        }
    }

    impl<T> ConvolveCommitProof<T, DummyVec, TestProtocol> for [u8; 32]
    where
        T: AsRef<[u8]> + Clone + CommitEncode,
    {
        type Suppl = [u8; 32];

        fn restore_original(&self, _: &sha256::Hash) -> DummyVec {
            DummyVec(vec![])
        }

        fn extract_supplement(&self) -> &Self::Suppl { self }
    }

    #[test]
    fn test_embed_commit() {
        embed_commit_verify_suite::<Vec<u8>, DummyVec>(
            gen_messages(),
            DummyVec(vec![]),
        );
    }

    #[test]
    fn test_convolve_commit() {
        convolve_commit_verify_suite::<Vec<u8>, DummyVec>(
            gen_messages(),
            DummyVec(vec![0xC0; 15]),
        );
    }
}
