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
    Self: Sized + Eq,
    Container: EmbedCommitVerify<Msg, Protocol>,
    Msg: CommitEncode,
    Protocol: CommitmentProtocol,
{
    /// Restores original container before the commitment from the proof data
    /// and a container containing embedded commitment.
    fn restore_original_container(
        &self,
        commit_container: &Container,
    ) -> Result<Container, Container::CommitError>;
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
/// # use secp256k1zkp::Secp256k1;
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
    ) -> Result<bool, Self::CommitError>
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

/// Trait for *convolve-commit-verify scheme*, where some data structure (named
/// *container*) may commit to existing *message* using *supplement* and
/// producing final *commitment* value. The commitment can't be use to restore
/// original message, however the fact of the commitment may be
/// deterministically *verified* when the message and the proof are *revealed*.
///
/// To use *convolve-commit-verify scheme* one needs to implement this trait for
/// a data structure acting as a container for a specific commitment under
/// certain protocol, specified as generic parameters. The container type must
/// specify commitment types as associated type [`Self::Commitment`]. The
/// commitment type in certain cases may be equal to the original container
/// type; when the commitment represents internally modified container.
///
/// The difference between *convolve-commit-verify* and *embed-commit-verify*
/// schemes is in the fact that unlike embed-commit, convolve-commit does not
/// produces a proof external to the commitment, but instead requires additional
/// immutable supplement information which is not a part of the container
/// converted into the commitment. As an example one may consider procedures of
/// homomorphic public key tweaking with the hash of the message, which is
/// a case of embed-commit procedure, producing original public key as a proof
/// and tweaked public key as a commitment -- and procedure of pay-to-contract
/// commitment in scriptPubkey of a transaction output, which requires
/// additional information about the public key or scripts present in the
/// scriptPubkey only in hashed form (this is *supplement*), and producing just
/// a modified version of the scriptPubkey (commitment) without any additional
/// proof data.
///
/// Operations with *convolve-commit-verify scheme* may be represented in form
/// of `ConvolveCommit: (Container, Supplement, Message) -> Commitment` (see
/// [`Self::convolve_commit`] and
/// `Verify: (Container', Supplement, Message) -> bool` (see [`Self::verify`]).
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
/// # use secp256k1zkp::Secp256k1;
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
pub trait ConvolveCommitVerify<Msg, Suppl, Protocol>
where
    Self: Sized,
    Msg: CommitEncode,
    Protocol: CommitmentProtocol,
{
    /// Commitment type produced as a result of [`Self::convolve_commit`]
    /// procedure.
    type Commitment: Sized + Eq;

    /// Error type that may be reported during [`Self::convolve_commit`]
    /// procedure. It may also be returned from [`Self::verify`] in case the
    /// proof data are invalid and the commitment can't be re-created.
    type CommitError: std::error::Error;

    /// Takes the `supplement` to unparse the content of this container (`self`)
    /// ("convolves" these two data together) and uses them to produce a final
    /// [`Self::Commitment`] to the message `msg`.
    ///
    /// Implementations must error with a dedicated error type enumerating
    /// commitment procedure mistakes.
    fn convolve_commit(
        &self,
        supplement: &Suppl,
        msg: &Msg,
    ) -> Result<Self::Commitment, Self::CommitError>;

    /// Verifies commitment with commitment proof against the message.
    ///
    /// Default implementation repeats [`Self::convolve_commit`] procedure
    /// checking that the resulting commitment matches the provided one as
    /// the `commitment` parameter.
    ///
    /// Errors if the provided commitment can't be created, i.e. the
    /// [`Self::convolve_commit`] procedure for the original container, restored
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
    fn verify(
        &self,
        supplement: &Suppl,
        msg: &Msg,
        commitment: Self::Commitment,
    ) -> Result<bool, Self::CommitError>
    where
        Self::Commitment: VerifyEq,
    {
        let commitment_prime = self.convolve_commit(supplement, msg)?;
        Ok(commitment_prime.verify_eq(&commitment))
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
pub mod test_helpers {
    use core::fmt::Debug;
    use core::hash::Hash;
    use std::collections::HashSet;

    use bitcoin_hashes::sha256::Midstate;

    use super::*;

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
    pub fn convolve_commit_verify_suite<Msg, Container>(
        messages: Vec<Msg>,
        container: Container,
    ) where
        Msg: AsRef<[u8]> + CommitEncode + Eq + Clone,
        Container: ConvolveCommitVerify<Msg, [u8; 32], TestProtocol>
            + VerifyEq
            + Hash
            + Debug
            + Clone,
        Container::Commitment: Clone + Debug + Hash + VerifyEq,
    {
        messages.iter().fold(
            HashSet::<Container::Commitment>::with_capacity(messages.len()),
            |mut acc, msg| {
                let commitment =
                    container.convolve_commit(&SUPPLEMENT, msg).unwrap();

                // Commitments MUST be deterministic: the same message must
                // always produce the same commitment
                (1..10).for_each(|_| {
                    let commitment_prime =
                        container.convolve_commit(&SUPPLEMENT, msg).unwrap();
                    assert_eq!(commitment_prime, commitment);
                });

                // Testing verification
                assert!(container
                    .clone()
                    .verify(&SUPPLEMENT, msg, commitment.clone())
                    .unwrap());

                messages.iter().for_each(|m| {
                    // Testing that commitment verification succeeds only
                    // for the original message and fails for the rest
                    assert_eq!(
                        container
                            .clone()
                            .verify(&SUPPLEMENT, m, commitment.clone())
                            .unwrap(),
                        m == msg
                    );
                });

                acc.iter().for_each(|commitment| {
                    // Testing that verification against other commitments
                    // returns `false`
                    assert!(!container
                        .clone()
                        .verify(&SUPPLEMENT, msg, commitment.clone())
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
    use crate::commit_verify::test_helpers::gen_messages;

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

    impl<T> ConvolveCommitVerify<T, [u8; 32], TestProtocol> for DummyVec
    where
        T: AsRef<[u8]> + Clone + CommitEncode,
    {
        type Commitment = sha256::Hash;
        type CommitError = Error;

        fn convolve_commit(
            &self,
            supplement: &[u8; 32],
            msg: &T,
        ) -> Result<Self::Commitment, Self::CommitError> {
            let mut engine = sha256::Hash::engine();
            engine.input(TestProtocol::HASH_TAG_MIDSTATE.unwrap().as_ref());
            engine.input(supplement);
            engine.input(msg.as_ref());
            Ok(sha256::Hash::from_engine(engine))
        }
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
