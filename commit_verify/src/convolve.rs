// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Convolved commitments (convolve-commit-verify scheme).

use crate::{CommitmentProtocol, VerifyEq};

/// Error during commitment verification
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub enum ConvolveVerifyError {
    /// commitment doesn't match the message.
    CommitmentMismatch,

    /// the message is invalid since a valid commitment to it can't be created.
    ImpossibleMessage,

    /// the proof is invalid and the commitment can't be verified.
    InvalidProof,
}

/// Proof type used by [`ConvolveCommit`] protocol.
pub trait ConvolveCommitProof<Msg, Source, Protocol>
where
    Self: Sized + VerifyEq,
    Source: ConvolveCommit<Msg, Self, Protocol>,
    Protocol: CommitmentProtocol,
{
    /// Supplement is a part of the proof data provided during commitment
    /// procedure.
    type Suppl;

    /// Restores the original source before the commitment from the supplement
    /// (the `self`) and commitment.
    fn restore_original(&self, commitment: &Source::Commitment) -> Source;

    /// Extract supplement from the proof.
    fn extract_supplement(&self) -> &Self::Suppl;

    /// Verifies commitment using proof (the `self`) against the message.
    ///
    /// Default implementation repeats [`ConvolveCommit::convolve_commit`]
    /// procedure, restoring the original value out of proof data, checking
    /// that the resulting commitment matches the provided one in the
    /// `commitment` parameter.
    ///
    /// # Errors
    ///
    /// Errors if the commitment doesn't pass the validation (see
    /// [`ConvolveVerifyError`] variants for the cases when this may happen).
    fn verify(
        &self,
        msg: &Msg,
        commitment: &Source::Commitment,
    ) -> Result<(), ConvolveVerifyError>
    where
        Self: VerifyEq,
    {
        let original = self.restore_original(commitment);
        let suppl = self.extract_supplement();
        let (commitment_prime, proof) = original
            .convolve_commit(suppl, msg)
            .map_err(|_| ConvolveVerifyError::ImpossibleMessage)?;
        if !self.verify_eq(&proof) {
            return Err(ConvolveVerifyError::InvalidProof);
        }
        if !commitment.verify_eq(&commitment_prime) {
            return Err(ConvolveVerifyError::CommitmentMismatch);
        }
        Ok(())
    }
}

/// Trait for *convolve-commit-verify scheme*, where some data structure (named
/// *container*) may commit to existing *message* using *supplement* and
/// producing final *commitment* value. The commitment can't be used to restore
/// original message, however the fact of the commitment may be
/// deterministically *verified* when the message and the supplement (now acting
/// as a *proof*) proof are *revealed*.
///
/// In other words, *convolve-commit* takes an object (`self`), a *supplement*,
/// convolves them in certain way together and than uses the result to produce a
/// commitment to a *message* and a *proof*:
/// - `self + supplement -> internal_repr`;
/// - `internal_repr + msg -> (commitment, proof)`.
/// Later on, a verifier presented with a message and the proof may do the
/// commitment verification in the following way:
/// `msg, proof, commitment -> bool`.
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
/// produce a proof external to the commitment, but instead requires additional
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
/// `Verify: (Container', Supplement, Message) -> bool` (see
/// [`ConvolveCommitProof::verify`]).
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
/// # use commit_verify::CommitmentProtocol;
///
/// // Uninstantiable type
/// pub enum Lnpbp6 {}
///
/// impl CommitmentProtocol for Lnpbp6 {}
///
/// // Protocol definition
/// pub enum Lnpbp1 {}
/// // ...
/// ```
pub trait ConvolveCommit<Msg, Proof, Protocol>
where
    Self: Sized,
    Proof: ConvolveCommitProof<Msg, Self, Protocol>,
    Protocol: CommitmentProtocol,
{
    /// Commitment type produced as a result of [`Self::convolve_commit`]
    /// procedure.
    type Commitment: Sized + VerifyEq;

    /// Error type that may be reported during [`Self::convolve_commit`]
    /// procedure. It may also be returned from [`ConvolveCommitProof::verify`]
    /// in case the proof data are invalid and the commitment can't be
    /// re-created.
    type CommitError: std::error::Error;

    /// Takes the `supplement` to unparse the content of this container (`self`)
    /// ("convolves" these two data together) and uses them to produce a final
    /// [`Self::Commitment`] to the message `msg`.
    ///
    /// Implementations must error with a dedicated error type enumerating
    /// commitment procedure mistakes.
    fn convolve_commit(
        &self,
        supplement: &Proof::Suppl,
        msg: &Msg,
    ) -> Result<(Self::Commitment, Proof), Self::CommitError>;

    /// Phantom method used to add `Protocol` generic parameter to the trait.
    ///
    /// # Panics
    ///
    /// Always panics when called.
    #[doc(hidden)]
    fn _phantom(_: Protocol) {
        unimplemented!("EmbedCommitVerify::_phantom is a marker method which must not be used")
    }
}
