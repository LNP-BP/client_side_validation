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
//
// The author of the code acknowledges significant input from Peter Todd,
// who is the author of single-use-seal concept and who spent a lot of his time
// to help to understanding single-use-seal concept and write the current
// implementation.

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! # Single-use-seals
//!
//! Set of traits that allow to implement Peter's Todd **single-use seal**
//! paradigm. Information in this file partially contains extracts from Peter's
//! works listed in "Further reading" section.
//!
//! ## Single-use-seal definition
//!
//! Analogous to the real-world, physical, single-use-seals used to secure
//! shipping containers, a single-use-seal primitive is a unique object that can
//! be closed over a message exactly once. In short, a single-use-seal is an
//! abstract mechanism to prevent double-spends.
//!
//! A single-use-seal implementation supports two fundamental operations:
//! * `Close(l,m) → w` — Close seal l over message m, producing a witness `w`.
//! * `Verify(l,w,m) → bool` — Verify that the seal l was closed over message
//! `m`.
//!
//! A single-use-seal implementation is secure if it is impossible for an
//! attacker to cause the Verify function to return true for two distinct
//! messages m1, m2, when applied to the same seal (it is acceptable, although
//! non-ideal, for there to exist multiple witnesses for the same seal/message
//! pair).
//!
//! Practical single-use-seal implementations will also obviously require some
//! way of generating new single-use-seals:
//! * `Gen(p)→l` — Generate a new seal basing on some seal definition data `p`.
//!
//! ## Terminology
//!
//! **Single-use-seal**: a commitment to commit to some (potentially unknown)
//!   message. The first commitment (i.e. single-use-seal) must be a
//!   well-defined (i.e. fully specified and unequally identifiable
//!   in some space, like in time/place or within a given formal informational
//!   system).
//! **Closing of a single-use-seal over message**: a fulfilment of the first
//!   commitment: creation of the actual commitment to some message in a form
//!   unequally defined by the seal.
//! **Witness**: data produced with closing of a single use seal which are
//!   required and sufficient for an independent party to verify that the seal
//!   was indeed closed over a given message (i.e. the commitment to the message
//!   had being created according to the seal definition).
//!
//! NB: It's important to note, that while its possible to deterministically
//!   define was a given seal closed it yet may be not possible to find out
//!   if the seal is open; i.e. seal status may be either "closed over message"
//!   or "unknown". Some specific implementations of single-use-seals may define
//!   procedure to deterministically prove that a given seal is not closed (i.e.
//!   opened), however this is not a part of the specification and we should
//!   not rely on the existence of such possibility in all cases.
//!
//! ## Trait structure
//!
//! The module defines trait [`SealProtocol`] that can be used for
//! implementation of single-use-seals with methods for seal close and
//! verification. A type implementing this trait operates only with messages
//! (which is represented by any type that implements `AsRef<[u8]>`,i.e. can be
//! represented as a sequence of bytes) and witnesses (which is represented by
//! an associated type [`SealProtocol::Witness`]). At the same time,
//! [`SealProtocol`] can't define seals by itself.
//!
//! Seal protocol operates with a *seal medium *: a proof of publication medium
//! on which the seals are defined.
//!
//! The module provides two options of implementing such medium: synchronous
//! [`SealProtocol`] and asynchronous `SealProtocolAsync`.
//!
//! ## Sample implementation
//!
//! Examples of implementations can be found in `bp::seals` module of `bp-core`
//! crate.
//!
//! ## Further reading
//!
//! * Peter Todd. Preventing Consensus Fraud with Commitments and
//!   Single-Use-Seals.
//!   <https://petertodd.org/2016/commitments-and-single-use-seals>.
//! * Peter Todd. Scalable Semi-Trustless Asset Transfer via Single-Use-Seals
//!   and Proof-of-Publication. 1. Single-Use-Seal Definition.
//!   <https://petertodd.org/2017/scalable-single-use-seal-asset-transfer>

#[macro_use]
extern crate amplify_derive;
#[cfg(feature = "async")]
#[macro_use]
extern crate async_trait;

/// Trait for proof-of-publication medium on which the seals are defined,
/// closed, verified and which can be used for convenience operations related to
/// seals:
/// * finding out the seal status
/// * publishing witness information
/// * get some identifier on the exact place of the witness publication
/// * check validity of the witness publication identifier
///
/// Since the medium may require network communications or extensive computing
/// involved (like in case with blockchain) there is a special asynchronous
/// version of the seal medium [`SealProtocolAsync`], which requires use of
/// `async` feature of this crate.
///
/// All these operations are medium-specific; for the same single-use-seal type
/// they may differ when are applied to different proof of publication mediums.
///
/// To read more on proof-of-publication please check
/// <https://petertodd.org/2014/setting-the-record-proof-of-publication>
pub trait SealProtocol<Seal> {
    /// Associated type for the witness produced by the single-use-seal close
    /// procedure
    type Witness;

    /// Message type that is supported by the current single-use-seal
    type Message;

    /// Publication id that may be used for referencing publication of
    /// witness data in the medium. By default set `()`, so [`SealProtocol`]
    /// may not implement  publication id and related functions
    type PublicationId;

    /// Error type that contains reasons of medium access failure
    type Error: std::error::Error;

    /// Checks the status for a given seal in proof-of-publication medium
    fn get_seal_status(&self, seal: &Seal) -> Result<SealStatus, Self::Error>;

    /// Publishes witness data to the medium. Function has default
    /// implementation doing nothing and returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    fn publish_witness(
        &mut self,
        _witness: &Self::Witness,
    ) -> Result<Self::PublicationId, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }

    /// Returns [`Self::PublicationId`] for a given witness, if any; the id is
    /// returned as an option. Function has default implementation doing
    /// nothing and just returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    fn get_witness_publication_id(
        &self,
        _witness: &Self::Witness,
    ) -> Result<Option<Self::PublicationId>, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }

    /// Validates whether a given publication id is present in the medium.
    /// Function has default implementation doing nothing and returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    fn validate_publication_id(
        &self,
        _publication_id: &Self::PublicationId,
    ) -> Result<bool, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }
}

/// Adds support for the seal close operation to [`SealProtocol`].
pub trait SealClose<Seal>: SealProtocol<Seal> {
    /// Closes seal over a message, producing *witness*.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    fn seal_close(
        &mut self,
        seal: &Seal,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>;

    /// Closes number of related seals over the same message, producing a single
    /// *witness*.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    fn seal_close_all<'seal>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>
    where
        Seal: 'seal;
}

/// Adds support to [`SealProtocol`] for merging seal close operation into an
/// existing witness data (closing some other seals).
pub trait SealCloseMerge<Seal>: SealProtocol<Seal> {
    /// Closes seal over a message, adding witness to some existing *witness*
    /// container.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    fn seal_close_merge(
        &mut self,
        seal: &Seal,
        over: &Self::Message,
        witness_proto: Self::Witness,
    ) -> Result<Self::Witness, Self::Error>;

    /// Closes number of related seals over the same message, adding witness to
    /// some existing *witness* container.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    fn seal_close_merge_all<'seal>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>
    where
        Seal: 'seal;
}

/// Adds support for the seal verify operation to [`SealProtocol`].
pub trait SealVerify<'seal, Seal>: SealProtocol<Seal>
where
    Seal: 'seal,
{
    /// Verifies that the seal was indeed closed over the message with the
    /// provided seal closure witness.
    fn verify(
        &self,
        seal: &'seal Seal,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error>;

    /// Performs batch verification of the seals. Default implementation
    /// iterates through the seals and calls [`Self::verify`] for each of them,
    /// returning `false` on first failure (not verifying the rest of seals).
    fn verify_batch(
        &self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error> {
        for seal in seals {
            if !self.verify(seal, msg, witness)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// Asynchronous version of the [`SealProtocol`] trait.
#[cfg(feature = "async")]
#[async_trait]
pub trait SealProtocolAsync<Seal>
where
    Seal: Sync + Send,
    Self: Send + Sync,
{
    /// Associated type for the witness produced by the single-use-seal close
    /// procedure
    type Witness: Sync + Send;

    /// Message type that is supported by the current single-use-seal
    type Message;

    /// Publication id that may be used for referencing publication of
    /// witness data in the medium. By default set `()`, so
    /// [`SealProtocolAsync`] may not implement  publication id and related
    /// functions
    type PublicationId: Sync;

    /// Error type that contains reasons of medium access failure
    type Error: std::error::Error;

    /// Checks the status for a given seal in proof-of-publication medium
    async fn get_seal_status_async(
        &self,
        seal: &Seal,
    ) -> Result<SealStatus, Self::Error>;

    /// Publishes witness data to the medium. Function has default
    /// implementation doing nothing and returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    async fn publish_witness_async(
        &mut self,
        _witness: &Self::Witness,
    ) -> Result<Self::PublicationId, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }

    /// Returns [`Self::PublicationId`] for a given witness, if any; the id is
    /// returned as an option. Function has default implementation doing
    /// nothing and just returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    async fn get_witness_publication_id_async(
        &self,
        _witness: &Self::Witness,
    ) -> Result<Option<Self::PublicationId>, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }

    /// Validates whether a given publication id is present in the medium.
    /// Function has default implementation doing nothing and returning
    /// [`SealMediumError::PublicationNotSupported`] error.
    async fn validate_publication_id_async(
        &self,
        _publication_id: &Self::PublicationId,
    ) -> Result<bool, SealMediumError<Self::Error>> {
        Err(SealMediumError::PublicationNotSupported)
    }
}

/// Adds support for the seal close operation to [`SealProtocolAsync`].
#[cfg(feature = "async")]
#[async_trait]
pub trait SealCloseAsync<Seal>: SealProtocolAsync<Seal>
where
    Seal: Sync + Send,
{
    /// Closes seal over a message, producing *witness*.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    async fn seal_close_async(
        &mut self,
        seal: &Seal,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>;

    /// Closes number of related seals over the same message, producing a single
    /// *witness*.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    async fn seal_close_all_async<'seal>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>
    where
        Seal: 'seal;
}

/// Adds support to [`SealProtocolAsync`] for merging seal close operation into
/// an existing witness data (closing some other seals).
#[cfg(feature = "async")]
#[async_trait]
pub trait SealCloseMergeAsync<Seal>: SealProtocolAsync<Seal>
where
    Seal: Sync + Send,
{
    /// Closes seal over a message, adding witness to some existing *witness*
    /// container.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    async fn seal_close_merge_async(
        &mut self,
        seal: &Seal,
        over: &Self::Message,
        witness_proto: Self::Witness,
    ) -> Result<Self::Witness, Self::Error>;

    /// Closes number of related seals over the same message, adding witness to
    /// some existing *witness* container.
    ///
    /// NB: Closing of the seal MUST not change the internal state of the
    /// seal itself; all the data produced by the process must be placed
    /// into the returned Witness type.
    ///
    /// The witness _is not_ published by this method to the seal medium.
    async fn seal_close_merge_all_async<'seal>(
        &mut self,
        seals: impl IntoIterator<Item = &'seal Seal>,
        over: &Self::Message,
    ) -> Result<Self::Witness, Self::Error>
    where
        Seal: 'seal;
}

/// Adds support for the seal verify operation to [`SealProtocolAsync`].
#[cfg(feature = "async")]
#[async_trait]
pub trait SealVerifyAsync<'seal, Seal>: SealProtocol<Seal>
where
    Seal: 'seal + Sync + Send,
{
    /// Verifies that the seal was indeed closed over the message with the
    /// provided seal closure witness.
    async fn verify_async(
        &self,
        seal: &'seal Seal,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error>;

    /// Performs batch verification of the seals. Default implementation
    /// iterates through the seals and calls [`Self::verify_async`] for each of
    /// them, returning `false` on first failure (not verifying the rest of
    /// seals).
    async fn verify_async_batch<I>(
        &self,
        seals: I,
        msg: &Self::Message,
        witness: &Self::Witness,
    ) -> Result<bool, Self::Error>
    where
        <Self as SealProtocol<Seal>>::Message: Sync,
        <Self as SealProtocol<Seal>>::Witness: Sync,
        I: IntoIterator<Item = &'seal Seal> + Send,
        I::IntoIter: Send,
    {
        for seal in seals {
            if !self.verify_async(seal, msg, witness).await? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
}

/// Single-use-seal status returned by [`SealProtocol::get_seal_status`] and
/// `SealProtocolAsync::get_seal_status` functions.
///
/// NB: It's important to note, that while its possible to deterministically
///   define was a given seal closed it yet may be not possible to find out
///   if the seal is open without provision of the message and witness; i.e.
///   seal status may be either "closed over message"
///   or "unknown". Some specific implementations of single-use-seals may define
///   procedure to deterministically prove that a given seal is not closed (i.e.
///   opened), however this is not a part of the specification and we should
///   not rely on the existence of such possibility in all cases.
#[derive(Clone, Copy, Debug, Display)]
#[display(Debug)]
#[repr(u8)]
pub enum SealStatus {
    /// It is unknown/undetermined whether the seal was closed
    Undefined = 0,

    /// The seal is closed
    Closed = 1,
}

/// Error returned by [`SealProtocol`] and `SealProtocolAsync` functions related
/// to work with publication id ([`SealProtocol::PublicationId`]). Required
/// since not all implementation of [`SealProtocol`] may define publication
/// identifier, and the traits provide default implementation for these
/// functions always returning [`SealMediumError::PublicationNotSupported`]. If
/// the implementation would like to provide custom implementation, it may embed
/// standard error related to [`SealProtocol`] operations within
/// [`SealMediumError::MediumAccessError`] case; the type of MediumAccessError
/// is defined through generic argument to [`SealMediumError`].
#[derive(Clone, Copy, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SealMediumError<E: std::error::Error> {
    /// Can't access the publication medium
    #[from]
    MediumAccessError(E),

    /// Publication id is not supported
    PublicationNotSupported,
}
