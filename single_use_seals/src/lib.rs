// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems
// (InDCS), Switzerland. Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

#![deny(missing_docs)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "strict_encoding"), no_std)]

//! # Single-use-seals
//!
//! Set of traits that allow to implement Peter's Todd **single-use seal**
//! paradigm. Information in this file partially contains extracts from Peter's
//! works listed in the "Further reading" section.
//!
//! ## Single-use-seal definition
//!
//! Analogous to the real-world, physical, single-use-seals used to secure
//! shipping containers, a single-use-seal primitive is a unique object that can
//! be closed over a message exactly once. In short, a single-use-seal is an
//! abstract mechanism to prevent double-spends.
//!
//! A single-use-seal implementation supports two fundamental operations:
//! * `Close(l,m) → w` — Close seal l over a message m, producing a witness `w`.
//! * `Verify(l,w,m) → bool` — Verify that the seal l was closed over message
//!   `m`.
//!
//! A single-use-seal implementation is secure if it is impossible for an
//! attacker to cause the Verify function to return true for two distinct
//! messages m1, m2, when applied to the same seal (it is acceptable, although
//! non-ideal, for there to exist multiple witnesses for the same seal/message
//! pair).
//!
//! Practical single-use-seal implementations will also obviously require some
//! way of generating new single-use-seals:
//! * `Gen(p)→l` — Generate a new seal based on some seal definition data `p`.
//!
//! ## Terminology
//!
//! **Single-use-seal**: a commitment to commit to some (potentially unknown)
//!   message. The first commitment (i.e., single-use-seal) must be a
//!   well-defined (i.e., fully specified and unequally identifiable
//!   in some space, like in time/place or within a given formal informational
//!   system).
//! **Closing of a single-use-seal over message**: fulfilment of the first
//!   commitment: creation of the actual commitment to some message in a form
//!   unequally defined by the seal.
//! **Witness**: data produced with closing of a single use seal which is
//!   required and sufficient for an independent party to verify that the seal
//!   was indeed closed over a given message (i.e.б the commitment to the
//!   message had been created according to the seal definition).
//!
//! NB: It is important to note that while it is possible to deterministically
//!   define was a given seal closed, it yet may be not possible to find out
//!   if the seal is open; i.e., seal status may be either "closed over message"
//!   or "unknown". Some specific implementations of single-use-seals may define
//!   a procedure to deterministically prove that a given seal is not closed
//!   (i.e., opened), however, this is not a part of the specification, and we
//!   should not rely on the existence of such a possibility in all cases.
//!
//! ## Trait structure
//!
//! The main trait is [`SingleUseSeal`], which should be implemented for a
//! single-use seal data type. It references component types for seal witness
//! [`SealWitness`], which are a _published witness_ [`PublishedWitness`] and a
//! _client-side witness_ [`ClientSideWitness`].
//!
//! ## Sample implementation
//!
//! Examples of implementations can be found in the [`bp::seals`] module of
//! `bp-core` crate.
//!
//! ## Further reading
//!
//! * Peter Todd. Preventing Consensus Fraud with Commitments and
//!   Single-Use-Seals.
//!   <https://petertodd.org/2016/commitments-and-single-use-seals>.
//! * Peter Todd. Scalable Semi-Trustless Asset Transfer via Single-Use-Seals
//!   and Proof-of-Publication. 1. Single-Use-Seal Definition.
//!   <https://petertodd.org/2017/scalable-single-use-seal-asset-transfer>
//!
//! [`bp::seals`]: https://github.com/BP-WG/bp-core/tree/master/seals

#[cfg(feature = "strict_encoding")]
#[macro_use]
extern crate strict_encoding;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

use core::borrow::Borrow;
use core::convert::Infallible;
use core::error::Error;
use core::fmt::{self, Debug, Display, Formatter};
use core::marker::PhantomData;

#[cfg(feature = "strict_encoding")]
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

#[cfg(not(feature = "strict_encoding"))]
trait StrictDumb {}
#[cfg(not(feature = "strict_encoding"))]
impl<T> StrictDumb for T {}

#[cfg(not(feature = "strict_encoding"))]
trait StrictEncode {}
#[cfg(not(feature = "strict_encoding"))]
impl<T> StrictEncode for T {}

#[cfg(not(feature = "strict_encoding"))]
trait StrictDecode {}
#[cfg(not(feature = "strict_encoding"))]
impl<T> StrictDecode for T {}

/// Strict type library name for single-use seals.
pub const LIB_NAME_SEALS: &str = "SingleUseSeals";

/// Trait for the types implementing single-use seal protocol, composing all
/// their components (seal definition, message, and seal closing withness)
/// together, and implementing the logic of the protocol-specific verification
/// of the seal closing over the message (see [`Self::is_included`]).
pub trait SingleUseSeal:
    Clone + Debug + Display + StrictDumb + StrictEncode + StrictDecode
{
    /// Message type that is supported by the current single-use-seal.
    type Message: Copy + Eq;

    /// A type for the published part of the seal closing witness.
    type PubWitness: PublishedWitness<Self> + StrictDumb + StrictEncode + StrictDecode;

    /// A type for the client-side part of the seal closing witness.
    type CliWitness: ClientSideWitness<Seal = Self> + StrictDumb + StrictEncode + StrictDecode;

    /// Check that the seal was closing over a message is a part of the witness.
    ///
    /// Some public or client-side witnesses must be checked to include specific
    /// seal closing information. This method ensures that this is the case.
    ///
    /// NB: This method does not perform the seal closing verification; for this
    /// purpose use [`SealWitness::verify_seal_closing`] and
    /// [`SealWitness::verify_seals_closing`].
    fn is_included(&self, message: Self::Message, witness: &SealWitness<Self>) -> bool;
}

/// A client-side part of the seal closing witness [`SealWitness`].
///
/// A client-side witness is always specific to a particular [`SingleUseSeal`]
/// protocol, hence it specifies single-use seal implementation as an associated
/// type [`Self::Seal`].
pub trait ClientSideWitness: Eq {
    /// Client-side witness is specific to just one type of single-use seals,
    /// provided as an associated type.
    type Seal: SingleUseSeal;

    /// Proof which is passed from the client-side witness to the public-side
    /// witness during single-use seal validation.
    type Proof;

    /// Error type returned by the [`Self::convolve_commit`] operation.
    type Error: Clone + Error;

    /// Procedure that convolves the message with the client-side data kept in
    /// the client-side part of the seal closing witness. This produces
    /// [`Self::Proof`], which is lately verified by
    /// [`SealWitness::verify_seal_closing`] and
    /// [`SealWitness::verify_seals_closing`] against the published part of the
    /// witness.
    fn convolve_commit(
        &self,
        msg: <Self::Seal as SingleUseSeal>::Message,
    ) -> Result<Self::Proof, Self::Error>;

    /// Merge two compatible client-side witnesses together, or error in case of
    /// their incompatibility.
    ///
    /// Client-side witnesses may be split into different client-specific
    /// versions, for instance, by concealing some of the data which should be
    /// private and not known to the other users.
    /// This procedure allows combining information from multiple sources back.
    fn merge(&mut self, other: Self) -> Result<(), impl Error>
    where Self: Sized;
}

/// Some single-use seal protocols may not distinguish client-side seal closing
/// witness and have just the published one. To use [`SealWitness`] type in such
/// protocols, the [`SingleUseSeal`] must set its [`SingleUseSeal::CliWitness`]
/// to [`NoClientWitness`] type.
#[derive(Copy, Clone, Debug)]
pub struct NoClientWitness<Seal: SingleUseSeal>(PhantomData<Seal>);

impl<Seal: SingleUseSeal> PartialEq for NoClientWitness<Seal> {
    fn eq(&self, _: &Self) -> bool { true }
}
impl<Seal: SingleUseSeal> Eq for NoClientWitness<Seal> {}

impl<Seal: SingleUseSeal> ClientSideWitness for NoClientWitness<Seal> {
    type Seal = Seal;
    type Proof = Seal::Message;
    type Error = Infallible;

    fn convolve_commit(&self, msg: Seal::Message) -> Result<Self::Proof, Self::Error> { Ok(msg) }

    fn merge(&mut self, _: Self) -> Result<(), impl Error>
    where Self: Sized {
        Ok::<_, Infallible>(())
    }
}

impl<Seal: SingleUseSeal> NoClientWitness<Seal> {
    /// Constructs the object.
    pub fn new() -> Self { Self(PhantomData) }
}

impl<Seal: SingleUseSeal> Default for NoClientWitness<Seal> {
    fn default() -> Self { Self::new() }
}

#[cfg(feature = "strict_encoding")]
mod _strict_encoding_impls {
    use strict_encoding::{
        DecodeError, StrictProduct, StrictTuple, StrictType, TypedRead, TypedWrite,
    };

    use super::*;

    impl<Seal: SingleUseSeal> StrictType for NoClientWitness<Seal> {
        const STRICT_LIB_NAME: &'static str = LIB_NAME_SEALS;
    }
    impl<Seal: SingleUseSeal> StrictProduct for NoClientWitness<Seal> {}
    impl<Seal: SingleUseSeal> StrictTuple for NoClientWitness<Seal> {
        const FIELD_COUNT: u8 = 0;
    }
    impl<Seal: SingleUseSeal> StrictEncode for NoClientWitness<Seal> {
        fn strict_encode<W: TypedWrite>(&self, writer: W) -> std::io::Result<W> { Ok(writer) }
    }
    impl<Seal: SingleUseSeal> StrictDecode for NoClientWitness<Seal> {
        fn strict_decode(_reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            Ok(NoClientWitness::new())
        }
    }
}

/// A published part of the seal closing witness [`SealWitness`].
///
/// Published witness may be used by multiple implementations of single-use
/// seals ([`SingleUseSeal`]), hence it binds the specific seal type as a
/// generic parameter.
pub trait PublishedWitness<Seal: SingleUseSeal> {
    /// A unique id for the published part of the single-use seal closing
    /// witness.
    ///
    /// Publication id that may be used for referencing publication of
    /// witness data in the medium.
    type PubId: Copy + Ord + Debug + Display;

    /// Error type returned by [`Self::verify_commitment`].
    type Error: Clone + Error;

    /// Get the unique id of this witness publication.
    fn pub_id(&self) -> Self::PubId;

    /// Verify that the public witness commits to the message using a proof
    /// [`ClientSideWitness::Proof`], which is prepared by the client-side part
    /// of the seal closing witness and include the information about the
    /// message.
    fn verify_commitment(
        &self,
        proof: <Seal::CliWitness as ClientSideWitness>::Proof,
    ) -> Result<(), Self::Error>;
}

/// Seal closing witness, consisting of published and client-side parts.
///
/// The seal closing witness commits to the specific [`SingleUseSeal`] protocol
/// implementation via its `Seal` generic parameter.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(StrictType, StrictDumb, StrictEncode, StrictDecode),
    strict_type(lib = LIB_NAME_SEALS)
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(bound = "Seal::PubWitness: serde::Serialize + for<'d> serde::Deserialize<'d>, \
                   Seal::CliWitness: serde::Serialize + for<'d> serde::Deserialize<'d>")
)]
pub struct SealWitness<Seal>
where Seal: SingleUseSeal
{
    /// The published part of the single-use seal closing witness.
    pub published: Seal::PubWitness,
    /// The client-side part of the single-use seal closing witness.
    pub client: Seal::CliWitness,
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "strict_encoding", strict_type(skip))]
    _phantom: PhantomData<Seal>,
}

impl<Seal> SealWitness<Seal>
where Seal: SingleUseSeal
{
    /// Construct seal closing withness out of published and client-side
    /// components.
    pub fn new(published: Seal::PubWitness, client: Seal::CliWitness) -> Self {
        Self {
            published,
            client,
            _phantom: PhantomData,
        }
    }

    /// Verify that a single `seal` is correctly closed over the `message` using
    /// the current seal closing witness.
    ///
    /// This is the implementation of the single-use seals `verigy` procedure.
    ///
    /// If you have multiple seals closed over the same message, consider
    /// calling [`Self::verify_seals_closing`].
    pub fn verify_seal_closing(
        &self,
        seal: impl Borrow<Seal>,
        message: Seal::Message,
    ) -> Result<(), SealError<Seal>> {
        self.verify_seals_closing([seal], message)
    }

    /// Verify that all the seals from a set of `seals` are correctly closed
    /// over the single `message` using the current seal closing witness.
    ///
    /// This is the implementation of the single-use seals `verigy` procedure.
    ///
    /// If you have just a single seal, consider calling
    /// [`Self::verify_seal_closing`].
    pub fn verify_seals_closing(
        &self,
        seals: impl IntoIterator<Item = impl Borrow<Seal>>,
        message: Seal::Message,
    ) -> Result<(), SealError<Seal>> {
        // ensure that witness includes all seals
        for seal in seals {
            seal.borrow()
                .is_included(message, self)
                .then_some(())
                .ok_or(SealError::NotClosed(seal.borrow().clone(), self.published.pub_id()))?;
        }
        // ensure that the published witness contains the commitment to the
        // f(message), where `f` is defined in the client-side witness
        let f_msg = self
            .client
            .convolve_commit(message)
            .map_err(SealError::Client)?;
        self.published
            .verify_commitment(f_msg)
            .map_err(SealError::Published)
    }
}

/// Errors indicating cases of failed single-use seal verification with
/// [`SealWitness::verify_seal_closing`] and
/// [`SealWitness::verify_seals_closing`] procedures.
#[derive(Clone)]
pub enum SealError<Seal: SingleUseSeal> {
    /// The single-use seal was not closed over the provided message.
    NotClosed(Seal, <Seal::PubWitness as PublishedWitness<Seal>>::PubId),
    /// The provided proof of the seal closing is not valid for the published
    /// part of the seal closing witness.
    Published(<Seal::PubWitness as PublishedWitness<Seal>>::Error),
    /// The client part of the single-use seal doesn't match the provided seal
    /// definition or is unrelated to the message.
    Client(<Seal::CliWitness as ClientSideWitness>::Error),
}

impl<Seal: SingleUseSeal> Debug for SealError<Seal> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SealError::NotClosed(seal, pub_id) => f
                .debug_tuple("SealError::NotIncluded")
                .field(seal)
                .field(pub_id)
                .finish(),
            SealError::Published(err) => f.debug_tuple("SealError::Published").field(err).finish(),
            SealError::Client(err) => f.debug_tuple("SealError::Client(err").field(err).finish(),
        }
    }
}

impl<Seal: SingleUseSeal> Display for SealError<Seal> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SealError::NotClosed(seal, pub_id) => {
                write!(f, "seal {seal} is not included in the witness {pub_id}")
            }
            SealError::Published(err) => Display::fmt(err, f),
            SealError::Client(err) => Display::fmt(err, f),
        }
    }
}

impl<Seal: SingleUseSeal> Error for SealError<Seal>
where
    <<Seal as SingleUseSeal>::PubWitness as PublishedWitness<Seal>>::Error: 'static,
    <<Seal as SingleUseSeal>::CliWitness as ClientSideWitness>::Error: 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            SealError::NotClosed(..) => None,
            SealError::Published(e) => Some(e),
            SealError::Client(e) => Some(e),
        }
    }
}
