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

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "strict_encoding"), no_std)]

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
//!   opened), however this is not a part of the specification, and we should
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

/// Trait for proof-of-publication medium on which the seals are defined,
/// closed, verified and which can be used for convenience operations related to
/// seals:
/// * finding out the seal status
/// * publishing witness information
/// * get some identifier on the exact place of the witness publication
/// * check validity of the witness publication identifier
///
/// All these operations are medium-specific; for the same single-use-seal type
/// they may differ when are applied to different proof of publication mediums.
///
/// To read more on proof-of-publication please check
/// <https://petertodd.org/2014/setting-the-record-proof-of-publication>
pub trait SingleUseSeal:
    Clone + Debug + Display + StrictDumb + StrictEncode + StrictDecode
{
    /// Message type that is supported by the current single-use-seal.
    type Message: Copy + Eq;

    type PubWitness: PublishedWitness<Self> + StrictDumb + StrictEncode + StrictDecode;

    type CliWitness: ClientSideWitness<Seal = Self> + StrictDumb + StrictEncode + StrictDecode;

    fn is_included(&self, message: Self::Message, witness: &SealWitness<Self>) -> bool;
}

pub trait ClientSideWitness: Eq {
    /// Client-side witness is specific to just one type of single-use seals,
    /// provided as an associated type.
    type Seal: SingleUseSeal;
    /// Proof which is passed from the client-side witness to the public-side
    /// witness during single-use seal validation.
    type Proof;
    type Error: Clone + Error;

    fn convolve_commit(
        &self,
        msg: <Self::Seal as SingleUseSeal>::Message,
    ) -> Result<Self::Proof, Self::Error>;

    fn merge(&mut self, other: Self) -> Result<(), impl Error>
    where Self: Sized;
}

#[derive(Copy, Clone, Debug, Default)]
pub struct NoWitness<Seal: SingleUseSeal>(PhantomData<Seal>);

impl<Seal: SingleUseSeal> PartialEq for NoWitness<Seal> {
    fn eq(&self, _: &Self) -> bool { true }
}
impl<Seal: SingleUseSeal> Eq for NoWitness<Seal> {}

impl<Seal: SingleUseSeal> ClientSideWitness for NoWitness<Seal> {
    type Seal = Seal;
    type Proof = Seal::Message;
    type Error = Infallible;

    fn convolve_commit(&self, msg: Seal::Message) -> Result<Self::Proof, Self::Error> { Ok(msg) }

    fn merge(&mut self, _: Self) -> Result<(), impl Error>
    where Self: Sized {
        Ok::<_, Infallible>(())
    }
}

/// Public witness can be used by multiple types of single-use seals, hence it
/// has the seal type as a generic parameter.
pub trait PublishedWitness<Seal: SingleUseSeal> {
    /// Publication id that may be used for referencing publication of
    /// witness data in the medium. By default, set `()`, so [`SingleUseSeal`]
    /// may not implement publication id and related functions.
    type PubId: Copy + Ord + Debug + Display;
    type Error: Clone + Error;

    fn pub_id(&self) -> Self::PubId;
    fn verify_commitment(
        &self,
        proof: <Seal::CliWitness as ClientSideWitness>::Proof,
    ) -> Result<(), Self::Error>;
}

/// Seal closing witness.
#[derive(Clone, Copy)]
#[cfg_attr(
    feature = "strict_encoding",
    derive(StrictType, StrictDumb, StrictEncode, StrictDecode),
    strict_type(lib = "SingleUseSeals")
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
    pub published: Seal::PubWitness,
    pub client: Seal::CliWitness,
    #[cfg_attr(feature = "serde", serde(skip))]
    #[cfg_attr(feature = "strict_encoding", strict_type(skip))]
    _phantom: PhantomData<Seal>,
}

impl<Seal> SealWitness<Seal>
where Seal: SingleUseSeal
{
    pub fn new(published: Seal::PubWitness, client: Seal::CliWitness) -> Self {
        Self {
            published,
            client,
            _phantom: PhantomData,
        }
    }

    pub fn verify_seal_closing(
        &self,
        seal: impl Borrow<Seal>,
        message: Seal::Message,
    ) -> Result<(), SealError<Seal>> {
        self.verify_seals_closing([seal], message)
    }

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
                .ok_or(SealError::NotIncluded(seal.borrow().clone(), self.published.pub_id()))?;
        }
        // ensure that published witness contains the commitment to the
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

#[derive(Clone)]
pub enum SealError<Seal: SingleUseSeal> {
    NotIncluded(Seal, <Seal::PubWitness as PublishedWitness<Seal>>::PubId),
    Published(<Seal::PubWitness as PublishedWitness<Seal>>::Error),
    Client(<Seal::CliWitness as ClientSideWitness>::Error),
}

impl<Seal: SingleUseSeal> Debug for SealError<Seal> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SealError::NotIncluded(seal, pub_id) => f
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
            SealError::NotIncluded(seal, pub_id) => {
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
            SealError::NotIncluded(..) => None,
            SealError::Published(e) => Some(e),
            SealError::Client(e) => Some(e),
        }
    }
}
