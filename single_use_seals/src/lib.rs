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

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

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

use core::borrow::Borrow;

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
pub trait Seal: Sized {
    /// Single-use seal parameters, which allow to differentiate alternative
    /// forms of single-use seals from each other.
    type Params;

    /// Seal parameters which the type commits to.
    const PARAMS: Self::Params;

    /// Associated type for the witness produced by the single-use-seal close
    /// procedure
    type Witness: SealWitness<Self>;

    /// Message type that is supported by the current single-use-seal
    type Message;

    /// Publication id that may be used for referencing publication of
    /// witness data in the medium. By default, set `()`, so [`SealProtocol`]
    /// may not implement publication id and related functions
    type PublicationId;
}

/// Seal witness which can verify seal or multiple seals.
pub trait SealWitness<S: Seal<Witness = Self>> {
    /// Message type that is supported by the current single-use-seal
    type Message;

    /// Error type that contains reasons of medium access failure
    type Error: std::error::Error;

    /// Verifies that the seal was indeed closed over the message with the
    /// provided seal closure witness.
    fn verify_seal(&self, seal: impl Borrow<S>, msg: &Self::Message) -> Result<(), Self::Error>;

    /// Performs batch verification of the seals.
    ///
    /// Default implementation iterates through the seals and calls
    /// [`Self::verify_seal`] for each of them, returning `false` on first
    /// failure (not verifying the rest of seals).
    fn verify_many_seals(
        &self,
        seals: impl IntoIterator<Item = impl Borrow<S>>,
        msg: &Self::Message,
    ) -> Result<(), Self::Error> {
        for seal in seals {
            self.verify_seal(seal, msg)?;
        }
        Ok(())
    }
}
