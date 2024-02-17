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

use std::hash::Hash;

use amplify::confinement::{Collection, Confined, U64 as U64MAX};
use amplify::Bytes32;
use sha2::Sha256;
use strict_encoding::{StreamWriter, StrictDumb, StrictEncode, StrictType};
use strict_types::typesys::TypeFqn;

use crate::{Conceal, DigestExt, MerkleHash, MerkleLeaves, LIB_NAME_COMMIT_VERIFY};

const COMMIT_MAX_LEN: usize = U64MAX;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CommitStep {
    Serialized(TypeFqn),
    Collection,
    Hashed(TypeFqn),
    Merklized(TypeFqn),
    Concealed(TypeFqn),
}

#[derive(Clone, Debug)]
pub struct CommitEngine {
    finished: bool,
    hasher: Sha256,
    layout: Vec<CommitStep>,
}

fn commitment_fqn<T: StrictType>() -> TypeFqn {
    TypeFqn::with(
        libname!(T::STRICT_LIB_NAME),
        T::strict_name().expect("commit encoder can commit only to named types"),
    )
}

impl CommitEngine {
    pub fn new(tag: &'static str) -> Self {
        Self {
            finished: false,
            hasher: Sha256::from_tag(tag),
            layout: vec![],
        }
    }

    fn inner_commit_to<T: StrictEncode, const MAX_LEN: usize>(&mut self, value: &T) {
        debug_assert!(!self.finished);
        let writer = StreamWriter::new::<MAX_LEN>(&mut self.hasher);
        let ok = value.strict_write(writer).is_ok();
        debug_assert!(ok);
    }

    pub fn commit_to_serialized<T: StrictEncode>(&mut self, value: &T) {
        let fqn = commitment_fqn::<T>();
        debug_assert!(
            Some(&fqn.name) != MerkleHash::strict_name().as_ref() ||
                fqn.lib.as_str() != MerkleHash::STRICT_LIB_NAME,
            "do not use commit_to_serialized for merklized collections, use commit_to_merkle \
             instead"
        );
        debug_assert!(
            Some(&fqn.name) != StrictHash::strict_name().as_ref() ||
                fqn.lib.as_str() != StrictHash::STRICT_LIB_NAME,
            "do not use commit_to_serialized for StrictHash types, use commit_to_hash instead"
        );
        self.layout.push(CommitStep::Serialized(fqn));

        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&value);
    }

    pub fn commit_to_hash<T: CommitEncode<CommitmentId = StrictHash> + StrictType>(
        &mut self,
        value: T,
    ) {
        let fqn = commitment_fqn::<T>();
        self.layout.push(CommitStep::Hashed(fqn));

        self.inner_commit_to::<_, 32>(&value.commit_id());
    }

    pub fn commit_to_merkle<T: MerkleLeaves>(&mut self, value: &T)
    where T::Leaf: StrictType {
        let fqn = commitment_fqn::<T::Leaf>();
        self.layout.push(CommitStep::Merklized(fqn));

        let root = MerkleHash::merklize(value);
        self.inner_commit_to::<_, 32>(&root);
    }

    pub fn commit_to_concealed<T: Conceal>(&mut self, value: &T)
    where
        T: StrictType,
        T::Concealed: StrictEncode,
    {
        let fqn = commitment_fqn::<T>();
        self.layout.push(CommitStep::Concealed(fqn));

        let concealed = value.conceal();
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&concealed);
    }

    pub fn commit_to_collection<C, const MIN: usize, const MAX: usize>(
        &mut self,
        collection: &Confined<C, MIN, MAX>,
    ) where
        C: Collection,
        Confined<C, MIN, MAX>: StrictEncode,
    {
        self.layout.push(CommitStep::Collection);
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&collection);
    }

    pub fn as_layout(&mut self) -> &[CommitStep] {
        self.finished = true;
        self.layout.as_ref()
    }

    pub fn into_layout(self) -> Vec<CommitStep> { self.layout }

    pub fn set_finished(&mut self) { self.finished = true; }

    pub fn finish(self) -> Sha256 { self.hasher }

    pub fn finish_layout(self) -> (Sha256, Vec<CommitStep>) { (self.hasher, self.layout) }
}

/// Prepares the data to the *consensus commit* procedure by first running
/// necessary conceal and merklization procedures, and them performing strict
/// encoding for the resulted data.
pub trait CommitEncode {
    /// Type of the resulting commitment.
    type CommitmentId: CommitmentId;

    /// Encodes the data for the commitment by writing them directly into a
    /// [`io::Write`] writer instance
    fn commit_encode(&self, e: &mut CommitEngine);
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CommitmentLayout {
    ty: TypeFqn,
    tag: &'static str,
    fields: Vec<CommitStep>,
}

pub trait CommitmentId: Copy + Ord + From<Sha256> + StrictType {
    const TAG: &'static str;
}

/// High-level API used in client-side validation for producing a single
/// commitment to the data, which includes running all necessary procedures like
/// concealment with [`crate::Conceal`], merklization, strict encoding,
/// wrapped into [`CommitEncode`], followed by the actual commitment to its
/// output.
///
/// The trait is separate from the `CommitEncode` to prevent custom
/// implementation of its methods, since `CommitId` can't be manually
/// implemented for any type since it has a generic blanket implementation.
pub trait CommitId: CommitEncode {
    #[doc = hidden]
    fn commit(&self) -> CommitEngine;

    fn commitment_layout(&self) -> CommitmentLayout;

    /// Performs commitment to client-side-validated data
    fn commit_id(&self) -> Self::CommitmentId;
}

impl<T: CommitEncode> CommitId for T {
    fn commit(&self) -> CommitEngine {
        let mut engine = CommitEngine::new(T::CommitmentId::TAG);
        self.commit_encode(&mut engine);
        engine.set_finished();
        engine
    }

    fn commitment_layout(&self) -> CommitmentLayout {
        let fields = self.commit().into_layout();
        CommitmentLayout {
            ty: TypeFqn::with(
                libname!(Self::CommitmentId::STRICT_LIB_NAME),
                Self::CommitmentId::strict_name()
                    .expect("commitment types must have explicit type name"),
            ),
            tag: T::CommitmentId::TAG,
            fields,
        }
    }

    fn commit_id(&self) -> Self::CommitmentId { self.commit().finish().into() }
}

#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictDumb, strict_encoding::StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct StrictHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for StrictHash {
    const TAG: &'static str = "urn:ubideco:strict-types:value-hash#2024-02-10";
}

impl From<Sha256> for StrictHash {
    fn from(hash: Sha256) -> Self { hash.finish().into() }
}
