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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::{self, Display, Formatter};
use std::hash::Hash;

use amplify::confinement::{Confined, TinyVec, U64 as U64MAX};
use amplify::Bytes32;
use sha2::Sha256;
use strict_encoding::{Sizing, StreamWriter, StrictDumb, StrictEncode, StrictType};
use strict_types::typesys::TypeFqn;

use crate::{Conceal, DigestExt, MerkleHash, MerkleLeaves, LIB_NAME_COMMIT_VERIFY};

const COMMIT_MAX_LEN: usize = U64MAX;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CommitColType {
    List,
    Set,
    Map { key: TypeFqn },
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CommitStep {
    Serialized(TypeFqn),
    Collection(CommitColType, Sizing, TypeFqn),
    Hashed(TypeFqn),
    Merklized(TypeFqn),
    Concealed(TypeFqn),
}

#[derive(Clone, Debug)]
pub struct CommitEngine {
    finished: bool,
    hasher: Sha256,
    layout: TinyVec<CommitStep>,
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
            layout: empty!(),
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
        self.layout
            .push(CommitStep::Serialized(fqn))
            .expect("too many fields for commitment");

        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&value);
    }

    pub fn commit_to_option<T: StrictEncode + StrictDumb>(&mut self, value: &Option<T>) {
        let fqn = commitment_fqn::<T>();
        self.layout
            .push(CommitStep::Serialized(fqn))
            .expect("too many fields for commitment");

        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&value);
    }

    pub fn commit_to_hash<T: CommitEncode<CommitmentId = StrictHash> + StrictType>(
        &mut self,
        value: T,
    ) {
        let fqn = commitment_fqn::<T>();
        self.layout
            .push(CommitStep::Hashed(fqn))
            .expect("too many fields for commitment");

        self.inner_commit_to::<_, 32>(&value.commit_id());
    }

    pub fn commit_to_merkle<T: MerkleLeaves>(&mut self, value: &T)
    where T::Leaf: StrictType {
        let fqn = commitment_fqn::<T::Leaf>();
        self.layout
            .push(CommitStep::Merklized(fqn))
            .expect("too many fields for commitment");

        let root = MerkleHash::merklize(value);
        self.inner_commit_to::<_, 32>(&root);
    }

    pub fn commit_to_concealed<T>(&mut self, value: &T)
    where
        T: Conceal + StrictType,
        T::Concealed: StrictEncode,
    {
        let fqn = commitment_fqn::<T>();
        self.layout
            .push(CommitStep::Concealed(fqn))
            .expect("too many fields for commitment");

        let concealed = value.conceal();
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&concealed);
    }

    pub fn commit_to_linear_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
        collection: &Confined<Vec<T>, MIN, MAX>,
    ) where
        T: StrictEncode + StrictDumb,
    {
        let fqn = commitment_fqn::<T>();
        let step =
            CommitStep::Collection(CommitColType::List, Sizing::new(MIN as u64, MAX as u64), fqn);
        self.layout
            .push(step)
            .expect("too many fields for commitment");
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&collection);
    }

    pub fn commit_to_linear_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
        collection: &Confined<BTreeSet<T>, MIN, MAX>,
    ) where
        T: Ord + StrictEncode + StrictDumb,
    {
        let fqn = commitment_fqn::<T>();
        let step =
            CommitStep::Collection(CommitColType::Set, Sizing::new(MIN as u64, MAX as u64), fqn);
        self.layout
            .push(step)
            .expect("too many fields for commitment");
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&collection);
    }

    pub fn commit_to_linear_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
        collection: &Confined<BTreeMap<K, V>, MIN, MAX>,
    ) where
        K: Ord + Hash + StrictEncode + StrictDumb,
        V: StrictEncode + StrictDumb,
    {
        let key_fqn = commitment_fqn::<K>();
        let val_fqn = commitment_fqn::<V>();
        let step = CommitStep::Collection(
            CommitColType::Map { key: key_fqn },
            Sizing::new(MIN as u64, MAX as u64),
            val_fqn,
        );
        self.layout
            .push(step)
            .expect("too many fields for commitment");
        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&collection);
    }

    pub fn as_layout(&mut self) -> &[CommitStep] {
        self.finished = true;
        self.layout.as_ref()
    }

    pub fn into_layout(self) -> TinyVec<CommitStep> { self.layout }

    pub fn set_finished(&mut self) { self.finished = true; }

    pub fn finish(self) -> Sha256 { self.hasher }

    pub fn finish_layout(self) -> (Sha256, TinyVec<CommitStep>) { (self.hasher, self.layout) }
}

/// Prepares the data to the *consensus commit* procedure by first running
/// necessary conceal and merklization procedures, and them performing strict
/// encoding for the resulted data.
pub trait CommitEncode {
    /// Type of the resulting commitment.
    type CommitmentId: CommitmentId;

    /// Encodes the data for the commitment by writing them directly into a
    /// [`std::io::Write`] writer instance
    fn commit_encode(&self, e: &mut CommitEngine);
}

#[derive(Getters, Clone, Eq, PartialEq, Hash, Debug)]
pub struct CommitLayout {
    idty: TypeFqn,
    #[getter(as_copy)]
    tag: &'static str,
    fields: TinyVec<CommitStep>,
}

impl Display for CommitLayout {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.to_vesper().display(), f)
    }
}

pub trait CommitmentId: Copy + Ord + From<Sha256> + StrictType {
    const TAG: &'static str;
}

pub trait CommitmentLayout: CommitEncode {
    fn commitment_layout() -> CommitLayout;
}

impl<T> CommitmentLayout for T
where T: CommitEncode + StrictDumb
{
    fn commitment_layout() -> CommitLayout {
        let dumb = Self::strict_dumb();
        let fields = dumb.commit().into_layout();
        CommitLayout {
            idty: TypeFqn::with(
                libname!(Self::CommitmentId::STRICT_LIB_NAME),
                Self::CommitmentId::strict_name()
                    .expect("commitment types must have explicit type name"),
            ),
            tag: T::CommitmentId::TAG,
            fields,
        }
    }
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
    #[doc(hidden)]
    fn commit(&self) -> CommitEngine;

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
