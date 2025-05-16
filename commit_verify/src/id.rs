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

/// Type of the collection participating in a commitment id creation.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CommitColType {
    /// A vector-type collection (always correspond to a confined variant of
    /// [`Vec`]).
    List,
    /// A set of unique sorted elements (always correspond to a confined variant
    /// of [`BTreeSet`]).
    Set,
    /// A map of unique sorted keys to values (always correspond to a confined
    /// variant of [`BTreeMap`]).
    Map {
        /// A fully qualified strict type name for the keys.
        key: TypeFqn,
    },
}

/// Step of the commitment id creation.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum CommitStep {
    /// Serialization with [`CommitEngine::commit_to_serialized`].
    Serialized(TypeFqn),

    /// Serialization with either
    /// - [`CommitEngine::commit_to_linear_list`],
    /// - [`CommitEngine::commit_to_linear_set`],
    /// - [`CommitEngine::commit_to_linear_map`].
    ///
    /// A specific type of serialization depends on the first field
    /// ([`CommitColType`]).
    Collection(CommitColType, Sizing, TypeFqn),

    /// Serialization with [`CommitEngine::commit_to_hash`].
    Hashed(TypeFqn),

    /// Serialization with [`CommitEngine::commit_to_merkle`].
    Merklized(TypeFqn),

    /// Serialization with [`CommitEngine::commit_to_concealed`].
    Concealed(TypeFqn),
}

/// A helper engine used in computing commitment ids.
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
    /// Initialize the engine using a type-specific tag string.
    ///
    /// The tag should be in a form of a valid URN, ending with a fragment
    /// specifying the date of the tag, or other form of versioning.
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

    /// Add a commitment to a strict-encoded value.
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

    /// Add a commitment to a strict-encoded optional value.
    pub fn commit_to_option<T: StrictEncode + StrictDumb>(&mut self, value: &Option<T>) {
        let fqn = commitment_fqn::<T>();
        self.layout
            .push(CommitStep::Serialized(fqn))
            .expect("too many fields for commitment");

        self.inner_commit_to::<_, COMMIT_MAX_LEN>(&value);
    }

    /// Add a commitment to a value which supports [`StrictHash`]ing.
    pub fn commit_to_hash<T: CommitEncode<CommitmentId = StrictHash> + StrictType>(
        &mut self,
        value: &T,
    ) {
        let fqn = commitment_fqn::<T>();
        self.layout
            .push(CommitStep::Hashed(fqn))
            .expect("too many fields for commitment");

        self.inner_commit_to::<_, 32>(&value.commit_id());
    }

    /// Add a commitment to a merklized collection.
    ///
    /// The collection must implement [`MerkleLeaves`] trait.
    pub fn commit_to_merkle<T: MerkleLeaves>(&mut self, value: &T)
    where T::Leaf: StrictType {
        let fqn = commitment_fqn::<T::Leaf>();
        self.layout
            .push(CommitStep::Merklized(fqn))
            .expect("too many fields for commitment");

        let root = MerkleHash::merklize(value);
        self.inner_commit_to::<_, 32>(&root);
    }

    /// Add a commitment to a type which supports [`Conceal`] procedure (hiding
    /// some of its data).
    ///
    /// First, the conceal procedure is called for the `value`, and then the
    /// resulting data are serialized using strict encoding.
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

    /// Add a commitment to a vector collection.
    ///
    /// Does not use merklization and encodes each element as strict encoding
    /// binary data right in to the hasher.
    ///
    /// Additionally to all elements, commits to the length of the collection
    /// and minimal and maximal dimensions of the confinement.
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

    /// Add a commitment to a set collection.
    ///
    /// Does not use merklization and encodes each element as strict encoding
    /// binary data right in to the hasher.
    ///
    /// Additionally to all elements, commits to the length of the collection
    /// and minimal and maximal dimensions of the confinement.
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

    /// Add a commitment to a mapped collection.
    ///
    /// Does not use merklization and encodes each element as strict encoding
    /// binary data right in to the hasher.
    ///
    /// Additionally to all keys and values, commits to the length of the
    /// collection and minimal and maximal dimensions of the confinement.
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

    /// Get a reference for the underlying sequence of commit steps.
    pub fn as_layout(&mut self) -> &[CommitStep] {
        self.finished = true;
        self.layout.as_ref()
    }

    /// Convert into the underlying sequence of commit steps.
    pub fn into_layout(self) -> TinyVec<CommitStep> { self.layout }

    /// Mark the procedure as completed, preventing any further data from being
    /// added.
    pub fn set_finished(&mut self) { self.finished = true; }

    /// Complete the commitment returning the resulting hash.
    pub fn finish(self) -> Sha256 { self.hasher }

    /// Complete the commitment returning the resulting hash and the description
    /// of all commitment steps performed during the procedure.
    pub fn finish_layout(self) -> (Sha256, TinyVec<CommitStep>) { (self.hasher, self.layout) }
}

/// A trait for types supporting commit-encode procedure.
///
/// The procedure is used to generate a cryptographic deterministic commitment
/// to data encoded in a binary form.
///
/// Later the commitment can be used to produce [`CommitmentId`] (which does a
/// tagged hash of the commitment).
pub trait CommitEncode {
    /// Type of the resulting commitment.
    type CommitmentId: CommitmentId;

    /// Encodes the data for the commitment by writing them directly into a
    /// [`std::io::Write`] writer instance
    fn commit_encode(&self, e: &mut CommitEngine);
}

/// The description of the commitment layout used in production of
/// [`CommitmentId`] (or other users of [`CommitEncode`]).
///
/// The layout description is useful in producing provably correct documentation
/// of the commitment process for a specific type. For instance, this library
/// uses it to generate a description of commitments in [Vesper] language.
///
/// [Vesper]: https://vesper-lang.org
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

/// A definition of a resulting commitment type, which represent a unique
/// identifier of the underlying data.
pub trait CommitmentId: Copy + Ord + From<Sha256> + StrictType {
    /// A tag string used in initializing SHA256 hasher.
    const TAG: &'static str;
}

/// A trait adding blanked implementation generating [`CommitmentLayout`] for
/// any type implementing [`CommitEncode`].
pub trait CommitmentLayout: CommitEncode {
    /// Generate a descriptive commitment layout, which includes a description
    /// of each encoded field and the used hashing strategies.
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
/// concealment with [`Conceal`], merklization, strict encoding,
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

/// A commitment to the strict encoded-representation of any data.
///
/// It is created using tagged hash with [`StrictHash::TAG`] value.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
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
