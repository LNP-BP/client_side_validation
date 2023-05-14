// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
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

//! Encoding and data preparation for commitment procedures in
//! client-side-validation as defined by [LNPBP-9] standard.
//!
//! Client-side-validation commitment process requires special encoding of
//! the data. While [`strict_encoding`] is the main standard for atomic data
//! types in client-side-validation world and should be used during internal
//! protocol-specific data validation, commitments may require processes of
//! merklization arrays of data items, or hiding confidential parts of the
//! data via hashing, pedersen commitments and so on. Thus, additionally to
//! strict encoding, a set of different encodings and data convolution and
//! hiding procedures are defined in `commit_verify` library. This includes:
//! - **merklization** procedure, operating special types of tagged hashes and
//!   committing to the depth of each node;
//! - **conceal** procedure, making data confidential (transforming types into
//!   confidential versions).
//!
//! [`CommitEncode`] is the main trait which should be implemented for all data
//! types participating in client-side-validation. It takes [`io::Write`]
//! encoder and serializes into it data which corresponds to the exact
//! commitment. These data mus be concealed, if needed, merkelized etc. The
//! encoder is usually a hash function of specific type, which may be keyed with
//! a tag.
//!
//! Main patterns of [`CommitEncode`] implementation can be automatically
//! applied to a type by using [`amplify::strategy`] adaptor. These patterns
//! include:
//! - [`strategies::IntoU8`], which converts the type into U8 using `Into` trait
//!   and serializes it.
//! - [`strategies::IntoInner`], which converts the type into inner type using
//!   `Wrapper` trait and serializes it.
//! - [`strategies::Strict`], which serializes the type into the hasher using
//!   [`strict_encoding::StrictEncode`] implementation for the type.
//! - [`strategies::ConcealStrict`] does the same, but runs [`Conceal::conceal`]
//!   on the self first, and serializes the result using strict encoding.
//! - [`strategies::Id`] can apply to types implementing [`CommitmentId`]. It
//!   computes a single id for the type and then serializes it into the hasher.
//! - [`strategies::Merklize`] can apply to types implementing
//!   [`super::merkle::MerkleLeaves`]. It merkelizes data provided by this trait
//!   and serializes merkle root into the hasher. [`CommitmentId`] should be
//!   implemented for types which has external identifiers
//!
//! [LNPBP-9]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0009.md

use std::io;

use crate::id::CommitmentId;
use crate::Conceal;

/// Prepares the data to the *consensus commit* procedure by first running
/// necessary conceal and merklization procedures, and them performing strict
/// encoding for the resulted data.
pub trait CommitEncode {
    /// Encodes the data for the commitment by writing them directly into a
    /// [`io::Write`] writer instance
    fn commit_encode(&self, e: &mut impl io::Write);
}

/// Convenience macro for commit-encoding list of the data
#[macro_export]
macro_rules! commit_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commit_encode(&mut $encoder);
            )+CommitId
            len
        }
    }
}

/// Marker trait defining specific encoding strategy which should be used for
/// automatic implementation of [`CommitEncode`].
pub trait CommitStrategy {
    /// Specific strategy. List of supported strategies:
    /// - [`strategies::IntoU8`]
    /// - [`strategies::IntoInner`]
    /// - [`strategies::Strict`]
    /// - [`strategies::ConcealStrict`]
    /// - [`strategies::Id`]
    /// - [`strategies::Merklize`]
    type Strategy;
}

/// Strategies simplifying implementation of [`CommitEncode`] trait.
///
/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod strategies {
    use amplify::confinement::Confined;
    use amplify::num::apfloat::ieee;
    use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
    use amplify::{Bytes32, Holder, Wrapper};
    use strict_encoding::{StrictEncode, StrictWriter};

    use super::*;
    use crate::merkle::{MerkleLeaves, MerkleNode};

    /// Used only internally for blank implementation on reference types.
    #[doc(hidden)]
    pub enum AsRef {}

    /// Commits to the value by converting it into `u8` type. Useful for enum
    /// types.
    ///
    /// Can apply only to types implementing `Into<u8>`.
    pub enum IntoU8 {}

    /// Commits to the value by converting it into inner type. Useful for
    /// newtypes.
    ///
    /// Can apply only to types implementing [`Wrapper`].
    pub enum IntoInner {}

    /// Commits to the value by running strict *encoding procedure* on the raw
    /// data without any pre-processing.
    ///
    /// Should not be used for array types (require manual [`CommitEncode`]
    /// implementation involving merklization) or data which may contain
    /// confidential or sensitive information (in such case use
    /// [`ConcealStrict`]).
    ///
    /// Can apply only to types implementing [`StrictEncode`] trait.
    pub enum Strict {}

    /// Commits to the value data by first converting them into confidential
    /// version (*concealing*) by running [`Conceal::conceal`]
    /// first and returning its result serialized with strict encoding
    /// rules.
    ///
    /// Can apply only to types implementing [`Conceal`] trait, where
    /// [`Conceal::Concealed`] type must also implement [`StrictEncode`] trait.
    pub enum ConcealStrict {}

    /// Commits to the value via commitment id of the type, which is serialized
    /// into the hasher.
    ///
    /// Can apply only to types implementing [`CommitmentId`] trait.
    pub enum Id {}

    /// Commits to the value by merklizing data provided by [`MerkleLeaves`]
    /// implementation and serializes merkle root into the hasher.
    ///
    /// Can apply only to types implementing [`MerkleLeaves`] trait.
    pub enum Merklize<const MERKLE_ROOT_TAG: u128> {}

    impl<'a, T> CommitEncode for Holder<&'a T, IntoU8>
    where T: Copy + Into<u8>
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            let raw = **self.as_type();
            e.write_all(&[raw.into()]).ok();
        }
    }

    impl<'a, T> CommitEncode for Holder<&'a T, AsRef>
    where T: CommitEncode
    {
        fn commit_encode(&self, e: &mut impl io::Write) { self.as_type().commit_encode(e); }
    }

    impl<'a, T> CommitEncode for Holder<&'a T, IntoInner>
    where
        T: Wrapper,
        T::Inner: CommitEncode,
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            self.as_type().as_inner().commit_encode(e);
        }
    }

    impl<'a, T> CommitEncode for Holder<&'a T, Strict>
    where T: StrictEncode
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            let w = StrictWriter::with(u32::MAX as usize, e);
            self.as_type().strict_encode(w).ok();
        }
    }

    impl<'a, T> CommitEncode for Holder<&'a T, ConcealStrict>
    where
        T: Conceal,
        T::Concealed: StrictEncode,
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            let w = StrictWriter::with(u32::MAX as usize, e);
            self.as_type().conceal().strict_encode(w).ok();
        }
    }
    impl<'a, T> CommitEncode for Holder<&'a T, Id>
    where
        T: CommitmentId,
        T::Id: Into<[u8; 32]>,
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            e.write_all(&self.as_type().commitment_id().into()).ok();
        }
    }

    impl<'a, T, const MERKLE_ROOT_TAG: u128> CommitEncode for Holder<&'a T, Merklize<MERKLE_ROOT_TAG>>
    where T: MerkleLeaves
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            MerkleNode::merklize(MERKLE_ROOT_TAG.to_be_bytes(), *self.as_type()).commit_encode(e);
        }
    }

    impl<T> CommitEncode for T
    where
        T: CommitStrategy,
        for<'a> Holder<&'a T, T::Strategy>: CommitEncode,
    {
        fn commit_encode(&self, e: &mut impl io::Write) { Holder::new(self).commit_encode(e) }
    }

    impl CommitStrategy for u8 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u16 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u24 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u32 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u64 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u128 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u256 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u512 {
        type Strategy = Strict;
    }
    impl CommitStrategy for u1024 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i8 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i16 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i32 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i64 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i128 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i256 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i512 {
        type Strategy = Strict;
    }
    impl CommitStrategy for i1024 {
        type Strategy = Strict;
    }

    impl CommitStrategy for ieee::Half {
        type Strategy = Strict;
    }
    impl CommitStrategy for ieee::Single {
        type Strategy = Strict;
    }
    impl CommitStrategy for ieee::Double {
        type Strategy = Strict;
    }
    impl CommitStrategy for ieee::X87DoubleExtended {
        type Strategy = Strict;
    }
    impl CommitStrategy for ieee::Quad {
        type Strategy = Strict;
    }
    impl CommitStrategy for ieee::Oct {
        type Strategy = Strict;
    }

    impl CommitStrategy for Bytes32 {
        type Strategy = IntoInner;
    }

    impl<T> CommitStrategy for Box<T>
    where T: CommitStrategy
    {
        type Strategy = T::Strategy;
    }
    impl<T> CommitStrategy for Option<T>
    where T: CommitStrategy
    {
        type Strategy = T::Strategy;
    }
    impl<const MIN: usize, const MAX: usize> CommitStrategy for Confined<Vec<u8>, MIN, MAX> {
        type Strategy = Strict;
    }

    impl<T> CommitStrategy for &T
    where T: CommitEncode
    {
        type Strategy = AsRef;
    }
}

impl CommitEncode for [u8; 32] {
    fn commit_encode(&self, e: &mut impl io::Write) { e.write_all(self).ok(); }
}
