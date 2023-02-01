// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
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
//! - [`strategy::Strict`], which serializes the type into the hasher using
//!   [`strict_encode::StrictEncode`] implementation for the type.
//! - [`strategy::ConcealStrict`] does the same, but runs [`Conceal::conceal`]
//!   on the self first, and serializes the result using strict encoding.
//! - [`strategy::Id`] can apply to types implementing [`CommitId`]. It computes
//!   a single id for the type and then serializes it into the hasher.
//! - [`strategy::MerkleId`] can apply to types implementing [`ToMerkleSource`].
//!   It merkelizes data provided by this trait and serializes merkle root into
//!   the hasher.
//!
//! - [`CommitId`] should be implemented for types which has external
//!   identifiers
//!
//! [LNPBP-9]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0009.md

use std::io;

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
            )+
            len
        }
    }
}

/// Marker trait defining specific encoding strategy which should be used for
/// automatic implementation of [`CommitEncode`].
pub trait Strategy {
    /// Specific strategy. List of supported strategies:
    /// - [`strategies::Strict`]
    /// - [`strategies::ConcealStrict`]
    /// - [`strategies::Id`]
    /// - [`strategies::MerkleId`]
    type Strategy;
}

/// Strategies simplifying implementation of [`CommitEncode`] trait.
///
/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod strategies {
    use super::*;
    use crate::merkle::{MerkleLeafs, MerkleNode, MerkleRoot};

    /// Encodes by running strict *encoding procedure* on the raw data without
    /// any pre-processing.
    ///
    /// Should not be used for array types (require manual [`CommitEncode`]
    /// implementation involving merklization) or data which may contain
    /// confidential or sensitive information (in such case use
    /// [`ConcealStrict`]).
    ///
    /// Can apply only to types implementing [`StrictEncode`] trait.
    pub enum Strict {}

    /// Encodes data by first converting them into confidential version
    /// (*concealing*) by running [`CommitConceal::commit_conceal`] first and
    /// returning its result serialized with strict encoding rules.
    ///
    /// Can apply only to types implementing [`Conceal`] trait, where
    /// [`Conceal::Concealed`] type must also implement [`StrictEncode`] trait.
    pub enum ConcealStrict {}

    /// Computes a single id for the type and then serializes it into the
    /// hasher.
    ///
    /// Can apply only to types implementing [`CommitId`] trait.
    pub enum Id {}

    /// Merkelizes data provided by this trait and serializes merkle root into
    /// the hasher.
    ///
    /// Can apply only to types implementing [`MerkleLeafs`] trait.
    pub enum MerkleId<const MERKLE_ROOT_TAG: u128> {}

    impl<T, const MERKLE_ROOT_TAG: u128> CommitEncode
        for amplify::Holder<T, MerkleId<MERKLE_ROOT_TAG>>
    where
        T: MerkleLeafs,
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            let leafs = self.as_inner().merkle_leafs().map(MerkleNode::commit);
            MerkleRoot::merklize(MERKLE_ROOT_TAG, leafs).commit_encode(e);
        }
    }

    impl<T> CommitEncode for T
    where
        T: Strategy + Clone,
        amplify::Holder<T, <T as Strategy>::Strategy>: CommitEncode,
    {
        fn commit_encode(&self, e: &mut impl io::Write) {
            amplify::Holder::new(self.clone()).commit_encode(e)
        }
    }

    impl Strategy for u8 {
        type Strategy = Strict;
    }
    impl Strategy for u16 {
        type Strategy = Strict;
    }
    impl Strategy for u32 {
        type Strategy = Strict;
    }
    impl Strategy for u64 {
        type Strategy = Strict;
    }
    impl Strategy for u128 {
        type Strategy = Strict;
    }
    impl Strategy for i8 {
        type Strategy = Strict;
    }
    impl Strategy for i16 {
        type Strategy = Strict;
    }
    impl Strategy for i32 {
        type Strategy = Strict;
    }
    impl Strategy for i64 {
        type Strategy = Strict;
    }
    impl Strategy for i128 {
        type Strategy = Strict;
    }

    impl<T> Strategy for &T
    where
        T: Strategy,
    {
        type Strategy = T::Strategy;
    }
}
