// LNP/BP client-side-validation library implementig respective LNPBP
// specifications & standards (LNPBP-7, 8, 9, 42)
//
// Written in 2019-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Library providing primitives for cryptographic commit-verify schemes used in
//! client-side-validation

#![recursion_limit = "256"]
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
#![allow(clippy::if_same_then_else, clippy::branches_sharing_code)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate bitcoin_hashes;
#[cfg(feature = "serde")]
extern crate serde_crate as serde;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_with;

pub mod commit_encode;
pub mod commit_verify;
mod digests;
pub mod multi_commit;
mod slice32;
pub mod tagged_hash;

#[doc(hidden)]
pub use commit_encode::{
    merklize, CommitConceal, CommitEncode, ConsensusCommit,
    ConsensusMerkleCommit, MerkleSource, ToMerkleSource,
};
#[doc(hidden)]
pub use commit_verify::{CommitVerify, EmbedCommitVerify, TryCommitVerify};
#[doc(hidden)]
pub use multi_commit::{Message, MultiCommitBlock, MultiCommitItem};
pub use slice32::Slice32;
#[doc(hidden)]
pub use tagged_hash::TaggedHash;
