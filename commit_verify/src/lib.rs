// LNP/BP Core Library implementing LNPBP specifications & standards
// Written in 2020 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the MIT License
// along with this software.
// If not, see <https://opensource.org/licenses/MIT>.

#![recursion_limit = "256"]
// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    //missing_docs
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

mod commit_encode;
mod commit_verify;
mod digests;
pub mod lnpbp4;
mod slice32;
pub mod tagged_hash;

pub use commit_encode::{
    commit_strategy, merklize, CommitConceal, CommitEncode,
    CommitEncodeWithStrategy, ConsensusCommit, ConsensusMerkleCommit,
    MerkleSource, ToMerkleSource,
};
pub use commit_verify::{
    test_helpers, CommitVerify, EmbedCommitVerify, TryCommitVerify,
};
pub use slice32::Slice32;
pub use tagged_hash::TaggedHash;
