// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]
#![allow(clippy::branches_sharing_code)]

//! Library providing primitives for cryptographic commit-verify schemes used in
//! client-side-validation
//!
//! Library covers [LNPBP-9] and [LNPBP-81] standards.
//!
//! [LNPBP-9]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0009.md
//! [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md

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

pub mod api;
pub mod commit_encode;
mod digests;
pub mod merkle;
pub mod multi_commit;
pub mod tagged_hash;

#[doc(hidden)]
pub use api::{CommitVerify, EmbedCommitVerify, TryCommitVerify};
#[doc(hidden)]
pub use commit_encode::{CommitConceal, CommitEncode, ConsensusCommit};
pub use merkle::{
    merklize, ConsensusMerkleCommit, MerkleSource, ToMerkleSource,
};
#[doc(hidden)]
pub use multi_commit::{Message, MultiCommitBlock, MultiCommitItem};
#[doc(hidden)]
pub use tagged_hash::TaggedHash;
