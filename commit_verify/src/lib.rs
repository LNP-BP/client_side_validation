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

#[macro_use]
extern crate amplify_derive;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate bitcoin_hashes;

mod commit_encode;
mod commit_verify;
mod digests;
pub mod lnpbp4;
pub mod tagged_hash;

pub use commit_encode::{
    commit_strategy, merklize, CommitConceal, CommitEncode,
    CommitEncodeWithStrategy, ConsensusCommit, ConsensusMerkleCommit,
    MerkleSource, ToMerkleSource,
};
pub use commit_verify::{CommitVerify, EmbedCommitVerify, TryCommitVerify};
pub use tagged_hash::TaggedHash;
