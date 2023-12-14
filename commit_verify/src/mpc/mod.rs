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

//! Multi-protocol commitments according to [LNPBP-4] standard.
//!
//! [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

mod atoms;
mod tree;
mod block;

pub use atoms::{
    Commitment, Leaf, Message, MessageMap, MultiSource, ProtocolId, MPC_MINIMAL_DEPTH,
};
pub use block::{InvalidProof, LeafNotKnown, MergeError, MerkleBlock, MerkleProof};
pub use tree::{Error, MerkleTree};

#[deprecated(since = "0.10.6", note = "use commit_verify::merkle::MerkleBuoy instead")]
pub use crate::merkle::MerkleBuoy;

pub const MERKLE_LNPBP4_TAG: u128 = u128::from_le_bytes(*b"urn:lnpbp:lnpbp4");

/// Marker trait for variates of LNPBP-4 commitment proofs, which differ by the
/// amount of concealed information.
pub trait Proof:
    strict_encoding::StrictEncode
    + strict_encoding::StrictDecode
    + crate::CommitEncode
    + Eq
    + std::fmt::Debug
{
}
