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

use std::collections::BTreeSet;
use std::ops::SubAssign;

use amplify::confinement::Confined;
use amplify::num::{u256, u5};
use amplify::{Bytes32, Wrapper};
use sha2::Sha256;
use strict_encoding::StrictEncode;

use crate::digest::DigestExt;
use crate::{CommitId, CommitmentId, LIB_NAME_COMMIT_VERIFY};

/// Type of merkle node branching.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY, tags = repr, into_u8, try_from_u8)]
#[repr(u8)]
pub enum NodeBranching {
    /// Void node: virtual node with no leafs.
    ///
    /// Used when the total width of the three is not a power two.
    #[strict_type(dumb)]
    Void = 0x00,

    /// Node having just a single leaf, with the second branch being void.
    Single = 0x01,

    /// Node having two branches.
    Branch = 0x02,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, strategy = strict, id = MerkleHash)]
pub struct MerkleNode {
    pub branching: NodeBranching,
    pub depth: u8,
    pub width: u256,
    pub node1: MerkleHash,
    pub node2: MerkleHash,
}

impl MerkleNode {
    pub fn void(depth: impl Into<u8>, width: impl Into<u256>) -> Self {
        Self::with(NodeBranching::Void, depth, width, VIRTUAL_LEAF, VIRTUAL_LEAF)
    }

    pub fn single(depth: impl Into<u8>, width: impl Into<u256>, node: MerkleHash) -> Self {
        Self::with(NodeBranching::Single, depth, width, node, VIRTUAL_LEAF)
    }

    pub fn branches(
        depth: impl Into<u8>,
        width: impl Into<u256>,
        node1: MerkleHash,
        node2: MerkleHash,
    ) -> Self {
        Self::with(NodeBranching::Branch, depth, width, node1, node2)
    }

    fn with(
        branching: NodeBranching,
        depth: impl Into<u8>,
        width: impl Into<u256>,
        node1: MerkleHash,
        node2: MerkleHash,
    ) -> Self {
        Self {
            branching,
            depth: depth.into(),
            width: width.into(),
            node1,
            node2,
        }
    }
}

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(transparent))]
pub struct MerkleHash(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for MerkleHash {
    const TAG: &'static str = "urn:ubideco:merkle:node#2024-01-31";
}

impl From<Sha256> for MerkleHash {
    fn from(hash: Sha256) -> Self { hash.finish().into() }
}

const VIRTUAL_LEAF: MerkleHash = MerkleHash(Bytes32::from_array([0xFF; 32]));

impl MerkleHash {
    pub fn void(depth: impl Into<u8>, width: impl Into<u256>) -> Self {
        MerkleNode::void(depth, width).commit_id()
    }

    pub fn single(depth: impl Into<u8>, width: impl Into<u256>, node: MerkleHash) -> Self {
        MerkleNode::single(depth, width, node).commit_id()
    }

    pub fn branches(
        depth: impl Into<u8>,
        width: impl Into<u256>,
        node1: MerkleHash,
        node2: MerkleHash,
    ) -> Self {
        MerkleNode::branches(depth, width, node1, node2).commit_id()
    }
}

impl MerkleHash {
    /// Merklization procedure that uses tagged hashes with depth commitments
    /// according to [LNPBP-81] standard of client-side-validation merklization.
    ///
    /// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
    pub fn merklize(leaves: &impl MerkleLeaves) -> Self {
        let mut nodes = leaves.merkle_leaves().map(|leaf| leaf.commit_id());
        let base_width =
            u32::try_from(nodes.len()).expect("too many merkle leaves (more than 2^31)");
        if base_width == 1 {
            // If we have just one leaf, it's MerkleNode value is the root
            nodes.next().expect("length is 1")
        } else {
            Self::_merklize(nodes, u5::ZERO, base_width, base_width)
        }
    }

    fn _merklize(
        mut iter: impl ExactSizeIterator<Item = MerkleHash>,
        depth: u5,
        branch_width: u32,
        base_width: u32,
    ) -> Self {
        if branch_width <= 2 {
            match (iter.next(), iter.next()) {
                (None, None) => MerkleHash::void(depth, base_width),
                // Here, a single node means Merkle tree width non-equal to the power of 2, thus we
                // need to process it with a special encoding.
                (Some(branch), None) => MerkleHash::single(depth, base_width, branch),
                (Some(branch1), Some(branch2)) => {
                    MerkleHash::branches(depth, base_width, branch1, branch2)
                }
                (None, Some(_)) => unreachable!(),
            }
        } else {
            let div = branch_width / 2 + branch_width % 2;

            let slice = iter
                .by_ref()
                .take(div as usize)
                // Normally we should use `iter.by_ref().take(div)`, but currently
                // rust compilers is unable to parse recursion with generic types
                // TODO: Do this without allocation
                .collect::<Vec<_>>()
                .into_iter();
            let branch1 = Self::_merklize(slice, depth + 1, div, base_width);
            let branch2 = Self::_merklize(iter, depth + 1, branch_width - div, base_width);

            MerkleHash::branches(depth, base_width, branch1, branch2)
        }
    }
}

pub trait MerkleLeaves {
    type Leaf: CommitId<CommitmentId = MerkleHash>;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &Self::Leaf>;
}

impl<T, const MIN: usize> MerkleLeaves for Confined<Vec<T>, MIN, { u8::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

impl<T: Ord, const MIN: usize> MerkleLeaves for Confined<BTreeSet<T>, MIN, { u8::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

impl<T, const MIN: usize> MerkleLeaves for Confined<Vec<T>, MIN, { u16::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

impl<T: Ord, const MIN: usize> MerkleLeaves for Confined<BTreeSet<T>, MIN, { u16::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

impl<T, const MIN: usize> MerkleLeaves for Confined<Vec<T>, MIN, { u32::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

impl<T: Ord, const MIN: usize> MerkleLeaves for Confined<BTreeSet<T>, MIN, { u32::MAX as usize }>
where T: CommitId<CommitmentId = MerkleHash>
{
    type Leaf = T;
    fn merkle_leaves(&self) -> impl ExactSizeIterator<Item = &T> { self.iter() }
}

/// Helper struct to track depth when working with Merkle blocks.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct MerkleBuoy<D: Copy + Eq + SubAssign<u8> + Default> {
    buoy: D,
    stack: Option<Box<MerkleBuoy<D>>>,
}

impl<D: Copy + Eq + SubAssign<u8> + Default> MerkleBuoy<D> {
    pub fn new(top: D) -> Self {
        Self {
            buoy: top,
            stack: None,
        }
    }

    /// Measure the current buoy level.
    pub fn level(&self) -> D {
        self.stack
            .as_ref()
            .map(Box::as_ref)
            .map(MerkleBuoy::level)
            .unwrap_or(self.buoy)
    }

    /// Add new item to the buoy.
    ///
    /// Returns whether the buoy have surfaced in a result.
    ///
    /// The buoy surfaces each time the contents it has is reduced to two depth
    /// of the same level.
    pub fn push(&mut self, depth: D) -> bool {
        if depth == D::default() {
            return false;
        }
        match self
            .stack
            .as_mut()
            .map(|stack| (stack.push(depth), stack.level()))
        {
            None if depth == self.buoy => {
                self.buoy -= 1;
                true
            }
            None => {
                self.stack = Some(Box::new(MerkleBuoy::new(depth)));
                false
            }
            Some((true, level)) => {
                self.stack = None;
                self.push(level)
            }
            Some((false, _)) => false,
        }
    }
}
