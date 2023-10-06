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

use core::{iter, slice};
use std::collections::{btree_set, BTreeSet};
use std::io::Write;
use std::ops::SubAssign;

use amplify::confinement::Confined;
use amplify::num::u5;
use amplify::{Bytes32, Wrapper};
use sha2::Sha256;

use crate::digest::DigestExt;
use crate::encode::{strategies, CommitStrategy};
use crate::{CommitEncode, CommitmentId, LIB_NAME_COMMIT_VERIFY};

/// Type of a merkle node branching.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum NodeBranching {
    /// Void node: virtual node with no leafs.
    ///
    /// Used when the total width of the three is not a power two.
    Void = 0x00,

    /// Node having just a single leaf, with the second branch being void.
    Single = 0x01,

    /// Node having two branches.
    Branch = 0x02,
}

impl From<NodeBranching> for u8 {
    fn from(value: NodeBranching) -> Self { value as u8 }
}

impl CommitStrategy for NodeBranching {
    type Strategy = strategies::IntoU8;
}

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY, dumb = MerkleNode(default!()))]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, strategy = strict)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct MerkleNode(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for MerkleNode {
    const TAG: [u8; 32] = *b"urn:lnpbp:lnpbp0081:node:v01#23A";
    type Id = Self;
}

const VIRTUAL_LEAF: MerkleNode = MerkleNode(Bytes32::from_array([0xFF; 32]));

impl MerkleNode {
    pub fn void(tag: [u8; 16], depth: u5, width: u32) -> Self {
        let virt = VIRTUAL_LEAF;
        Self::with(NodeBranching::Void, tag, depth, width, virt, virt)
    }

    pub fn single(tag: [u8; 16], depth: u5, width: u32, node: MerkleNode) -> Self {
        let single = NodeBranching::Single;
        Self::with(single, tag, depth, width, node, VIRTUAL_LEAF)
    }

    pub fn branches(
        tag: [u8; 16],
        depth: u5,
        width: u32,
        node1: MerkleNode,
        node2: MerkleNode,
    ) -> Self {
        Self::with(NodeBranching::Branch, tag, depth, width, node1, node2)
    }

    fn with(
        branching: NodeBranching,
        tag: [u8; 16],
        depth: u5,
        width: u32,
        node1: MerkleNode,
        node2: MerkleNode,
    ) -> Self {
        let mut engine = Sha256::default();
        branching.commit_encode(&mut engine);
        engine.write_all(&tag).ok();
        depth.to_u8().commit_encode(&mut engine);
        width.commit_encode(&mut engine);
        node1.commit_encode(&mut engine);
        node2.commit_encode(&mut engine);
        engine.finish().into()
    }
}

impl MerkleNode {
    /// Merklization procedure that uses tagged hashes with depth commitments
    /// according to [LNPBP-81] standard of client-side-validation merklization.
    ///
    /// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
    pub fn merklize(tag: [u8; 16], leaves: &impl MerkleLeaves) -> Self {
        let mut nodes = leaves.merkle_leaves().map(|leaf| leaf.commitment_id());
        let len = nodes.len() as u32;
        if len == 1 {
            // If we have just one leaf, it's MerkleNode value is the root
            nodes.next().expect("length is 1")
        } else {
            Self::_merklize(tag, nodes, u5::ZERO, len)
        }
    }

    pub fn _merklize(
        tag: [u8; 16],
        mut iter: impl ExactSizeIterator<Item = MerkleNode>,
        depth: u5,
        width: u32,
    ) -> Self {
        let len = iter.len() as u16;

        if len <= 2 {
            match (iter.next(), iter.next()) {
                (None, None) => MerkleNode::void(tag, depth, width),
                // Here, a single node means Merkle tree width nonequal to the power of 2, thus we
                // need to process it with a special encoding.
                (Some(branch), None) => MerkleNode::single(tag, depth, width, branch),
                (Some(branch1), Some(branch2)) => {
                    MerkleNode::branches(tag, depth, width, branch1, branch2)
                }
                (None, Some(_)) => unreachable!(),
            }
        } else {
            let div = len / 2 + len % 2;

            let slice = iter
                .by_ref()
                .take(div as usize)
                // Normally we should use `iter.by_ref().take(div)`, but currently
                // rust compilers is unable to parse recursion with generic types
                // TODO: Do this without allocation
                .collect::<Vec<_>>()
                .into_iter();
            let branch1 = Self::_merklize(tag, slice, depth + 1, width);
            let branch2 = Self::_merklize(tag, iter, depth + 1, width);

            MerkleNode::branches(tag, depth, width, branch1, branch2)
        }
    }
}

pub trait MerkleLeaves {
    type Leaf: CommitmentId<Id = MerkleNode>;
    type LeafIter<'tmp>: ExactSizeIterator<Item = Self::Leaf>
    where Self: 'tmp;

    fn merkle_leaves(&self) -> Self::LeafIter<'_>;
}

impl<T, const MIN: usize> MerkleLeaves for Confined<Vec<T>, MIN, { u16::MAX as usize }>
where T: CommitmentId<Id = MerkleNode> + Copy
{
    type Leaf = T;
    type LeafIter<'tmp> = iter::Copied<slice::Iter<'tmp, T>> where Self: 'tmp;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> { self.iter().copied() }
}

impl<T: Ord, const MIN: usize> MerkleLeaves for Confined<BTreeSet<T>, MIN, { u16::MAX as usize }>
where T: CommitmentId<Id = MerkleNode> + Copy
{
    type Leaf = T;
    type LeafIter<'tmp> = iter::Copied<btree_set::Iter<'tmp, T>> where Self: 'tmp;

    fn merkle_leaves(&self) -> Self::LeafIter<'_> { self.iter().copied() }
}

/// Helper struct to track depth when working with Merkle blocks.
// TODO: v0.11 Remove default generic from MerkleBuoy
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleBuoy<D: Copy + Eq + SubAssign<u8> + Default = u5> {
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
