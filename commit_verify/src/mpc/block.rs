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

#![allow(unused_braces)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use amplify::confinement::{Confined, SmallVec};
use amplify::num::u4;
use strict_encoding::StrictEncode;

use crate::id::CommitmentId;
use crate::merkle::MerkleNode;
use crate::mpc::atoms::Leaf;
use crate::mpc::tree::protocol_id_pos;
use crate::mpc::{
    Commitment, MerkleTree, Message, MessageMap, Proof, ProtocolId, MERKLE_LNPBP4_TAG,
};
use crate::{Conceal, LIB_NAME_COMMIT_VERIFY};

/// commitment under protocol id {_0} is absent from the known part of a given
/// LNPBP-4 Merkle block.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub struct LeafNotKnown(ProtocolId);

/// attempt to merge unrelated LNPBP-4 proof.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub struct UnrelatedProof;

/// LNPBP-4 Merkle tree node.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_COMMIT_VERIFY,
    tags = order,
    dumb = { TreeNode::ConcealedNode { depth: u4::ZERO, hash: [0u8; 32].into() } }
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
enum TreeNode {
    /// A node of the tree with concealed leaf or tree branch information.
    ConcealedNode {
        /// Depth of the node.
        depth: u4,
        /// Node hash.
        hash: MerkleNode,
    },
    /// A tree leaf storing specific commitment under given protocol.
    CommitmentLeaf {
        /// Protocol under which the commitment is created.
        protocol_id: ProtocolId,
        /// Message this leaf commits to.
        message: Message,
    },
}

impl TreeNode {
    fn with(hash1: MerkleNode, hash2: MerkleNode, depth: u4, width: u16) -> TreeNode {
        TreeNode::ConcealedNode {
            depth,
            hash: MerkleNode::branches(MERKLE_LNPBP4_TAG.to_be_bytes(), depth, width, hash1, hash2),
        }
    }

    pub fn depth(&self) -> Option<u4> {
        match self {
            TreeNode::ConcealedNode { depth, .. } => Some(*depth),
            TreeNode::CommitmentLeaf { .. } => None,
        }
    }

    pub fn depth_or(&self, tree_depth: u4) -> u4 { self.depth().unwrap_or(tree_depth) }

    pub fn is_leaf(&self) -> bool { matches!(self, TreeNode::CommitmentLeaf { .. }) }

    pub fn merkle_node_with(&self) -> MerkleNode {
        match self {
            TreeNode::ConcealedNode { hash, .. } => *hash,
            TreeNode::CommitmentLeaf {
                protocol_id,
                message,
            } => Leaf::inhabited(*protocol_id, *message).commitment_id(),
        }
    }
}

/// Partially-concealed merkle tree data.
#[derive(Getters, Clone, PartialEq, Eq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, conceal, strategy = strict)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MerkleBlock {
    /// Tree depth (up to 16).
    #[getter(as_copy)]
    depth: u4,

    /// Tree cross-section.
    #[getter(skip)]
    cross_section: SmallVec<TreeNode>,

    /// Entropy used for placeholders. May be unknown if the message is provided
    /// by a third-party, wishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

impl Proof for MerkleBlock {}

impl From<&MerkleTree> for MerkleBlock {
    fn from(tree: &MerkleTree) -> Self {
        let map = &tree.map;

        let iter = (0..tree.width()).into_iter().map(|pos| {
            map.get(&pos)
                .map(|(protocol_id, message)| TreeNode::CommitmentLeaf {
                    protocol_id: *protocol_id,
                    message: *message,
                })
                .unwrap_or_else(|| TreeNode::ConcealedNode {
                    depth: tree.depth,
                    hash: Leaf::entropy(tree.entropy, pos).commitment_id(),
                })
        });
        let cross_section =
            SmallVec::try_from_iter(iter).expect("tree width guarantees are broken");

        MerkleBlock {
            depth: tree.depth,
            cross_section,
            entropy: Some(tree.entropy),
        }
    }
}

impl From<MerkleTree> for MerkleBlock {
    fn from(tree: MerkleTree) -> Self { MerkleBlock::from(&tree) }
}

impl MerkleBlock {
    /// Constructs merkle block from a merkle proof
    pub fn with(
        proof: &MerkleProof,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<Self, UnrelatedProof> {
        let path = proof.as_path();
        let mut pos = proof.pos;
        let mut width = proof.width() as u16;

        if protocol_id_pos(protocol_id, width) != pos {
            return Err(UnrelatedProof);
        }

        let mut dir = Vec::with_capacity(path.len());
        let mut rev = Vec::with_capacity(path.len());
        for (depth, hash) in path.iter().enumerate() {
            let list = if pos >= width / 2 {
                pos -= width / 2;
                &mut dir
            } else {
                &mut rev
            };
            list.push(TreeNode::ConcealedNode {
                depth: u4::with(depth as u8) + 1,
                hash: *hash,
            });
            width /= 2;
        }

        let mut cross_section = Vec::with_capacity(path.len() + 1);
        cross_section.extend(dir);
        cross_section.push(TreeNode::CommitmentLeaf {
            protocol_id,
            message,
        });
        cross_section.extend(rev.into_iter().rev());
        let cross_section =
            SmallVec::try_from(cross_section).expect("tree width guarantees are broken");

        Ok(MerkleBlock {
            depth: u4::with(path.len() as u8),
            cross_section,
            entropy: None,
        })
    }

    /// Conceals all commitments in the block except for the commitment under
    /// given `protocol_id`s. Also removes information about the entropy value
    /// used.
    ///
    /// # Returns
    ///
    /// Number of concealed nodes.
    ///
    /// # Error
    ///
    /// If leaf with the given `protocol_id` is not found (absent or already
    /// concealed), errors with [`LeafNotKnown`] error.
    pub fn conceal_except(
        &mut self,
        protocols: impl AsRef<[ProtocolId]>,
    ) -> Result<usize, LeafNotKnown> {
        let protocols = protocols.as_ref();

        let mut count = 0usize;
        let mut not_found = protocols.iter().copied().collect::<BTreeSet<_>>();

        self.entropy = None;

        // Conceal all leafs except of one
        for node in &mut self.cross_section {
            match node {
                TreeNode::ConcealedNode { .. } => {
                    // Do nothing
                }
                TreeNode::CommitmentLeaf { protocol_id: p, .. } if protocols.contains(p) => {
                    not_found.remove(p);
                }
                TreeNode::CommitmentLeaf { .. } => {
                    count += 1;
                    *node = TreeNode::ConcealedNode {
                        depth: self.depth,
                        hash: node.merkle_node_with(),
                    };
                }
            }
        }

        if let Some(protocol_id) = not_found.into_iter().next() {
            return Err(LeafNotKnown(protocol_id));
        }

        loop {
            debug_assert!(!self.cross_section.is_empty());
            let prev_count = count;
            let mut offset = 0u16;
            let mut pos = 0usize;
            let mut len = self.cross_section.len();
            while pos < len {
                let (n1, n2) = (self.cross_section[pos], self.cross_section.get(pos + 1).copied());
                match (n1, n2) {
                    (
                        TreeNode::ConcealedNode {
                            depth: depth1,
                            hash: hash1,
                        },
                        Some(TreeNode::ConcealedNode {
                            depth: depth2,
                            hash: hash2,
                        }),
                    ) if depth1 == depth2 => {
                        let depth = depth1 - 1;
                        let height = self.depth.to_u8() as u32 - depth.to_u8() as u32;
                        let pow = 2u16.pow(height);
                        if offset % pow != 0 {
                            offset += 2u16.pow(self.depth.to_u8() as u32 - depth1.to_u8() as u32);
                        } else {
                            self.cross_section[pos] =
                                TreeNode::with(hash1, hash2, depth, self.width());
                            self.cross_section
                                .remove(pos + 1)
                                .expect("we allow 0 elements");
                            count += 1;
                            offset += pow;
                            len -= 1;
                        }
                    }
                    (TreeNode::CommitmentLeaf { .. }, Some(TreeNode::CommitmentLeaf { .. })) => {
                        offset += 2;
                        pos += 1;
                    }
                    (
                        TreeNode::CommitmentLeaf { .. },
                        Some(TreeNode::ConcealedNode { depth, .. }),
                    ) |
                    (
                        TreeNode::ConcealedNode { depth, .. },
                        Some(TreeNode::CommitmentLeaf { .. }),
                    ) if depth == self.depth => {
                        offset += 2;
                        pos += 1;
                    }
                    (TreeNode::CommitmentLeaf { .. }, _) => {
                        offset += 1;
                    }
                    (TreeNode::ConcealedNode { depth, .. }, _) => {
                        offset += 2u16.pow(self.depth.to_u8() as u32 - depth.to_u8() as u32);
                    }
                }
                pos += 1;
            }
            if count == prev_count {
                break;
            }
            debug_assert_eq!(offset, self.width());
        }

        Ok(count)
    }

    /// Merges information from the given `proof` to the merkle block, revealing
    /// path related to te `commitment` to the message under the given
    /// `protocol_id`.
    pub fn merge_reveal_path(
        &mut self,
        proof: &MerkleProof,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<u16, UnrelatedProof> {
        let block = MerkleBlock::with(proof, protocol_id, message)?;
        self.merge_reveal(block)
    }

    /// Merges two merkle blocks together, joining revealed information from
    /// each one of them.
    pub fn merge_reveal(&mut self, other: MerkleBlock) -> Result<u16, UnrelatedProof> {
        if self.commitment_id() != other.commitment_id() {
            return Err(UnrelatedProof);
        }

        let mut cross_section =
            Vec::with_capacity(self.cross_section.len() + other.cross_section.len());
        let mut a = self.cross_section.clone().into_iter();
        let mut b = other.cross_section.into_iter();

        let mut last_a = a.next();
        let mut last_b = b.next();
        while let (Some(n1), Some(n2)) = (last_a, last_b) {
            let n1_depth = n1.depth_or(self.depth);
            let n2_depth = n2.depth_or(self.depth);
            match n1_depth.cmp(&n2_depth) {
                Ordering::Equal if n1 == n2 => {
                    cross_section.push(n1);
                    last_a = a.next();
                    last_b = b.next();
                }
                Ordering::Equal => {
                    match (n1.is_leaf(), n2.is_leaf()) {
                        (true, false) => cross_section.push(n1),
                        (false, true) => cross_section.push(n2),
                        // If two nodes are both leafs or concealed, but not
                        // equal to each other it means that the provided blocks
                        // are unrelated
                        _ => return Err(UnrelatedProof),
                    }
                    last_a = a.next();
                    last_b = b.next();
                }
                Ordering::Less => {
                    cross_section.push(n2);
                    cross_section.extend(b.by_ref().take_while(|n| {
                        if n.depth_or(self.depth) > n1_depth {
                            last_b = None;
                            true
                        } else {
                            last_b = Some(*n);
                            false
                        }
                    }));
                    last_a = a.next();
                }
                Ordering::Greater => {
                    cross_section.push(n1);
                    cross_section.extend(a.by_ref().take_while(|n| {
                        if n.depth_or(self.depth) > n2_depth {
                            last_a = None;
                            true
                        } else {
                            last_a = Some(*n);
                            false
                        }
                    }));
                    last_b = b.next();
                }
            }
        }

        self.cross_section =
            SmallVec::try_from(cross_section).expect("tree width guarantees are broken");

        Ok(self.cross_section.len() as u16)
    }

    /// Converts the merkle block into a merkle proof for the inclusion of a
    /// commitment under given `protocol_id`.
    pub fn into_merkle_proof(
        mut self,
        protocol_id: ProtocolId,
    ) -> Result<MerkleProof, LeafNotKnown> {
        self.conceal_except([protocol_id])?;
        let mut map = BTreeMap::<u4, MerkleNode>::new();
        for node in &self.cross_section {
            match node {
                TreeNode::ConcealedNode { depth, hash } => {
                    let inserted = map.insert(*depth, *hash).is_none();
                    debug_assert!(inserted, "MerkleBlock conceal procedure is broken");
                }
                TreeNode::CommitmentLeaf { .. } => {}
            }
        }
        debug_assert_eq!(
            self.depth.to_u8() as usize,
            map.len(),
            "MerkleBlock conceal procedure is broken"
        );
        Ok(MerkleProof {
            pos: self.protocol_id_pos(protocol_id),
            path: SmallVec::try_from_iter(map.into_values())
                .expect("tree width guarantees are broken"),
        })
    }

    /// Constructs merkle proof for the inclusion of a commitment under given
    /// `protocol_id` for the current Merkle block.
    pub fn to_merkle_proof(&self, protocol_id: ProtocolId) -> Result<MerkleProof, LeafNotKnown> {
        self.clone().into_merkle_proof(protocol_id)
    }

    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u16 {
        protocol_id_pos(protocol_id, self.width())
    }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> u16 { 2usize.pow(self.depth.to_u8() as u32) as u16 }

    /// Constructs [`MessageMap`] for revealed protocols and messages.
    pub fn to_known_message_map(&self) -> MessageMap {
        Confined::try_from_iter(
            self.cross_section
                .iter()
                .copied()
                .filter_map(|item| match item {
                    TreeNode::ConcealedNode { .. } => None,
                    TreeNode::CommitmentLeaf {
                        protocol_id,
                        message,
                    } => Some((protocol_id, message)),
                }),
        )
        .expect("same collection size")
    }
}

impl Conceal for MerkleBlock {
    type Concealed = MerkleNode;

    /// Reduces merkle tree into merkle tree root.
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .conceal_except([])
            .expect("broken internal MerkleBlock structure");
        debug_assert_eq!(concealed.cross_section.len(), 1);
        concealed.cross_section[0].merkle_node_with()
    }
}

impl CommitmentId for MerkleBlock {
    const TAG: [u8; 32] = *b"urn:lnpbp:lnpbp0004:tree:v01#23A";
    type Id = Commitment;
}

/// A proof of the merkle commitment.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, strategy = strict)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MerkleProof {
    /// Position of the leaf in the tree.
    ///
    /// Used to determine chirality of the node hashing partners on each step
    /// of the path.
    #[getter(as_copy)]
    pos: u16,

    /// Merkle proof path consisting of node hashing partners.
    #[getter(skip)]
    path: SmallVec<MerkleNode>,
}

impl Proof for MerkleProof {}

impl MerkleProof {
    /// Computes the depth of the merkle tree.
    pub fn depth(&self) -> u8 { self.path.len() as u8 }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> usize { 2usize.pow(self.depth() as u32) }

    /// Converts the proof into inner merkle path representation
    pub fn into_path(self) -> SmallVec<MerkleNode> { self.path }

    /// Constructs the proof into inner merkle path representation
    pub fn to_path(&self) -> SmallVec<MerkleNode> { self.path.clone() }

    /// Returns inner merkle path representation
    pub fn as_path(&self) -> &[MerkleNode] { &self.path }

    /// Convolves the proof with the `message` under the given `protocol_id`,
    /// producing [`Commitment`].
    pub fn convolve(
        &self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<Commitment, UnrelatedProof> {
        let block = MerkleBlock::with(self, protocol_id, message)?;
        Ok(block.commitment_id())
    }
}
