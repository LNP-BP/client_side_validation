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

use amplify::confinement::{Confined, LargeVec};
use amplify::num::u5;
use strict_encoding::{StrictDeserialize, StrictEncode, StrictSerialize};

use crate::id::CommitId;
use crate::merkle::{MerkleBuoy, MerkleHash};
use crate::mpc::atoms::Leaf;
use crate::mpc::tree::protocol_id_pos;
use crate::mpc::{Commitment, MerkleTree, Message, MessageMap, Proof, ProtocolId};
use crate::{Conceal, LIB_NAME_COMMIT_VERIFY};

/// commitment under protocol id {0} is absent from the known part of a given
/// LNPBP-4 Merkle block.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub struct LeafNotKnown(ProtocolId);

/// the provided merkle proof protocol id {protocol_id} position {actual}
/// doesn't match the expected position {expected} within the tree of width
/// {width}.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error)]
#[display(doc_comments)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct InvalidProof {
    protocol_id: ProtocolId,
    expected: u32,
    actual: u32,
    width: u32,
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum MergeError {
    #[from]
    #[display(inner)]
    InvalidProof(InvalidProof),

    /// attempt to merge two unrelated LNPBP-4 blocks with different Merkle
    /// roots (base {base_root}, merged-in {merged_root}).
    UnrelatedBlocks {
        base_root: Commitment,
        merged_root: Commitment,
    },
}

/// LNPBP-4 Merkle tree node.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(
    lib = LIB_NAME_COMMIT_VERIFY,
    tags = order,
    dumb = { TreeNode::ConcealedNode { depth: u5::ZERO, hash: [0u8; 32].into() } }
)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
enum TreeNode {
    /// A node of the tree with concealed leaf or tree branch information.
    ConcealedNode {
        /// Depth of the node.
        depth: u5,
        /// Node hash.
        hash: MerkleHash,
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
    fn with(hash1: MerkleHash, hash2: MerkleHash, depth: u5, width: u32) -> TreeNode {
        TreeNode::ConcealedNode {
            depth,
            hash: MerkleHash::branches(depth, width, hash1, hash2),
        }
    }

    pub fn depth(&self) -> Option<u5> {
        match self {
            TreeNode::ConcealedNode { depth, .. } => Some(*depth),
            TreeNode::CommitmentLeaf { .. } => None,
        }
    }

    pub fn depth_or(&self, tree_depth: u5) -> u5 { self.depth().unwrap_or(tree_depth) }

    pub fn is_leaf(&self) -> bool { matches!(self, TreeNode::CommitmentLeaf { .. }) }

    pub fn to_merkle_node(self) -> MerkleHash {
        match self {
            TreeNode::ConcealedNode { hash, .. } => hash,
            TreeNode::CommitmentLeaf {
                protocol_id,
                message,
            } => Leaf::inhabited(protocol_id, message).commit_id(),
        }
    }
}

/// Partially-concealed merkle tree data.
#[derive(Getters, Clone, PartialEq, Eq, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, strategy = conceal, id = Commitment)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MerkleBlock {
    /// Tree depth (up to 16).
    #[getter(as_copy)]
    depth: u5,

    /// Cofactor is used as an additive to the modulo divisor to improve packing
    /// of protocols inside a tree of a given depth.
    #[getter(as_copy)]
    cofactor: u16,

    /// Tree cross-section.
    #[getter(skip)]
    cross_section: LargeVec<TreeNode>,

    /// Entropy used for placeholders. May be unknown if the message is provided
    /// by a third-party, wishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

impl StrictSerialize for MerkleBlock {}
impl StrictDeserialize for MerkleBlock {}

impl Proof for MerkleBlock {}

impl From<&MerkleTree> for MerkleBlock {
    fn from(tree: &MerkleTree) -> Self {
        let map = &tree.map;

        let iter = (0..tree.width()).map(|pos| {
            map.get(&pos)
                .map(|(protocol_id, message)| TreeNode::CommitmentLeaf {
                    protocol_id: *protocol_id,
                    message: *message,
                })
                .unwrap_or_else(|| TreeNode::ConcealedNode {
                    depth: tree.depth,
                    hash: Leaf::entropy(tree.entropy, pos).commit_id(),
                })
        });
        let cross_section =
            LargeVec::try_from_iter(iter).expect("tree width guarantees are broken");

        MerkleBlock {
            depth: tree.depth,
            cofactor: tree.cofactor,
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
    ) -> Result<Self, InvalidProof> {
        let path = proof.as_path();
        let mut pos = proof.pos;
        let mut width = proof.width();

        let expected = protocol_id_pos(protocol_id, proof.cofactor, width);
        if expected != pos {
            return Err(InvalidProof {
                protocol_id,
                expected,
                actual: pos,
                width,
            });
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
                depth: u5::with(depth as u8) + 1,
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
            LargeVec::try_from(cross_section).expect("tree width guarantees are broken");

        Ok(MerkleBlock {
            depth: u5::with(path.len() as u8),
            cofactor: proof.cofactor,
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
                        hash: node.to_merkle_node(),
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
            let mut offset = 0u32;
            let mut pos = 0usize;
            let mut len = self.cross_section.len();
            while pos < len {
                let (n1, n2) = (self.cross_section[pos], self.cross_section.get(pos + 1).copied());
                match (n1, n2) {
                    // Two concealed nodes of the same depth: aggregate if they are on the same
                    // branch, skip just one otherwise
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
                        let pow = 2u32.pow(height);
                        if offset % pow != 0 {
                            offset += 2u32.pow(self.depth.to_u8() as u32 - depth1.to_u8() as u32);
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
                    // Two concealed nodes at different depth, or the last concealed node:
                    // - we skip one of them and repeat
                    (
                        TreeNode::ConcealedNode { depth, .. },
                        Some(TreeNode::ConcealedNode { .. }) | None,
                    ) => {
                        offset += 2u32.pow(self.depth.to_u8() as u32 - depth.to_u8() as u32);
                    }
                    // Two commitment leafs: skipping both
                    (TreeNode::CommitmentLeaf { .. }, Some(TreeNode::CommitmentLeaf { .. })) => {
                        offset += 2;
                        pos += 1;
                    }
                    // Concealed node followed by a leaf: skipping both
                    (
                        TreeNode::ConcealedNode { depth, .. },
                        Some(TreeNode::CommitmentLeaf { .. }),
                    ) => {
                        offset += 2u32.pow(self.depth.to_u8() as u32 - depth.to_u8() as u32);
                        offset += 1;
                        pos += 1;
                    }
                    // Leaf followed by a concealed node: skipping leaf only, repeating
                    (
                        TreeNode::CommitmentLeaf { .. },
                        Some(TreeNode::ConcealedNode { .. }) | None,
                    ) => {
                        offset += 1;
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
    ) -> Result<u16, MergeError> {
        let block = MerkleBlock::with(proof, protocol_id, message)?;
        self.merge_reveal(block)
    }

    /// Merges two merkle blocks together, joining revealed information from
    /// each one of them.
    pub fn merge_reveal(&mut self, other: MerkleBlock) -> Result<u16, MergeError> {
        let orig = self.clone();
        let base_root = self.commit_id();
        let merged_root = other.commit_id();
        if base_root != merged_root {
            return Err(MergeError::UnrelatedBlocks {
                base_root,
                merged_root,
            });
        }

        let mut cross_section =
            Vec::with_capacity(self.cross_section.len() + other.cross_section.len());
        let mut a = self.cross_section.iter().copied();
        let mut b = other.cross_section.iter().copied();

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
                        // Nothing to do here, we are skipping both nodes
                        (false, false) => {}
                        // If two nodes are both leafs or concealed, but not
                        // equal to each other it means out algorithm is broken
                        _ => unreachable!(
                            "two MerkleBlock's with equal commitment failed to merge.\nBlock #1: \
                             {self:#?}\nBlock #2: {other:#?}\nFailed nodes:\n{n1:?}\n{n2:?}"
                        ),
                    }
                    last_a = a.next();
                    last_b = b.next();
                }
                Ordering::Less => {
                    cross_section.push(n2);
                    let mut buoy = MerkleBuoy::<u5>::new(n2_depth);
                    let mut stop = false;
                    last_b = None;
                    cross_section.extend(b.by_ref().take_while(|n| {
                        if stop {
                            last_b = Some(*n);
                            return false;
                        }
                        buoy.push(n.depth_or(self.depth));
                        if buoy.level() <= n1_depth {
                            stop = true
                        }
                        true
                    }));
                    last_a = a.next();
                }
                Ordering::Greater => {
                    cross_section.push(n1);
                    let mut buoy = MerkleBuoy::<u5>::new(n1_depth);
                    let mut stop = false;
                    last_a = None;
                    cross_section.extend(a.by_ref().take_while(|n| {
                        if stop {
                            last_a = Some(*n);
                            return false;
                        }
                        buoy.push(n.depth_or(self.depth));
                        if buoy.level() <= n2_depth {
                            stop = true
                        }
                        true
                    }));
                    last_b = b.next();
                }
            }
        }
        cross_section.extend(a);
        cross_section.extend(b);

        self.cross_section =
            LargeVec::try_from(cross_section).expect("tree width guarantees are broken");

        assert_eq!(
            self.cross_section
                .iter()
                .map(|n| self.depth.to_u8() - n.depth_or(self.depth).to_u8())
                .map(|height| 2u32.pow(height as u32))
                .sum::<u32>(),
            self.width(),
            "LNPBP-4 merge-reveal procedure is broken; please report the below data to the LNP/BP \
             Standards Association
Original block: {orig:#?}
Merged-in block: {other:#?}
Failed merge: {self:#?}"
        );
        assert_eq!(
            base_root,
            self.commit_id(),
            "LNPBP-4 merge-reveal procedure is broken; please report the below data to the LNP/BP \
             Standards Association
Original commitment id: {base_root}
Changed commitment id: {}",
            self.commit_id()
        );

        Ok(self.cross_section.len() as u16)
    }

    /// Converts the merkle block into a merkle proof for the inclusion of a
    /// commitment under given `protocol_id`.
    pub fn into_merkle_proof(
        mut self,
        protocol_id: ProtocolId,
    ) -> Result<MerkleProof, LeafNotKnown> {
        self.conceal_except([protocol_id])?;
        let mut map = BTreeMap::<u5, MerkleHash>::new();
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
            cofactor: self.cofactor,
            path: Confined::try_from_iter(map.into_values())
                .expect("tree width guarantees are broken"),
        })
    }

    /// Constructs merkle proof for the inclusion of a commitment under given
    /// `protocol_id` for the current Merkle block.
    pub fn to_merkle_proof(&self, protocol_id: ProtocolId) -> Result<MerkleProof, LeafNotKnown> {
        self.clone().into_merkle_proof(protocol_id)
    }

    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u32 {
        protocol_id_pos(protocol_id, self.cofactor, self.width())
    }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> u32 { 2u32.pow(self.depth.to_u8() as u32) }

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
    type Concealed = Self;

    /// Reduces merkle tree into merkle tree root.
    fn conceal(&self) -> Self::Concealed {
        let mut concealed = self.clone();
        concealed
            .conceal_except([])
            .expect("broken internal MerkleBlock structure");
        debug_assert_eq!(concealed.cross_section.len(), 1);
        concealed
    }
}

/// A proof of the merkle commitment.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct MerkleProof {
    /// Position of the leaf in the tree.
    ///
    /// Used to determine chirality of the node hashing partners on each step
    /// of the path.
    #[getter(as_copy)]
    pos: u32,

    /// Cofactor used by the Merkle tree.
    #[getter(as_copy)]
    cofactor: u16,

    /// Merkle proof path consisting of node hashing partners.
    #[getter(skip)]
    path: Confined<Vec<MerkleHash>, 0, 32>,
}

impl Proof for MerkleProof {}

impl MerkleProof {
    /// Computes the depth of the merkle tree.
    pub fn depth(&self) -> u8 { self.path.len() as u8 }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> u32 { 2u32.pow(self.depth() as u32) }

    /// Converts the proof into inner merkle path representation
    pub fn into_path(self) -> Confined<Vec<MerkleHash>, 0, 32> { self.path }

    /// Constructs the proof into inner merkle path representation
    pub fn to_path(&self) -> Confined<Vec<MerkleHash>, 0, 32> { self.path.clone() }

    /// Returns inner merkle path representation
    pub fn as_path(&self) -> &[MerkleHash] { &self.path }

    /// Convolves the proof with the `message` under the given `protocol_id`,
    /// producing [`Commitment`].
    pub fn convolve(
        &self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<Commitment, InvalidProof> {
        let block = MerkleBlock::with(self, protocol_id, message)?;
        Ok(block.commit_id())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::mpc::tree::test_helpers::{
        make_det_messages, make_random_messages, make_random_tree,
    };

    #[test]
    fn entropy() {
        let msgs = make_random_messages(3);
        let tree = make_random_tree(&msgs);
        let mut block = MerkleBlock::from(&tree);

        // Check we preserve entropy value
        assert_eq!(Some(tree.entropy), block.entropy);
        // Check if we remove entropy the commitment doesn't change
        let cid1 = block.commit_id();
        block.entropy = None;
        let cid2 = block.commit_id();
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn single_leaf_tree() {
        let msgs = make_random_messages(1);
        let tree = make_random_tree(&msgs);
        let block = MerkleBlock::from(&tree);

        let (pid, msg) = msgs.first_key_value().unwrap();
        let leaf = Leaf::inhabited(*pid, *msg);
        let cid1 = block.cross_section.first().unwrap().to_merkle_node();
        let cid2 = leaf.commit_id();
        assert_eq!(cid1, cid2);

        assert_eq!(tree.conceal(), block.conceal());
        assert_eq!(tree.root(), cid1);
        assert_eq!(tree.commit_id(), block.commit_id())
    }

    #[test]
    fn determin_tree() {
        for size in 1..6 {
            let msgs = make_det_messages(size);
            let tree = make_random_tree(&msgs);
            let block = MerkleBlock::from(&tree);

            assert_eq!(tree.conceal(), block.conceal());
            assert_eq!(tree.commit_id(), block.commit_id())
        }
    }

    #[test]
    fn sparse_tree() {
        for size in 2..6 {
            let msgs = make_random_messages(size);
            let tree = make_random_tree(&msgs);
            let block = MerkleBlock::from(&tree);

            assert_eq!(tree.conceal(), block.conceal());
            assert_eq!(tree.commit_id(), block.commit_id())
        }
    }

    #[test]
    fn merge_reveal() {
        for size in 2..9 {
            let msgs = make_random_messages(size);
            let mpc_tree = make_random_tree(&msgs);
            let mpc_block = MerkleBlock::from(mpc_tree.clone());

            let proofs = msgs
                .keys()
                .map(|pid| mpc_block.to_merkle_proof(*pid).unwrap())
                .collect::<Vec<_>>();

            let mut iter = proofs.iter().zip(msgs.into_iter());
            let (proof, (pid, msg)) = iter.next().unwrap();
            let mut merged_block = MerkleBlock::with(proof, pid, msg).unwrap();
            for (proof, (pid, msg)) in iter {
                let block = MerkleBlock::with(proof, pid, msg).unwrap();
                if let Err(err) = merged_block.merge_reveal(block.clone()) {
                    eprintln!("Error: {err}");
                    eprintln!("Source tree: {mpc_tree:#?}");
                    eprintln!("Source block: {mpc_block:#?}");
                    eprintln!("Base block: {merged_block:#?}");
                    eprintln!("Added proof: {proof:#?}");
                    eprintln!("Added block: {block:#?}");
                    panic!();
                }
            }

            assert_eq!(merged_block.commit_id(), mpc_tree.commit_id());
        }
    }
}
