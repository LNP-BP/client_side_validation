// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

//! Multi-message commitments: implementation of [LNPBP-4] standard.
//!
//! [LNPBP-4] defines a commit-verify scheme for committing to a multiple
//! messages under distinct protocols with ability to partially reveal set of
//! the commitments and still be able to prove the commitment for each message
//! without exposing the exact number of other messages and their respective
//! protocol identifiers.
//!
//! LBPBP-4 commitments are originally constructed from [`MultiSource`] data
//! structure in form of full LNPBP-4 merkle trees [`MerkleTree`] using
//! [`MerkleTree::try_commit`] method. Full trees preserve all the information
//! from the [`MultiSource`], plus keep information on generated entropy and
//! the actual size of the created tree.
//!
//! [`MerkleTree`] can than be either converted into [`MerkleBlock`] and than
//! a separate instances of [`MerkleProof`]s can be extracted from it for each
//! specific protocol using [`PartialTree::conceal_except`] operation.
//! [`MerkleBlock`] can conceal sme data and can also be constructed from
//! (multiple) [`MerkleProof`] and/or other [`MerkleBlock`].
//!
//! Summary of the operations with LNPBP-4 data structures:
//!
//! - [`TryCommit::try_commit`]: [`MultiSource`] -> [`MerkleTree`]
//! - [`MerkleBlock::from`]: [`MerkleTree`] -> `Self`
//! - [`MerkleBlock::conceal_except`]: `Self`, [`ProtocolId`] -> [`MerkleProof`]
//! - [`MerkleBlock::from`]: [`MerkleProof`] -> `Self`
//! - [`MerkleBlock::merge_reveal`]: `Self`, [`MerkleProof`] -> `Self`
//!
//! [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

use std::collections::BTreeMap;
use std::io::Write;

use amplify::num::u256;
use amplify::{Slice32, Wrapper};
use bitcoin_hashes::{sha256, sha256t, Hash, HashEngine};
use strict_encoding::StrictEncode;

use crate::merkle::MerkleNode;
use crate::tagged_hash::TaggedHash;
use crate::{
    CommitConceal, CommitEncode, CommitVerify, ConsensusCommit,
    PrehashedProtocol, TryCommitVerify,
};

/// Maximal depth of LNPBP-4 commitment tree.
pub const MAX_TREE_DEPTH: u8 = 16;

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
pub type ProtocolId = Slice32;

/// Original message participating in multi-message commitment.
///
/// The message must be represented by a SHA256 tagged hash. Since each message
/// may have a different tag, we can't use [`sha256t`] type directly and use its
/// [`sha256::Hash`] equivalent.
pub type Message = sha256::Hash;

// SHA256("LNPBP4:entropy")
const MIDSTATE_ENTROPY: [u8; 32] = [
    0xF4, 0x0D, 0x86, 0x94, 0x9F, 0xFF, 0xAD, 0xEE, 0x19, 0xEA, 0x50, 0x20,
    0x60, 0xAB, 0x6B, 0xAD, 0x11, 0x61, 0xB2, 0x35, 0x83, 0xD3, 0x78, 0x18,
    0x52, 0x0D, 0xD4, 0xD1, 0xD8, 0x88, 0x1E, 0x61,
];

// TODO: Fix value
// SHA256("LNPBP4:leaf")
const MIDSTATE_LEAF: [u8; 32] = [
    0x23, 0x4B, 0x4D, 0xBA, 0x22, 0x2A, 0x64, 0x1C, 0x7F, 0x74, 0xD5, 0xC9,
    0x80, 0x17, 0x36, 0x1A, 0x90, 0x76, 0x4F, 0xB3, 0xC2, 0xB1, 0xA1, 0x6F,
    0xDE, 0x28, 0x66, 0x89, 0xF1, 0xCC, 0x99, 0x3F,
];

// TODO: Fix value
// SHA256("LNPBP4:node")
const MIDSTATE_NODE: [u8; 32] = [
    0x23, 0x4B, 0x4D, 0xBA, 0x22, 0x2A, 0x64, 0x1C, 0x7F, 0x74, 0xD5, 0xC9,
    0x80, 0x17, 0x36, 0x1A, 0x90, 0x76, 0x4F, 0xB3, 0xC2, 0xB1, 0xA1, 0x6F,
    0xDE, 0x28, 0x66, 0x89, 0xF1, 0xCC, 0x99, 0x3F,
];

// SHA256("LNPBP4")
const MIDSTATE_LNPBP4: [u8; 32] = [
    0x23, 0x4B, 0x4D, 0xBA, 0x22, 0x2A, 0x64, 0x1C, 0x7F, 0x74, 0xD5, 0xC9,
    0x80, 0x17, 0x36, 0x1A, 0x90, 0x76, 0x4F, 0xB3, 0xC2, 0xB1, 0xA1, 0x6F,
    0xDE, 0x28, 0x66, 0x89, 0xF1, 0xCC, 0x99, 0x3F,
];

/// Tag used for [`MultiCommitment`] hash type
pub struct Lnpbp4Tag;

impl sha256t::Tag for Lnpbp4Tag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash (with [`Lnpbp4Tag`]) of the sequentially serialized
/// [`MultiCommitBlock::commitments`].
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From
)]
#[derive(StrictEncode, StrictDecode)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct MultiCommitment(sha256t::Hash<Lnpbp4Tag>);

impl<M> CommitVerify<M, PrehashedProtocol> for MultiCommitment
where
    M: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &M) -> MultiCommitment { MultiCommitment::hash(msg) }
}

#[cfg(feature = "rand")]
impl TryCommitVerify<MultiSource, PrehashedProtocol> for MultiCommitment {
    type Error = Error;

    fn try_commit(msg: &MultiSource) -> Result<Self, Self::Error> {
        Ok(MerkleTree::try_commit(msg)?.consensus_commit())
    }
}

/// Structured source multi-message data for commitment creation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MultiSource {
    /// Minimal depth of the created LNPBP-4 commitment tree
    pub min_depth: u8,
    /// Map of the messages by their respective protocol ids
    pub messages: MessageMap,
}

impl Default for MultiSource {
    fn default() -> Self {
        MultiSource {
            min_depth: 3,
            messages: Default::default(),
        }
    }
}

/// Map from protocol ids to commitment messages.
pub type MessageMap = BTreeMap<ProtocolId, Message>;

/// Errors generated during multi-message commitment process by
/// [`MerkleTree::try_commit`]
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error, Debug, Display
)]
#[display(doc_comments)]
pub enum Error {
    /// can't create commitment for an empty message list and zero tree depth.
    Empty,

    /// number of messages ({0}) for LNPBP-4 commitment which exceeds the
    /// protocol limit of 2^16
    TooManyMessages(usize),

    /// the provided number of messages can't fit LNPBP-4 commitment size
    /// limits for a given set of protocol ids.
    CantFitInMaxSlots,
}

/// Complete information about LNPBP-4 merkle tree.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct MerkleTree {
    /// Tree depth (up to 16).
    #[getter(as_copy)]
    depth: u8,

    /// Entropy used for placeholders.
    #[getter(as_copy)]
    entropy: u64,

    /// Map of the messages by their respective protocol ids
    messages: MessageMap,
}

impl CommitEncode for MerkleTree {
    fn commit_encode<E: Write>(&self, e: E) -> usize {
        let commitment = self.commit_conceal();
        commitment.strict_encode(e).expect("memory encoder failure")
    }
}

impl CommitConceal for MerkleTree {
    type ConcealedCommitment = MultiCommitment;

    /// Reduces merkle tree into merkle tree root.
    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        let map = self
            .ordered_map()
            .expect("internal MerkleTree inconsistency");

        let mut layer = (0..=self.width())
            .into_iter()
            .map(|pos| {
                map.get(&pos)
                    .map(|(protocol_id, message)| {
                        TreeNode::CommitmentLeaf {
                            protocol_id: *protocol_id,
                            message: *message,
                        }
                        .merkle_node_with(self.depth)
                    })
                    .unwrap_or_else(|| {
                        MerkleNode::with_entropy(self.entropy, pos as u16)
                    })
            })
            .collect::<Vec<_>>();

        for depth in (0..self.depth).rev() {
            for pos in 0..(layer.len() - 1) {
                let (n1, n2) = (layer[pos], layer[pos + 1]);
                layer[pos] = MerkleNode::with_branch(
                    n1, n2, self.depth, depth, pos as u16,
                );
                layer.remove(pos + 1);
            }
        }

        debug_assert_eq!(layer.len(), 1);

        MultiCommitment::hash(&layer[0][..])
    }
}

impl ConsensusCommit for MerkleTree {
    type Commitment = MultiCommitment;
}

#[cfg(feature = "rand")]
mod commit {
    use rand::{thread_rng, RngCore};

    use super::*;
    use crate::{PrehashedProtocol, TryCommitVerify};

    impl TryCommitVerify<MultiSource, PrehashedProtocol> for MerkleTree {
        type Error = Error;

        fn try_commit(source: &MultiSource) -> Result<Self, Error> {
            if source.min_depth == 0 && source.messages.is_empty() {
                return Err(Error::Empty);
            }

            let entropy = thread_rng().next_u64();

            let mut tree = MerkleTree {
                depth: source.min_depth,
                messages: source.messages.clone(),
                entropy,
            };

            if source.messages.len() > 2usize.pow(MAX_TREE_DEPTH as u32) {
                return Err(Error::TooManyMessages(source.messages.len()));
            }

            let mut depth = tree.depth as usize;
            loop {
                if depth > MAX_TREE_DEPTH as usize {
                    return Err(Error::CantFitInMaxSlots);
                }
                tree.depth = depth as u8;

                if tree.ordered_map().is_some() {
                    return Ok(tree);
                }
                depth += 1;
            }
        }
    }
}

fn protocol_id_pos(protocol_id: ProtocolId, len: usize) -> u16 {
    let rem =
        u256::from_le_bytes(protocol_id.into_inner()) % u256::from(len as u64);
    rem.low_u64() as u16
}

impl MerkleTree {
    /// Computes the width of the merkle tree.
    pub fn width(&self) -> usize { 2usize.pow(self.depth as u32) }

    fn ordered_map(&self) -> Option<BTreeMap<usize, (ProtocolId, Message)>> {
        let mut ordered = BTreeMap::<usize, (ProtocolId, Message)>::new();
        if self.messages.iter().all(|(protocol, message)| {
            let pos = protocol_id_pos(*protocol, self.width());
            ordered
                .insert(pos as usize, (*protocol, *message))
                .is_none()
        }) {
            Some(ordered)
        } else {
            None
        }
    }
}

/// LNPBP-4 Merkle tree node.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
enum TreeNode {
    /// A node of the tree with concealed leaf or tree branch information.
    ConcealedNode {
        /// Depth of the node.
        depth: u8,
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

impl MerkleNode {
    fn with_commitment(
        protocol_id: ProtocolId,
        message: Message,
        depth: u8,
    ) -> MerkleNode {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LEAF);
        let mut engine = sha256::HashEngine::from_midstate(midstate, 64);
        engine.input(&depth.to_le_bytes());
        engine.input(&protocol_id[..]);
        engine.input(&message[..]);
        MerkleNode::from_engine(engine)
    }

    fn with_entropy(entropy: u64, pos: u16) -> MerkleNode {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        let mut engine = sha256::HashEngine::from_midstate(midstate, 64);
        engine.input(&entropy.to_le_bytes());
        engine.input(&pos.to_le_bytes());
        MerkleNode::from_engine(engine)
    }

    fn with_branch(
        hash1: MerkleNode,
        hash2: MerkleNode,
        tree_depth: u8,
        node_depth: u8,
        offset: u16,
    ) -> MerkleNode {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_NODE);
        let mut engine = sha256::HashEngine::from_midstate(midstate, 64);
        engine.input(&tree_depth.to_le_bytes());
        engine.input(&node_depth.to_le_bytes());
        engine.input(&offset.to_le_bytes());
        engine.input(&hash1[..]);
        engine.input(&hash2[..]);
        MerkleNode::from_engine(engine)
    }
}

impl TreeNode {
    fn with(
        hash1: MerkleNode,
        hash2: MerkleNode,
        tree_depth: u8,
        node_depth: u8,
        offset: u16,
    ) -> TreeNode {
        TreeNode::ConcealedNode {
            depth: node_depth,
            hash: MerkleNode::with_branch(
                hash1, hash2, tree_depth, node_depth, offset,
            ),
        }
    }

    pub fn merkle_node_with(&self, depth: u8) -> MerkleNode {
        match self {
            TreeNode::ConcealedNode { hash, .. } => *hash,
            TreeNode::CommitmentLeaf {
                protocol_id,
                message,
            } => MerkleNode::with_commitment(*protocol_id, *message, depth),
        }
    }
}

/// Partially-concealed merkle tree data.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct MerkleBlock {
    /// Tree depth (up to 16).
    #[getter(as_copy)]
    depth: u8,

    /// Tree cross-section.
    #[getter(skip)]
    cross_section: Vec<TreeNode>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`TryCommitVerify::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

impl From<&MerkleTree> for MerkleBlock {
    fn from(tree: &MerkleTree) -> Self {
        let map = tree
            .ordered_map()
            .expect("internal MerkleTree inconsistency");

        let cross_section = (0..=tree.width())
            .into_iter()
            .map(|pos| {
                map.get(&pos)
                    .map(|(protocol_id, message)| TreeNode::CommitmentLeaf {
                        protocol_id: *protocol_id,
                        message: *message,
                    })
                    .unwrap_or_else(|| TreeNode::ConcealedNode {
                        depth: tree.depth,
                        hash: MerkleNode::with_entropy(
                            tree.entropy,
                            pos as u16,
                        ),
                    })
            })
            .collect();

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

/// commitment under protocol id {0} is absent from the known part of a given
/// LNPBP-4 Merkle block.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct LeafNotKnown(ProtocolId);

impl MerkleBlock {
    /// Conceals all commitments in the block except for the commitment under
    /// given `protocol_id`. Also removes information about the entropy value
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
        protocol_id: ProtocolId,
    ) -> Result<usize, LeafNotKnown> {
        let mut count = 0usize;
        let mut found = false;

        self.entropy = None;

        // Conceal all leafs except of one
        for node in &mut self.cross_section {
            match node {
                TreeNode::ConcealedNode { .. } => {
                    // Do nothing
                }
                TreeNode::CommitmentLeaf { protocol_id: p, .. }
                    if *p == protocol_id =>
                {
                    found = true;
                }
                TreeNode::CommitmentLeaf { .. } => {
                    count += 1;
                    *node = TreeNode::ConcealedNode {
                        depth: self.depth,
                        hash: node.merkle_node_with(self.depth),
                    };
                }
            }
        }

        if !found {
            return Err(LeafNotKnown(protocol_id));
        }

        loop {
            assert!(!self.cross_section.is_empty());
            let prev_count = count;
            for pos in 0..self.cross_section.len() - 1 {
                let (n1, n2) =
                    (self.cross_section[pos], self.cross_section[pos + 1]);
                match (n1, n2) {
                    (
                        TreeNode::ConcealedNode {
                            depth: depth1,
                            hash: hash1,
                        },
                        TreeNode::ConcealedNode {
                            depth: depth2,
                            hash: hash2,
                        },
                    ) if depth1 == depth2 => {
                        count += 1;
                        self.cross_section[pos] = TreeNode::with(
                            hash1, hash2, self.depth, depth1, pos as u16,
                        );
                        self.cross_section.remove(pos + 1);
                    }
                    _ => {}
                }
            }
            if count == prev_count {
                break;
            }
        }

        Ok(count)
    }
}

/// A proof of the merkle commitment.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct MerkleProof {
    /// Position of the leaf in the tree.
    ///
    /// Used to determine chirality of the node hashing partners on each step
    /// of the path.
    #[getter(as_copy)]
    pos: u16,

    /// Merkle proof path consisting of node hashing partners.
    path: Vec<MerkleNode>,
}
