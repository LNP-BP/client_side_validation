// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
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
//! specific protocol using [`MerkleBlock::conceal_except`] operation.
//! [`MerkleBlock`] can conceal sme data and can also be constructed from
//! (multiple) [`MerkleProof`] and/or other [`MerkleBlock`].
//!
//! Summary of the operations with LNPBP-4 data structures:
//!
//! - [`MerkleTree::try_commit`]: [`MultiSource`] -> [`MerkleTree`]
//! - [`MerkleBlock::from`]: [`MerkleTree`] -> `Self`
//! - [`MerkleBlock::into_merkle_proof`]: `Self`, [`ProtocolId`] ->
//!   [`MerkleProof`]
//! - [`MerkleBlock::with`]: [`MerkleProof`], [`ProtocolId`], [`Message`] ->
//!   `Self`
//! - [`MerkleBlock::merge_reveal`]: `Self`, [`MerkleProof`] -> `Self`
//!
//! [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Debug;
use std::io::Write;

use amplify::confinement::{SmallOrdMap, SmallVec};
use amplify::num::u256;
use amplify::{Bytes32, Wrapper};
use bitcoin_hashes::{sha256, sha256t, Hash, HashEngine};
use confined_encoding::{ConfinedDecode, ConfinedEncode, ConfinedTag};

use crate::merkle::MerkleNode;
use crate::tagged_hash::TaggedHash;
#[cfg(doc)]
use crate::TryCommitVerify;
use crate::{
    commit_encode, CommitConceal, CommitEncode, CommitVerify, ConsensusCommit,
    PrehashedProtocol,
};

/// Maximal depth of LNPBP-4 commitment tree.
pub const MAX_TREE_DEPTH: u8 = 16;

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
pub type ProtocolId = Bytes32;

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

// SHA256("LNPBP4:leaf")
const MIDSTATE_LEAF: [u8; 32] = [
    0x82, 0x41, 0x89, 0x6d, 0xab, 0x0b, 0x37, 0x0c, 0x4a, 0x8d, 0x47, 0x65,
    0xcb, 0x19, 0x42, 0x68, 0xaa, 0x75, 0x7c, 0xa0, 0xbf, 0xd1, 0x95, 0x61,
    0x32, 0x9b, 0xa6, 0x3a, 0x46, 0x61, 0x31, 0xb8,
];

// SHA256("LNPBP4:node")
const MIDSTATE_NODE: [u8; 32] = [
    0x24, 0xdd, 0x37, 0xf7, 0x3f, 0x87, 0x8e, 0xbc, 0x86, 0x51, 0x5e, 0x58,
    0x19, 0x3d, 0x8a, 0x14, 0xf6, 0xc8, 0x0f, 0xb3, 0x9d, 0x94, 0xd0, 0x61,
    0xb8, 0xd6, 0x43, 0x04, 0x34, 0x9a, 0x7b, 0xb5,
];

// SHA256("LNPBP4")
const MIDSTATE_LNPBP4: [u8; 32] = [
    0x23, 0x4B, 0x4D, 0xBA, 0x22, 0x2A, 0x64, 0x1C, 0x7F, 0x74, 0xD5, 0xC9,
    0x80, 0x17, 0x36, 0x1A, 0x90, 0x76, 0x4F, 0xB3, 0xC2, 0xB1, 0xA1, 0x6F,
    0xDE, 0x28, 0x66, 0x89, 0xF1, 0xCC, 0x99, 0x3F,
];

/// Marker trait for variates of LNPBP-4 commitment proofs, which differ by the
/// amount of concealed information.
pub trait Proof: ConfinedEncode + ConfinedDecode + Clone + Eq + Debug {}

/// Tag used for [`CommitmentHash`] hash type
pub struct Lnpbp4Tag;

impl sha256t::Tag for Lnpbp4Tag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

impl ConfinedTag for Lnpbp4Tag {
    const TYPE_NAME: &'static str = "Lnpbp4";
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash (with [`Lnpbp4Tag`]) of the merkle root of
/// [`MerkleTree`] and [`MerkleBlock`].
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From
)]
#[derive(ConfinedEncode, ConfinedDecode)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct CommitmentHash(sha256t::Hash<Lnpbp4Tag>);

impl commit_encode::Strategy for CommitmentHash {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl<M> CommitVerify<M, PrehashedProtocol> for CommitmentHash
where
    M: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &M) -> CommitmentHash { CommitmentHash::hash(msg) }
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
pub type MessageMap = SmallOrdMap<ProtocolId, Message>;

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

/// Iterator over messages in [`MerkleTree`] and [`MerkleBlock`].
pub struct MessageIter(std::vec::IntoIter<Message>);

impl Iterator for MessageIter {
    type Item = Message;

    fn next(&mut self) -> Option<Self::Item> { self.0.next() }
}

/// Complete information about LNPBP-4 merkle tree.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(ConfinedEncode, ConfinedDecode)]
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

impl Proof for MerkleTree {}

impl CommitConceal for MerkleTree {
    type ConcealedCommitment = MerkleNode;

    /// Reduces merkle tree into merkle tree root.
    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        let map = self
            .ordered_map()
            .expect("internal MerkleTree inconsistency");

        let mut layer = (0..self.width())
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
            let mut pos = 0usize;
            let mut len = layer.len() - 1;
            while pos < len {
                let (n1, n2) = (layer[pos], layer[pos + 1]);
                layer[pos] = MerkleNode::with_branch(
                    n1, n2, self.depth, depth, pos as u16,
                );
                layer.remove(pos + 1);
                len -= 1;
                pos += 1;
            }
        }

        debug_assert_eq!(layer.len(), 1);

        layer[0]
    }
}

impl CommitEncode for MerkleTree {
    fn commit_encode(&self, e: &mut impl Write) {
        let commitment = self.commit_conceal();
        commitment
            .confined_encode(e)
            .expect("memory encoder failure");
    }
}

impl ConsensusCommit for MerkleTree {
    type Commitment = CommitmentHash;
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

impl IntoIterator for MerkleTree {
    type Item = Message;
    type IntoIter = MessageIter;

    #[allow(clippy::needless_collect)]
    fn into_iter(self) -> Self::IntoIter {
        let messages = self.messages.values().copied().collect::<Vec<_>>();
        MessageIter(messages.into_iter())
    }
}

fn protocol_id_pos(protocol_id: ProtocolId, width: usize) -> u16 {
    let rem = u256::from_le_bytes(protocol_id.into_inner())
        % u256::from(width as u64);
    rem.low_u64() as u16
}

impl MerkleTree {
    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u16 {
        protocol_id_pos(protocol_id, self.width())
    }

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
#[derive(ConfinedEncode, ConfinedDecode)]
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

    pub fn depth(&self) -> Option<u8> {
        match self {
            TreeNode::ConcealedNode { depth, .. } => Some(*depth),
            TreeNode::CommitmentLeaf { .. } => None,
        }
    }

    pub fn depth_or(&self, tree_depth: u8) -> u8 {
        self.depth().unwrap_or(tree_depth)
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
#[derive(ConfinedEncode, ConfinedDecode)]
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
    cross_section: SmallVec<TreeNode>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`MerkleTree::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

impl Proof for MerkleBlock {}

impl From<&MerkleTree> for MerkleBlock {
    fn from(tree: &MerkleTree) -> Self {
        let map = tree
            .ordered_map()
            .expect("internal MerkleTree inconsistency");

        let iter = (0..tree.width()).into_iter().map(|pos| {
            map.get(&pos)
                .map(|(protocol_id, message)| TreeNode::CommitmentLeaf {
                    protocol_id: *protocol_id,
                    message: *message,
                })
                .unwrap_or_else(|| TreeNode::ConcealedNode {
                    depth: tree.depth,
                    hash: MerkleNode::with_entropy(tree.entropy, pos as u16),
                })
        });
        let cross_section = SmallVec::try_from_iter(iter)
            .expect("tree width guarantees are broken");

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

impl CommitConceal for MerkleBlock {
    type ConcealedCommitment = MerkleNode;

    /// Reduces merkle tree into merkle tree root.
    fn commit_conceal(&self) -> Self::ConcealedCommitment {
        let mut concealed = self.clone();
        concealed
            .conceal_except([])
            .expect("broken internal MerkleBlock structure");
        debug_assert_eq!(concealed.cross_section.len(), 1);
        concealed.cross_section[0].merkle_node_with(0)
    }
}

impl CommitEncode for MerkleBlock {
    fn commit_encode(&self, e: &mut impl Write) {
        let commitment = self.commit_conceal();
        commitment
            .confined_encode(e)
            .expect("memory encoder failure")
    }
}

impl ConsensusCommit for MerkleBlock {
    type Commitment = CommitmentHash;
}

impl IntoIterator for &MerkleBlock {
    type Item = Message;
    type IntoIter = MessageIter;

    #[allow(clippy::needless_collect)]
    fn into_iter(self) -> Self::IntoIter {
        let messages = self
            .cross_section
            .iter()
            .filter_map(|node| match node {
                TreeNode::ConcealedNode { .. } => None,
                TreeNode::CommitmentLeaf { message, .. } => Some(*message),
            })
            .collect::<Vec<_>>();
        MessageIter(messages.into_iter())
    }
}

/// commitment under protocol id {_0} is absent from the known part of a given
/// LNPBP-4 Merkle block.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct LeafNotKnown(ProtocolId);

/// attempt to merge unrelated LNPBP-4 proof.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display(doc_comments)]
pub struct UnrelatedProof;

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

        if protocol_id_pos(protocol_id, width as usize) != pos {
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
                depth: depth as u8 + 1,
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
        let cross_section = SmallVec::try_from(cross_section)
            .expect("tree width guarantees are broken");

        Ok(MerkleBlock {
            depth: path.len() as u8,
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
                TreeNode::CommitmentLeaf { protocol_id: p, .. }
                    if protocols.contains(p) =>
                {
                    not_found.remove(p);
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
                let (n1, n2) = (
                    self.cross_section[pos],
                    self.cross_section.get(pos + 1).copied(),
                );
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
                        let height = self.depth as u32 - depth as u32;
                        let pow = 2u16.pow(height);
                        let offset_at_depth = offset / pow;
                        if offset % pow != 0 {
                            offset +=
                                2u16.pow(self.depth as u32 - depth1 as u32);
                        } else {
                            self.cross_section[pos] = TreeNode::with(
                                hash1,
                                hash2,
                                self.depth,
                                depth,
                                offset_at_depth,
                            );
                            self.cross_section
                                .remove(pos + 1)
                                .expect("we allow 0 elements");
                            count += 1;
                            offset += pow;
                            len -= 1;
                        }
                    }
                    (
                        TreeNode::CommitmentLeaf { .. },
                        Some(TreeNode::CommitmentLeaf { .. }),
                    ) => {
                        offset += 2;
                        pos += 1;
                    }
                    (
                        TreeNode::CommitmentLeaf { .. },
                        Some(TreeNode::ConcealedNode { depth, .. }),
                    )
                    | (
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
                        offset += 2u16.pow(self.depth as u32 - depth as u32);
                    }
                }
                pos += 1;
            }
            if count == prev_count {
                break;
            }
            debug_assert_eq!(offset, self.width() as u16);
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
    pub fn merge_reveal(
        &mut self,
        other: MerkleBlock,
    ) -> Result<u16, UnrelatedProof> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(UnrelatedProof);
        }

        let mut cross_section = Vec::with_capacity(
            self.cross_section.len() + other.cross_section.len(),
        );
        let mut a = self.cross_section.clone().into_iter();
        let mut b = other.cross_section.into_iter();

        let mut last_a = a.next();
        let mut last_b = b.next();
        while let (Some(n1), Some(n2)) = (last_a, last_b) {
            if n1 == n2 {
                cross_section.push(n1);
                last_a = a.next();
                last_b = b.next();
            } else if n1.depth_or(self.depth) < n2.depth_or(self.depth) {
                cross_section.push(n2);
                cross_section.extend(b.by_ref().take_while(|n| {
                    if n.depth_or(self.depth) > n1.depth_or(self.depth) {
                        last_b = None;
                        true
                    } else {
                        last_b = Some(*n);
                        false
                    }
                }));
                last_a = a.next();
            } else if n1.depth_or(self.depth) > n2.depth_or(self.depth) {
                cross_section.push(n1);
                cross_section.extend(a.by_ref().take_while(|n| {
                    if n.depth_or(self.depth) > n2.depth_or(self.depth) {
                        last_a = None;
                        true
                    } else {
                        last_a = Some(*n);
                        false
                    }
                }));
                last_b = b.next();
            } else {
                unreachable!("broken merkle block merge-reveal algorithm")
            }
        }

        self.cross_section = SmallVec::try_from(cross_section)
            .expect("tree width guarantees are broken");

        Ok(self.cross_section.len() as u16)
    }

    /// Converts the merkle block into a merkle proof for the inclusion of a
    /// commitment under given `protocol_id`.
    pub fn into_merkle_proof(
        mut self,
        protocol_id: ProtocolId,
    ) -> Result<MerkleProof, LeafNotKnown> {
        self.conceal_except([protocol_id])?;
        let mut map = BTreeMap::<u8, MerkleNode>::new();
        for node in &self.cross_section {
            match node {
                TreeNode::ConcealedNode { depth, hash } => {
                    let inserted = map.insert(*depth, *hash).is_none();
                    debug_assert!(
                        inserted,
                        "MerkleBlock conceal procedure is broken"
                    );
                }
                TreeNode::CommitmentLeaf { .. } => {}
            }
        }
        debug_assert_eq!(
            self.depth as usize,
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
    pub fn to_merkle_proof(
        &self,
        protocol_id: ProtocolId,
    ) -> Result<MerkleProof, LeafNotKnown> {
        self.clone().into_merkle_proof(protocol_id)
    }

    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u16 {
        protocol_id_pos(protocol_id, self.width())
    }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> usize { 2usize.pow(self.depth as u32) }
}

/// A proof of the merkle commitment.
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(ConfinedEncode, ConfinedDecode)]
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
    /// producing [`CommitmentHash`].
    pub fn convolve(
        &self,
        protocol_id: ProtocolId,
        message: Message,
    ) -> Result<CommitmentHash, UnrelatedProof> {
        let block = MerkleBlock::with(self, protocol_id, message)?;
        Ok(block.consensus_commit())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::TryCommitVerify;

    fn gen_proto_id(index: usize) -> ProtocolId {
        let hash = sha256::Hash::hash(format!("protocol#{}", index).as_bytes());
        ProtocolId::from(hash.into_inner())
    }

    fn gen_msg(index: usize) -> Message {
        Message::hash(format!("message#{}", index).as_bytes())
    }

    fn gen_source() -> MultiSource {
        MultiSource {
            min_depth: 3,
            messages: bmap! {
                gen_proto_id(0) => gen_msg(0),
                gen_proto_id(1) => gen_msg(1),
                gen_proto_id(2) => gen_msg(2)
            },
        }
    }

    #[test]
    fn test_lnpbp4_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        let tag_hash = sha256::Hash::hash(b"LNPBP4");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_entropy_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:entropy");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_leaf_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LEAF);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:leaf");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_node_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_NODE);
        let tag_hash = sha256::Hash::hash(b"LNPBP4:node");
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    fn test_tree() {
        let src = gen_source();

        let tree = MerkleTree::try_commit(&src).unwrap();
        assert_eq!(tree.depth, 3);
        assert_eq!(tree.width(), 8);

        assert_ne!(tree.commit_conceal()[..], tree.consensus_commit()[..]);
        assert_eq!(
            CommitmentHash::hash(tree.commit_conceal()),
            tree.consensus_commit()
        );

        let tree2 = MerkleTree::try_commit(&src).unwrap();
        assert_eq!(tree2.depth, 3);

        // Each time we must generate different randomness
        assert_ne!(tree.entropy, tree2.entropy);
        assert_ne!(tree, tree2);
        assert_ne!(tree.consensus_commit(), tree2.consensus_commit());
    }

    #[test]
    fn test_block() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let block = MerkleBlock::from(&tree);
        assert_eq!(tree.depth, block.depth);
        assert_eq!(tree.width(), block.width());
        assert_eq!(Some(tree.entropy), block.entropy);

        assert_eq!(tree.consensus_commit(), block.consensus_commit());

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();
        let second = iter.next().unwrap();
        let third = iter.next().unwrap();

        assert_eq!(block.cross_section[0], TreeNode::CommitmentLeaf {
            protocol_id: *third.0,
            message: *third.1,
        });
        assert_eq!(block.cross_section[3], TreeNode::CommitmentLeaf {
            protocol_id: *first.0,
            message: *first.1,
        });
        assert_eq!(block.cross_section[6], TreeNode::CommitmentLeaf {
            protocol_id: *second.0,
            message: *second.1,
        });

        assert_eq!(protocol_id_pos(*first.0, 8), 3);
        assert_eq!(protocol_id_pos(*second.0, 8), 6);
        assert_eq!(protocol_id_pos(*third.0, 8), 0);

        for pos in [1usize, 2, 4, 5, 7] {
            assert_eq!(block.cross_section[pos], TreeNode::ConcealedNode {
                depth: 3,
                hash: MerkleNode::with_entropy(tree.entropy, pos as u16)
            });
        }
    }

    #[test]
    fn test_block_conceal() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();

        let mut block = orig_block.clone();
        assert_eq!(block.conceal_except([*first.0]).unwrap(), 6);

        assert_eq!(block.entropy, None);

        assert_eq!(block.cross_section[0].depth().unwrap(), 2);
        assert_eq!(block.cross_section[1].depth().unwrap(), 3);
        assert_eq!(block.cross_section[3].depth().unwrap(), 1);
        assert_eq!(block.cross_section[2], TreeNode::CommitmentLeaf {
            protocol_id: *first.0,
            message: *first.1
        });

        assert_eq!(block.consensus_commit(), orig_block.consensus_commit());
    }

    #[test]
    fn test_proof() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        for ((proto, msg), pos) in src.messages.into_iter().zip([3, 6, 0]) {
            let mut block = orig_block.clone();
            block.conceal_except([proto]).unwrap();

            let proof1 = block.to_merkle_proof(proto).unwrap();
            let proof2 = orig_block.to_merkle_proof(proto).unwrap();

            assert_eq!(proof1, proof2);

            assert_eq!(proof1.pos, pos);
            if pos == 3 {
                assert_eq!(proof1.path, vec![
                    block.cross_section[3].merkle_node_with(1),
                    block.cross_section[0].merkle_node_with(2),
                    block.cross_section[1].merkle_node_with(3)
                ]);
            }

            assert_eq!(
                proof1.convolve(proto, msg).unwrap(),
                tree.consensus_commit()
            );
        }
    }

    #[test]
    fn test_proof_roundtrip() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let orig_block = MerkleBlock::from(&tree);

        for (proto, msg) in src.messages {
            let mut block = orig_block.clone();
            block.conceal_except([proto]).unwrap();
            assert_eq!(block.consensus_commit(), tree.consensus_commit());

            let proof = block.to_merkle_proof(proto).unwrap();
            let new_block = MerkleBlock::with(&proof, proto, msg).unwrap();
            assert_eq!(block, new_block);
            assert_eq!(block.consensus_commit(), new_block.consensus_commit());
        }
    }

    #[test]
    fn test_merge_reveal() {
        let src = gen_source();
        let tree = MerkleTree::try_commit(&src).unwrap();
        let mut orig_block = MerkleBlock::from(&tree);

        let mut iter = src.messages.iter();
        let first = iter.next().unwrap();

        let mut block = orig_block.clone();
        block.conceal_except([*first.0]).unwrap();

        let proof1 = block.to_merkle_proof(*first.0).unwrap();

        let mut new_block =
            MerkleBlock::with(&proof1, *first.0, *first.1).unwrap();
        assert_eq!(block, new_block);

        let second = iter.next().unwrap();
        let third = iter.next().unwrap();

        let proof2 = orig_block.to_merkle_proof(*second.0).unwrap();
        let proof3 = orig_block.to_merkle_proof(*third.0).unwrap();

        new_block
            .merge_reveal_path(&proof2, *second.0, *second.1)
            .unwrap();
        new_block
            .merge_reveal_path(&proof3, *third.0, *third.1)
            .unwrap();

        orig_block
            .conceal_except(src.messages.into_keys().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(orig_block, new_block);
    }
}
