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

use amplify::num::u256;
use amplify::{Slice32, Wrapper};
use bitcoin_hashes::sha256;

use crate::merkle::MerkleNode;

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
    /// Number of messages ({0}) for LNPBP-4 commitment which exceeds the
    /// protocol limit of 2^16
    TooManyMessages(usize),

    /// The provided number of messages can't fit LNPBP-4 commitment size
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

#[cfg(feature = "rand")]
mod commit {
    use rand::{thread_rng, RngCore};

    use super::*;
    use crate::{TryCommitVerify, UntaggedProtocol};

    impl TryCommitVerify<MultiSource, UntaggedProtocol> for MerkleTree {
        type Error = Error;

        fn try_commit(source: &MultiSource) -> Result<Self, Error> {
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
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub enum TreeNode {
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
    cross_section: Vec<TreeNode>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`TryCommitVerify::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

impl From<&MerkleTree> for MerkleBlock {
    fn from(tree: &MerkleTree) -> Self {
        MerkleBlock {
            depth: tree.depth,
            cross_section: tree
                .messages
                .iter()
                .map(|(protocol_id, message)| TreeNode::CommitmentLeaf {
                    protocol_id: *protocol_id,
                    message: *message,
                })
                .collect(),
            entropy: Some(tree.entropy),
        }
    }
}

impl From<MerkleTree> for MerkleBlock {
    fn from(tree: MerkleTree) -> Self { MerkleBlock::from(&tree) }
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
