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

use std::collections::BTreeMap;

use amplify::confinement::SmallOrdMap;
use amplify::num::{u256, u4};
use amplify::Wrapper;

#[cfg(feature = "rand")]
pub use self::commit::Error;
use crate::merkle::{MerkleLeaves, MerkleNode};
use crate::mpc::atoms::Leaf;
use crate::mpc::{Message, MessageMap, Proof, ProtocolId, LNPBP4_TAG};
use crate::{Conceal, LIB_NAME_COMMIT_VERIFY};

type OrderedMap = SmallOrdMap<u16, (ProtocolId, Message)>;

/// Complete information about LNPBP-4 merkle tree.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
pub struct MerkleTree {
    /// Tree depth (up to 16).
    pub(super) depth: u4,

    /// Entropy used for placeholders.
    pub(super) entropy: u64,

    /// Map of the messages by their respective protocol ids
    pub(super) messages: MessageMap,

    pub(super) map: OrderedMap,
}

impl Proof for MerkleTree {}

pub struct IntoIter {
    width: u16,
    pos: u16,
    map: OrderedMap,
    entropy: u64,
}

impl Iterator for IntoIter {
    type Item = Leaf;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos == self.width {
            return None;
        }
        self.pos += 1;

        let leaf = self
            .map
            .get(&self.pos)
            .map(|(protocol, msg)| Leaf::inhabited(*protocol, *msg))
            .unwrap_or_else(|| Leaf::entropy(self.entropy, self.pos));

        Some(leaf)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remains = self.map.len() - self.pos as usize;
        (remains, Some(remains))
    }
}

impl ExactSizeIterator for IntoIter {}

impl MerkleLeaves for MerkleTree {
    type Leaf = Leaf;
    type LeafIter = IntoIter;

    fn merkle_leaves(&self) -> Self::LeafIter {
        IntoIter {
            entropy: self.entropy,
            width: self.width(),
            pos: 0,
            map: self.as_ordered_map().clone(), // TODO: Remove clone
        }
    }
}

impl MerkleTree {
    pub fn root(&self) -> MerkleNode { MerkleNode::merklize(LNPBP4_TAG, self) }
}

impl Conceal for MerkleTree {
    type Concealed = MerkleNode;

    fn conceal(&self) -> Self::Concealed { self.root() }
}

#[cfg(feature = "rand")]
mod commit {
    use amplify::confinement::Confined;
    use rand::{thread_rng, RngCore};

    use super::*;
    use crate::mpc::MultiSource;
    use crate::{TryCommitVerify, UntaggedProtocol};

    /// Errors generated during multi-message commitment process by
    /// [`MerkleTree::try_commit`]
    #[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error, Debug, Display)]
    #[display(doc_comments)]
    pub enum Error {
        /// can't create commitment for an empty message list and zero tree
        /// depth.
        Empty,

        /// number of messages ({0}) for LNPBP-4 commitment which exceeds the
        /// protocol limit of 2^16
        TooManyMessages(usize),

        /// the provided number of messages can't fit LNPBP-4 commitment size
        /// limits for a given set of protocol ids.
        CantFitInMaxSlots,
    }

    impl TryCommitVerify<MultiSource> for MerkleTree {
        type Protocol = UntaggedProtocol;
        type Error = Error;

        fn try_commit(source: &MultiSource) -> Result<Self, Error> {
            if source.min_depth == u4::ZERO && source.messages.is_empty() {
                return Err(Error::Empty);
            }
            if source.messages.len() > 2usize.pow(u4::MAX.to_u8() as u32) {
                return Err(Error::TooManyMessages(source.messages.len()));
            }

            let entropy = thread_rng().next_u64();

            let mut map = BTreeMap::<u16, (ProtocolId, Message)>::new();

            let mut depth = source.min_depth;
            loop {
                let width = 2usize.pow(depth.to_u8() as u32) as u16;
                if source.messages.iter().all(|(protocol, message)| {
                    let pos = protocol_id_pos(*protocol, width);
                    map.insert(pos, (*protocol, *message)).is_none()
                }) {
                    break;
                }

                depth += 1;
            }

            Ok(MerkleTree {
                depth,
                messages: source.messages.clone(),
                entropy,
                map: Confined::try_from(map).expect("MultiSource type guarantees"),
            })
        }
    }
}

pub(super) fn protocol_id_pos(protocol_id: ProtocolId, width: u16) -> u16 {
    let rem = u256::from_le_bytes((*protocol_id).into_inner()) % u256::from(width as u64);
    rem.low_u64() as u16
}

impl MerkleTree {
    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u16 {
        protocol_id_pos(protocol_id, self.width())
    }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> u16 { 2usize.pow(self.depth.to_u8() as u32) as u16 }

    pub fn depth(&self) -> u4 { self.depth }

    fn as_ordered_map(&self) -> &OrderedMap { &self.map }
}
