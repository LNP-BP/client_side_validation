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

use amplify::confinement::{SmallOrdMap, SmallVec};
use amplify::num::{u256, u4};
use amplify::Wrapper;

#[cfg(feature = "rand")]
pub use self::commit::Error;
use crate::merkle::MerkleNode;
use crate::mpc::atoms::Leaf;
use crate::mpc::{Commitment, Message, MessageMap, Proof, ProtocolId, MERKLE_LNPBP4_TAG};
use crate::{CommitmentId, Conceal, LIB_NAME_COMMIT_VERIFY};

/// Number of cofactor variants tried before moving to the next tree depth.
#[allow(dead_code)]
const COFACTOR_ATTEMPTS: u16 = 500;

type OrderedMap = SmallOrdMap<u16, (ProtocolId, Message)>;

/// Complete information about LNPBP-4 merkle tree.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, conceal, strategy = strict)]
pub struct MerkleTree {
    /// Tree depth (up to 16).
    pub(super) depth: u4,

    /// Entropy used for placeholders.
    pub(super) entropy: u64,

    /// Cofactor is used as an additive to the modulo divisor to improve packing
    /// of protocols inside a tree of a given depth.
    pub(super) cofactor: u16,

    /// Map of the messages by their respective protocol ids
    pub(super) messages: MessageMap,

    pub(super) map: OrderedMap,
}

impl Proof for MerkleTree {}

impl CommitmentId for MerkleTree {
    const TAG: [u8; 32] = *b"urn:lnpbp:lnpbp0004:tree:v01#23A";
    type Id = Commitment;
}

impl MerkleTree {
    pub fn root(&self) -> MerkleNode {
        let iter = (0..self.width()).map(|pos| {
            self.map
                .get(&pos)
                .map(|(protocol, msg)| Leaf::inhabited(*protocol, *msg))
                .unwrap_or_else(|| Leaf::entropy(self.entropy, pos))
        });
        let leaves = SmallVec::try_from_iter(iter).expect("u16-bound size");
        MerkleNode::merklize(MERKLE_LNPBP4_TAG.to_be_bytes(), &leaves)
    }
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

        /// the provided number of messages ({0}) can't fit LNPBP-4 commitment
        /// size limits for a given set of protocol ids.
        CantFitInMaxSlots(usize),
    }

    impl TryCommitVerify<MultiSource, UntaggedProtocol> for MerkleTree {
        type Error = Error;

        fn try_commit(source: &MultiSource) -> Result<Self, Error> {
            use std::collections::BTreeMap;

            let msg_count = source.messages.len();

            if source.min_depth == u4::ZERO && source.messages.is_empty() {
                return Err(Error::Empty);
            }
            if msg_count > 2usize.pow(u4::MAX.to_u8() as u32) {
                return Err(Error::TooManyMessages(msg_count));
            }

            let entropy = thread_rng().next_u64();

            let mut map = BTreeMap::<u16, (ProtocolId, Message)>::new();

            let mut depth = source.min_depth;
            let mut prev_width = 1;
            loop {
                let width = 2usize.pow(depth.to_u8() as u32) as u16;
                for cofactor in 0..=(prev_width.min(COFACTOR_ATTEMPTS)) {
                    map.clear();
                    if source.messages.iter().all(|(protocol, message)| {
                        let pos = protocol_id_pos(*protocol, cofactor, width);
                        map.insert(pos, (*protocol, *message)).is_none()
                    }) {
                        return Ok(MerkleTree {
                            depth,
                            entropy,
                            cofactor,
                            messages: source.messages.clone(),
                            map: Confined::try_from(map).expect("MultiSource type guarantees"),
                        });
                    }
                }

                prev_width = width;
                depth = depth
                    .checked_add(1)
                    .ok_or(Error::CantFitInMaxSlots(msg_count))?;
            }
        }
    }
}

pub(super) fn protocol_id_pos(protocol_id: ProtocolId, cofactor: u16, width: u16) -> u16 {
    debug_assert_ne!(width, 0);
    let rem = u256::from_le_bytes((*protocol_id).into_inner()) %
        u256::from(width.saturating_sub(cofactor as u16).max(1) as u64);
    rem.low_u64() as u16
}

impl MerkleTree {
    /// Computes position for a given `protocol_id` within the tree leaves.
    pub fn protocol_id_pos(&self, protocol_id: ProtocolId) -> u16 {
        protocol_id_pos(protocol_id, self.cofactor, self.width())
    }

    /// Computes the width of the merkle tree.
    pub fn width(&self) -> u16 { 2usize.pow(self.depth.to_u8() as u32) as u16 }

    pub fn depth(&self) -> u4 { self.depth }

    pub fn entropy(&self) -> u64 { self.entropy }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::collections::BTreeMap;

    use amplify::confinement::Confined;
    use amplify::Bytes32;
    use rand::random;

    use super::*;
    use crate::mpc::MultiSource;
    use crate::TryCommitVerify;

    pub fn make_det_messages(no: u16) -> BTreeMap<ProtocolId, Message> {
        let mut msgs = BTreeMap::new();
        for _ in 0..no {
            let protocol_id = u256::from(no);
            let msg = random::<u8>();
            msgs.insert(
                ProtocolId::from(protocol_id.to_le_bytes()),
                Message::from_inner(Bytes32::with_fill(msg)),
            );
        }
        msgs
    }

    pub fn make_random_messages(no: u16) -> BTreeMap<ProtocolId, Message> {
        let mut msgs = BTreeMap::new();
        for _ in 0..no {
            let protocol_id = random::<u32>();
            let protocol_id = u256::from(protocol_id);
            let msg = random::<u8>();
            msgs.insert(
                ProtocolId::from(protocol_id.to_le_bytes()),
                Message::from_inner(Bytes32::with_fill(msg)),
            );
        }
        msgs
    }

    pub fn make_random_tree(msgs: &BTreeMap<ProtocolId, Message>) -> MerkleTree {
        let src = MultiSource {
            min_depth: u4::ZERO,
            messages: Confined::try_from_iter(msgs.iter().map(|(a, b)| (*a, *b))).unwrap(),
        };
        MerkleTree::try_commit(&src).unwrap()
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use amplify::num::u4;
    use rand::random;
    use sha2::Sha256;
    use strict_encoding::StrictEncode;

    use crate::mpc::tree::test_helpers::{make_random_messages, make_random_tree};
    use crate::mpc::MerkleTree;
    use crate::{CommitEncode, CommitmentId, Conceal, DigestExt};

    #[test]
    #[should_panic(expected = "Empty")]
    fn tree_empty() {
        let msgs = make_random_messages(0);
        make_random_tree(&msgs);
    }

    #[test]
    fn tree_sizing() {
        for size in 1..16 {
            let msgs = make_random_messages(size);
            make_random_tree(&msgs);
        }
        for exp in 5..=8 {
            let size = 2u16.pow(exp);

            let msgs = make_random_messages(size);
            make_random_tree(&msgs);

            let msgs = make_random_messages(size - 9);
            make_random_tree(&msgs);

            let msgs = make_random_messages(size + 13);
            make_random_tree(&msgs);
        }
    }

    #[test]
    #[should_panic(expected = "CantFitInMaxSlots(1024)")]
    fn tree_size_limits() {
        let msgs = make_random_messages(1024);
        make_random_tree(&msgs);
    }

    #[test]
    fn tree_structure() {
        let msgs = make_random_messages(9);
        let tree = make_random_tree(&msgs);
        assert!(tree.depth() > u4::with(3));
        assert!(tree.width() > 9);
        let mut set = BTreeSet::<u16>::new();
        for (pid, msg) in msgs {
            let pos = tree.protocol_id_pos(pid);
            assert!(set.insert(pos));
            assert_eq!(tree.messages.get(&pid), Some(&msg));
        }
    }

    #[test]
    fn tree_conceal() {
        let msgs = make_random_messages(9);
        let tree = make_random_tree(&msgs);
        assert_eq!(tree.conceal(), tree.root());
    }

    #[test]
    fn tree_id() {
        let msgs = make_random_messages(9);
        let tree = make_random_tree(&msgs);
        let id = tree.commitment_id();
        let root = tree.root();

        let mut enc1 = vec![];
        let mut enc2 = vec![];
        tree.commit_encode(&mut enc1);
        root.strict_write(usize::MAX, &mut enc2).unwrap();
        // Commitment encoding must be equal to the value of the Merkle root
        assert_eq!(enc1, enc2);

        let mut engine = Sha256::from_tag(MerkleTree::TAG);
        engine.input_raw(root.as_slice());
        let cmt = engine.finish();
        // Commitment id must be equal to the tag-hashed Merkle tree root
        assert_eq!(id.as_slice(), &cmt);
    }

    #[test]
    fn tree_id_entropy() {
        let msgs = make_random_messages(9);
        let mut tree = make_random_tree(&msgs);
        let id1 = tree.commitment_id();

        tree.entropy = loop {
            let entropy = random();
            if entropy != tree.entropy {
                break entropy;
            }
        };
        let id2 = tree.commitment_id();

        assert_ne!(id1, id2);
    }

    #[test]
    fn scalability() {
        let mut depths = vec![];
        let mut cofacs = vec![];
        for _ in 0..10 {
            let msgs = make_random_messages(500);
            let tree = make_random_tree(&msgs);
            depths.push(tree.depth.to_u8());
            cofacs.push(tree.cofactor);
        }
        let davg = depths.iter().map(|v| *v as u32).sum::<u32>() as f32 / 10f32;
        eprintln!("Depth: avg={davg:.2} {depths:?}");
        eprintln!("Cofactors: {cofacs:?}");
        assert!(davg <= 15f32);
    }
}
