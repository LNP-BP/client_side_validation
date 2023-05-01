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

use std::collections::BTreeSet;
use std::io::Write;

use amplify::confinement::Confined;
use amplify::num::u4;
use amplify::{Bytes32, Wrapper};

use crate::encode::{strategies, CommitStrategy};
use crate::{CommitEncode, Sha256, LIB_NAME_COMMIT_VERIFY};

/// Type of a merkle node branching.
#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub enum NodeBranching {
    /// Void node: virtual node with no leafs.
    ///
    /// Used when the total width of the three is not a power two.
    Void = 0x00,

    /// Node having just a single leaf, with the second branch being void.
    Single = 0x01,

    /// Node having two leafs.
    Couple = 0x02,

    /// Node having two branches.
    Branch = 0xFF,
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

const VIRTUAL_LEAF: MerkleNode = MerkleNode(Bytes32::from_array([0xFF; 32]));

impl MerkleNode {
    pub fn void(tag: [u8; 16], depth: u4, width: u16) -> Self {
        let virt = VIRTUAL_LEAF;
        Self::with(NodeBranching::Void, tag, depth, width, virt, virt)
    }

    pub fn single(tag: [u8; 16], depth: u4, width: u16, leaf: &impl CommitEncode) -> Self {
        let single = NodeBranching::Single;
        Self::with(single, tag, depth, width, Self::commit(leaf), VIRTUAL_LEAF)
    }

    pub fn couple<L: CommitEncode>(
        tag: [u8; 16],
        depth: u4,
        width: u16,
        leaf1: &L,
        leaf2: &L,
    ) -> Self {
        let couple = NodeBranching::Couple;
        let branch1 = Self::commit(leaf1);
        let branch2 = Self::commit(leaf2);
        Self::with(couple, tag, depth, width, branch1, branch2)
    }

    pub fn branches(
        tag: [u8; 16],
        depth: u4,
        width: u16,
        branch1: MerkleNode,
        branch2: MerkleNode,
    ) -> Self {
        Self::with(NodeBranching::Branch, tag, depth, width, branch1, branch2)
    }

    fn with(
        branching: NodeBranching,
        tag: [u8; 16],
        depth: u4,
        width: u16,
        branch1: MerkleNode,
        branch2: MerkleNode,
    ) -> Self {
        let mut engine = Sha256::default();
        branching.commit_encode(&mut engine);
        engine.write_all(&tag).ok();
        depth.to_u8().commit_encode(&mut engine);
        width.commit_encode(&mut engine);
        branch1.commit_encode(&mut engine);
        branch2.commit_encode(&mut engine);
        engine.finish().into()
    }

    pub fn commit(leaf: &impl CommitEncode) -> Self {
        let mut engine = Sha256::default();
        leaf.commit_encode(&mut engine);
        engine.finish().into()
    }
}

impl CommitStrategy for MerkleNode {
    type Strategy = strategies::Strict;
}

impl MerkleNode {
    /// Merklization procedure that uses tagged hashes with depth commitments
    /// according to [LNPBP-81] standard of client-side-validation merklization
    ///
    /// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
    pub fn merklize(tag: [u8; 16], nodes: &impl MerkleLeaves) -> Self {
        Self::_merklize(tag, nodes.merkle_leaves(), u4::ZERO, 0)
    }

    fn _merklize<'leaf, Leaf: CommitEncode + 'leaf>(
        tag: [u8; 16],
        mut iter: impl ExactSizeIterator<Item = Leaf>,
        depth: u4,
        offset: u16,
    ) -> Self {
        let len = iter.len() as u16;
        let width = len + offset;

        if len <= 2 {
            match (iter.next(), iter.next()) {
                (None, None) => MerkleNode::void(tag, depth, width),
                (Some(branch), None) => MerkleNode::single(tag, depth, width, &branch),
                (Some(branch1), Some(branch2)) => {
                    MerkleNode::couple(tag, depth, width, &branch1, &branch2)
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
            let branch1 = Self::_merklize(tag, slice, depth + 1, 0);
            let branch2 = Self::_merklize(tag, iter, depth + 1, div + 1);

            MerkleNode::branches(tag, depth, width, branch1, branch2)
        }
    }
}

pub trait MerkleLeaves {
    type Leaf: CommitEncode;

    type LeafIter: ExactSizeIterator<Item = Self::Leaf>;

    fn merkle_leaves(&self) -> Self::LeafIter;
}

impl<'a, T, const MIN: usize> MerkleLeaves for &'a Confined<Vec<T>, MIN, { u16::MAX as usize }>
where &'a T: CommitEncode
{
    type Leaf = &'a T;
    type LeafIter = std::slice::Iter<'a, T>;

    fn merkle_leaves(&self) -> Self::LeafIter { self.iter() }
}

impl<'a, T: Ord, const MIN: usize> MerkleLeaves
    for &'a Confined<BTreeSet<T>, MIN, { u16::MAX as usize }>
where &'a T: CommitEncode
{
    type Leaf = &'a T;
    type LeafIter = std::collections::btree_set::Iter<'a, T>;

    fn merkle_leaves(&self) -> Self::LeafIter { self.iter() }
}

/*
#[cfg(test)]
mod test {
    use std::collections::BTreeMap;

    use amplify::{bmap, s};
    use bitcoin_hashes::hex::ToHex;
    use bitcoin_hashes::{sha256d, Hash};
    use confined_encoding::{ConfinedDecode, ConfinedEncode};

    use super::*;
    use crate::commit_encode::{strategies, Strategy};
    use crate::CommitConceal;

    #[test]
    fn collections() {
        // First, we define a data type
        #[derive(
        Clone,
        PartialEq,
        Eq,
        PartialOrd,
        Ord,
        Hash,
        Debug,
        ConfinedEncode,
        ConfinedDecode
        )]
        struct Item(pub String);
        // Next, we say that it should be concealed using some function
        // (double SHA256 hash in this case)
        impl CommitConceal for Item {
            type ConcealedCommitment = sha256d::Hash;
            fn commit_conceal(&self) -> Self::ConcealedCommitment {
                sha256d::Hash::hash(self.0.as_bytes())
            }
        }
        // Next, we need to specify how the concealed data should be
        // commit-encoded: this time we strict-serialize the hash
        impl Strategy for sha256d::Hash {
            type Strategy = strategies::UsingStrict;
        }
        // Now, we define commitment encoding for our concealable type: it
        // should conceal the data
        impl Strategy for Item {
            type Strategy = strategies::UsingConceal;
        }
        // Now, we need to say that consensus commit procedure should produce
        // a final commitment from commit-encoded data (equal to the
        // strict encoding of the conceal result) using `CommitVerify` type.
        // Here, we use another round of hashing, producing merkle node hash
        // from the concealed data.
        impl ConsensusCommit for Item {
            type Commitment = MerkleNode;
        }
        // Next, we need to provide merkle node tags for each type of the tree
        impl ConsensusMerkleCommit for Item {
            const MERKLE_NODE_PREFIX: &'static str = "item";
        }
        impl ConsensusMerkleCommit for (usize, Item) {
            const MERKLE_NODE_PREFIX: &'static str = "usize->item";
        }

        impl ToMerkleSource for BTreeMap<usize, Item> {
            type Leaf = (usize, Item);
            fn to_merkle_source(&self) -> MerkleSource<Self::Leaf> {
                self.iter().map(|(k, v)| (*k, v.clone())).collect()
            }
        }

        let large = vec![Item(s!("none")); 3];
        let vec: MerkleSource<Item> = large.into();
        assert_eq!(
            vec.commit_serialize().to_hex(),
            "71ea45868fbd924061c4deb84f37ed82b0ac808de12aa7659afda7d9303e7a71"
        );

        let large = vec![Item(s!("none")); 5];
        let vec: MerkleSource<Item> = large.into();
        assert_eq!(
            vec.commit_serialize().to_hex(),
            "e255e0124efe0555fde0d932a0bc0042614129e1a02f7b8c0bf608b81af3eb94"
        );

        let large = vec![Item(s!("none")); 9];
        let vec: MerkleSource<Item> = large.into();
        assert_eq!(
            vec.commit_serialize().to_hex(),
            "6cd2d5345a654af4720bdcc637183ded8e432dc88f778b7d27c8d5a0e342c65f"
        );

        let large = vec![Item(s!("none")); 13];
        let vec: MerkleSource<Item> = large.into();
        assert_eq!(
            vec.commit_serialize().to_hex(),
            "3714c08c7c94a4ef769ad2cb7df9aaca1e1252d6599a02aff281c37e7242797d"
        );

        let large = vec![Item(s!("none")); 17];
        let vec: MerkleSource<Item> = large.into();
        assert_eq!(
            vec.commit_serialize().to_hex(),
            "6093dec47e5bdd706da01e4479cb65632eac426eb59c8c28c4e6c199438c8b6f"
        );

        let item = Item(s!("Some text"));
        assert_eq!(
            &b"\x09\x00Some text"[..],
            item.confined_serialize().unwrap()
        );
        assert_eq!(
            "6680bbec0d05d3eaac9c8b658c40f28d2f0cb0f245c7b1cabf5a61c35bd03d8e",
            item.commit_serialize().to_hex()
        );
        assert_eq!(
            "3e4b2dcf9bca33400028c8947565c1ff421f6d561e9ec48f88f0c9a24ebc8c30",
            item.consensus_commit().to_hex()
        );
        assert_ne!(item.commit_serialize(), item.confined_serialize().unwrap());
        assert_eq!(
            MerkleNode::hash(&item.commit_serialize()),
            item.consensus_commit()
        );

        let original = bmap! {
            0usize => Item(s!("My first case")),
            1usize => Item(s!("My second case with a very long string")),
            3usize => Item(s!("My third case to make the Merkle tree two layered"))
        };
        let collection = original.to_merkle_source();
        assert_eq!(
            &b"\x03\x00\
             \x00\x00\
             \x0d\x00\
             My first case\
             \x01\x00\
             \x26\x00\
             My second case with a very long string\
             \x03\x00\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            original.confined_serialize().unwrap()
        );
        assert_eq!(
            "d911717b8dfbbcef68495c93c0a5e69df618f5dcc194d69e80b6fafbfcd6ed5d",
            collection.commit_serialize().to_hex()
        );
        assert_eq!(
            "d911717b8dfbbcef68495c93c0a5e69df618f5dcc194d69e80b6fafbfcd6ed5d",
            collection.consensus_commit().to_hex()
        );
        assert_ne!(
            collection.commit_serialize(),
            original.confined_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::from_slice(&collection.commit_serialize()).unwrap(),
            collection.consensus_commit()
        );

        let original = vec![
            Item(s!("My first case")),
            Item(s!("My second case with a very long string")),
            Item(s!("My third case to make the Merkle tree two layered")),
        ];
        let vec: MerkleSource<Item> = original.clone().into();
        assert_eq!(
            &b"\x03\x00\
             \x0d\x00\
             My first case\
             \x26\x00\
             My second case with a very long string\
             \x31\x00\
             My third case to make the Merkle tree two layered"[..],
            original.confined_serialize().unwrap()
        );
        assert_eq!(
            "fd72061e26055fb907aa512a591b4291e739f15198eb72027c4dd6506f14f469",
            vec.commit_serialize().to_hex()
        );
        assert_eq!(
            "fd72061e26055fb907aa512a591b4291e739f15198eb72027c4dd6506f14f469",
            vec.consensus_commit().to_hex()
        );
        assert_ne!(
            vec.commit_serialize(),
            original.confined_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::from_slice(&vec.commit_serialize()).unwrap(),
            vec.consensus_commit()
        );
        assert_ne!(vec.consensus_commit(), collection.consensus_commit());
    }
}
*/
