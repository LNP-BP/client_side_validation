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

use std::collections::BTreeSet;
use std::io::{self, Write};

use amplify::confinement::Confined;
use amplify::num::u4;
use amplify::Bytes32;
use bitcoin_hashes::{sha256, Hash};

use crate::encode::{strategies, CommitStrategy};
use crate::CommitEncode;

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
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, RangeOps)]
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

    pub fn branch(
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
        let mut engine = sha256::HashEngine::default();
        (&branching).commit_encode(&mut engine);
        engine.write_all(&tag).ok();
        (&depth.to_u8()).commit_encode(&mut engine);
        (&width).commit_encode(&mut engine);
        branch1.commit_encode(&mut engine);
        branch2.commit_encode(&mut engine);
        sha256::Hash::from_engine(engine).into_inner().into()
    }

    pub fn commit(leaf: &impl CommitEncode) -> Self {
        let mut engine = sha256::HashEngine::default();
        leaf.commit_encode(&mut engine);
        sha256::Hash::from_engine(engine).into_inner().into()
    }
}

impl CommitEncode for MerkleNode {
    fn commit_encode(&self, e: &mut impl io::Write) {
        e.write_all(self.as_slice())
            .expect("hash encoders must not error");
    }
}

impl MerkleNode {
    /// Merklization procedure that uses tagged hashes with depth commitments
    /// according to [LNPBP-81] standard of client-side-validation merklization
    ///
    /// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
    pub fn merklize(tag: [u8; 16], nodes: &impl MerkleLeafs) -> Self {
        Self::_merklize(tag, nodes.merkle_leafs(), u4::ZERO, 0)
    }

    fn _merklize<'leaf, Leaf: CommitEncode + 'leaf>(
        tag: [u8; 16],
        mut iter: impl MerkleIter<Leaf>,
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

            let slice = iter.by_ref().take(div as usize);
            let branch1 = Self::_merklize(tag, slice, depth + 1, 0);
            let branch2 = Self::_merklize(tag, iter, depth + 1, div + 1);

            MerkleNode::branch(tag, depth, width, branch1, branch2)
        }
    }
}

pub trait MerkleIter<Leaf: CommitEncode>: ExactSizeIterator<Item = Leaf> {}

impl<Leaf: CommitEncode, I> MerkleIter<Leaf> for I where I: ExactSizeIterator<Item = Leaf> {}

pub trait MerkleLeafs {
    type Leaf: CommitEncode;

    type LeafIter: MerkleIter<Self::Leaf>;

    fn merkle_leafs(&self) -> Self::LeafIter;
}

impl<'a, T, const MIN: usize> MerkleLeafs for &'a Confined<Vec<T>, MIN, { u16::MAX as usize }>
where &'a T: CommitEncode
{
    type Leaf = &'a T;
    type LeafIter = std::slice::Iter<'a, T>;

    fn merkle_leafs(&self) -> Self::LeafIter { self.iter() }
}

impl<'a, T: Ord, const MIN: usize> MerkleLeafs
    for &'a Confined<BTreeSet<T>, MIN, { u16::MAX as usize }>
where &'a T: CommitEncode
{
    type Leaf = &'a T;
    type LeafIter = std::collections::btree_set::Iter<'a, T>;

    fn merkle_leafs(&self) -> Self::LeafIter { self.iter() }
}
