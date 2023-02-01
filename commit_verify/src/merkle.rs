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

use std::io;

use amplify::hex::ToHex;
use amplify::num::u4;
use amplify::Bytes32;
use bitcoin_hashes::{sha256, Hash};

use crate::CommitEncode;

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(
    Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From
)]
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

impl MerkleNode {
    pub fn empty_node() -> Self { MerkleNode([0xFF; 32].into()) }

    pub fn commit(leaf: &impl CommitEncode) -> Self {
        let mut engine = sha256::HashEngine::default();
        leaf.commit_encode(&mut engine);
        sha256::Hash::from_engine(engine).into_inner().into()
    }
}

pub trait MerkleLeafs {
    type Leaf: CommitEncode;

    type LeafIter<'leaf>: Iterator<Item = &'leaf Self::Leaf> + ExactSizeIterator
    where
        Self: 'leaf;

    fn merkle_leafs(&self) -> Self::LeafIter<'_>;
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct MerkleRoot {
    pub root: MerkleNode,
    pub height: u4,
}

impl CommitEncode for MerkleRoot {
    fn commit_encode(&self, e: &mut impl io::Write) {
        e.write_all(self.root.as_slice())
            .expect("hash encoders must not error");
    }
}

// Tag string: `urn:lnpbp:merkle:node?depth=0,height=A,width=AF16`

impl MerkleRoot {
    /// Merklization procedure that uses tagged hashes with depth commitments
    /// according to [LNPBP-81] standard of client-side-validation merklization
    ///
    /// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
    pub fn merklize<I>(tag: u128, data: I) -> Self
    where
        I: IntoIterator<Item = MerkleNode>,
        <I as IntoIterator>::IntoIter: ExactSizeIterator<Item = MerkleNode>,
    {
        let iter = data.into_iter();
        let width = iter.len();

        // Tagging merkle tree root
        let prototype = Self::merklize_inner(tag, iter, 0, 0, false, None);
        let height = prototype.height;

        let tagged = format!(
            "urn:lnpbp:merkle:root?tag={tag:016X},height={height:01X},\
             width={width:04X},node={}",
            prototype.root.to_hex()
        );
        let tagged_root = sha256::Hash::hash(tagged.as_bytes());

        MerkleRoot {
            root: MerkleNode::from(tagged_root.into_inner()),
            height,
        }
    }

    // TODO: Optimize to avoid allocations
    // In current rust generic iterators do not work with recursion :(
    fn merklize_inner(
        tag: u128,
        mut iter: impl ExactSizeIterator<Item = MerkleNode>,
        depth: u8,
        offset: u16,
        extend: bool,
        empty_node: Option<MerkleNode>,
    ) -> Self {
        let len = iter.len() + extend as usize;
        let width = iter.len() as u16 + offset;

        let (tagged, height) = match len {
            0 => (
                format!(
                    "urn:lnpbp:merkle:void?tag={tag:016X},depth={depth:01X},\
                     height=1,width={width:04X}"
                ),
                u4::ONE,
            ),
            1 => (
                format!(
                    "urn:lnpbp:merkle:single?tag={tag:016X},depth={depth:01X},\
                     height=1,width={width:04X},branch={}",
                    iter.next().expect("len >= 1").to_hex(),
                ),
                u4::ONE,
            ),
            2 => (
                format!(
                    "urn:lnpbp:merkle:node?tag={tag:016X},depth={depth:01X},\
                     height=1,width={width:04X},branch1={},branch2={}",
                    iter.next().expect("len >= 2").to_hex(),
                    iter.next().expect("len >= 2").to_hex(),
                ),
                u4::ONE,
            ),
            len => {
                let div = len / 2 + len % 2;
                let empty_node =
                    empty_node.unwrap_or_else(MerkleNode::empty_node);

                let slice1 =
                    iter.by_ref().take(div).collect::<Vec<_>>().into_iter();
                let MerkleRoot {
                    root: node1,
                    height: height1,
                } = Self::merklize_inner(
                    tag,
                    // Normally we should use `iter.by_ref().take(div)`, but
                    // currently rust compilers is unable to parse
                    // recursion with generic types
                    slice1,
                    depth + 1,
                    0,
                    false,
                    Some(empty_node),
                );

                let iter = if extend {
                    iter.chain(vec![empty_node]).collect::<Vec<_>>().into_iter()
                } else {
                    iter.collect::<Vec<_>>().into_iter()
                };

                let MerkleRoot {
                    root: node2,
                    height: height2,
                } = Self::merklize_inner(
                    tag,
                    iter,
                    depth + 1,
                    div as u16 + 1,
                    (div % 2 + len % 2) / 2 == 1,
                    Some(empty_node),
                );

                debug_assert_eq!(
                    height1,
                    height2,
                    "merklization algorithm failure: height of subtrees is \
                     not equal (width={len}, depth={depth}, \
                     prev_extend={extend}, next_extend={})",
                    div % 2 == 1 && len % 2 == 1
                );

                let height = height1 + 1;
                let tagged = format!(
                    "urn:lnpbp:merkle:node?tag={tag:016X},depth={depth:01X},\
                     height={height:01X},width={width:04X},branch1={},\
                     branch2={}",
                    node1.to_hex(),
                    node2.to_hex(),
                );

                (tagged, height)
            }
        };

        let tagged_node = sha256::Hash::hash(tagged.as_bytes());
        MerkleRoot {
            root: MerkleNode::from(tagged_node.into_inner()),
            height,
        }
    }
}
