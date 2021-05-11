// LNP/BP client-side-validation library implementing respective LNPBP
// specifications & standards (LNPBP-7, 8, 9, 42)
//
// Written in 2019-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

//! Merklization procedures for client-side-validation according to [LNPBP-81]
//! standard.
//!
//! [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md

use std::io;
use std::iter::FromIterator;

use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};

use crate::{commit_encode, CommitEncode, CommitVerify, ConsensusCommit};

/// Marker trait for types that require merklization of the underlying data
/// during [`ConsensusCommit`] procedure. Allows specifying custom tag for the
/// tagged hash used in the merklization (see [`merklize`]).
pub trait ConsensusMerkleCommit:
    ConsensusCommit<Commitment = MerkleNode>
{
    /// The tag which will be used in the merklization process (see
    /// [`merklize`])
    const MERKLE_NODE_TAG: &'static str;
}

hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "A hash of a arbitrary Merkle tree branch or root"
);

impl strict_encoding::Strategy for MerkleNode {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
}

impl commit_encode::Strategy for MerkleNode {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl<MSG> CommitVerify<MSG> for MerkleNode
where
    MSG: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &MSG) -> MerkleNode {
        MerkleNode::hash(msg.as_ref())
    }
}

impl<A, B> ConsensusCommit for (A, B)
where
    A: CommitEncode,
    B: CommitEncode,
{
    type Commitment = MerkleNode;
}

impl<A, B, C> ConsensusCommit for (A, B, C)
where
    A: CommitEncode,
    B: CommitEncode,
    C: CommitEncode,
{
    type Commitment = MerkleNode;
}

/// Merklization procedure that uses tagged hashes with depth commitments
pub fn merklize<N>(prefix: &str, data: &[N]) -> (MerkleNode, u8)
where
    N: AsRef<[u8]>,
{
    let mut tag_engine = sha256::Hash::engine();
    tag_engine.input(prefix.as_bytes());
    tag_engine.input(":merkle:".as_bytes());
    merklize_inner(&tag_engine, data, 0, false, None)
}

fn merklize_inner<N>(
    engine_proto: &sha256::HashEngine,
    data: &[N],
    depth: u8,
    extend: bool,
    empty_node: Option<MerkleNode>,
) -> (MerkleNode, u8)
where
    N: AsRef<[u8]>,
{
    let len = data.len();
    let mut iter = data.iter();
    let ext_len = len + if extend { 1 } else { 0 };
    let empty_node = empty_node.unwrap_or_else(|| MerkleNode::hash(&[0xFF]));

    // Computing tagged hash as per BIP-340
    let mut tag_engine = engine_proto.clone();
    tag_engine.input("depth=".as_bytes());
    tag_engine.input(depth.to_string().as_bytes());
    tag_engine.input(":width=".as_bytes());
    tag_engine.input(len.to_string().as_bytes());
    tag_engine.input(":height=".as_bytes());

    let mut engine = MerkleNode::engine();
    if ext_len <= 2 {
        tag_engine.input("0:".as_bytes());
        let tag_hash =
            sha256::Hash::hash(&sha256::Hash::from_engine(tag_engine));
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);

        let mut leaf_tag_engine = engine_proto.clone();
        leaf_tag_engine.input("leaf".as_bytes());
        let leaf_tag =
            sha256::Hash::hash(&sha256::Hash::from_engine(leaf_tag_engine));
        let mut leaf_engine = MerkleNode::engine();
        leaf_engine.input(&leaf_tag[..]);
        leaf_engine.input(&leaf_tag[..]);

        let mut leaf1 = leaf_engine.clone();
        leaf1.input(
            iter.next()
                .as_ref()
                .map(|d| d.as_ref())
                .unwrap_or_else(|| empty_node.as_ref()),
        );
        MerkleNode::from_engine(leaf1).commit_encode(&mut engine);

        leaf_engine.input(
            iter.next()
                .as_ref()
                .map(|d| d.as_ref())
                .unwrap_or_else(|| empty_node.as_ref()),
        );
        MerkleNode::from_engine(leaf_engine).commit_encode(&mut engine);

        (MerkleNode::from_engine(engine), 1)
    } else {
        let div = len / 2;

        let (node1, height1) = merklize_inner(
            engine_proto,
            &data[..div],
            depth + 1,
            false,
            Some(empty_node),
        );
        let (node2, height2) = merklize_inner(
            engine_proto,
            &data[div..],
            depth + 1,
            len % 2 == 0,
            Some(empty_node),
        );

        assert_eq!(height1, height2, "merklization algorithm failure: height of two subtrees is not equal");

        tag_engine.input(height1.to_string().as_bytes());
        tag_engine.input(":".as_bytes());
        let tag_hash =
            sha256::Hash::hash(&sha256::Hash::from_engine(tag_engine));
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        node1.commit_encode(&mut engine);
        node2.commit_encode(&mut engine);

        (MerkleNode::from_engine(engine), height1 + 1)
    }
}

/// The source data for the merklization process
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct MerkleSource<T>(
    /// Array of the data which will be merklized
    pub Vec<T>,
);

impl<L, I> From<I> for MerkleSource<L>
where
    I: IntoIterator<Item = L>,
    L: CommitEncode,
{
    fn from(collection: I) -> Self {
        Self(collection.into_iter().collect())
    }
}

impl<L> FromIterator<L> for MerkleSource<L>
where
    L: CommitEncode,
{
    fn from_iter<T: IntoIterator<Item = L>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

impl<L> CommitEncode for MerkleSource<L>
where
    L: ConsensusMerkleCommit,
{
    fn commit_encode<E: io::Write>(&self, e: E) -> usize {
        let leafs = self
            .0
            .iter()
            .map(L::consensus_commit)
            .collect::<Vec<MerkleNode>>();
        merklize(L::MERKLE_NODE_TAG, &leafs).0.commit_encode(e)
    }
}

impl<L> ConsensusCommit for MerkleSource<L>
where
    L: ConsensusMerkleCommit + CommitEncode,
{
    type Commitment = MerkleNode;

    #[inline]
    fn consensus_commit(&self) -> Self::Commitment {
        MerkleNode::from_slice(&self.commit_serialize())
            .expect("MerkleSource::commit_serialize must produce MerkleNode")
    }

    #[inline]
    fn consensus_verify(&self, commitment: &Self::Commitment) -> bool {
        self.consensus_commit() == *commitment
    }
}

/// Converts given piece of client-side-validated data into a structure which
/// can be used in merklization process
pub trait ToMerkleSource {
    /// Defining type of the commitment produced during merlization process
    type Leaf: ConsensusMerkleCommit;

    /// Performs transformation of the data type into a merkilzable data
    fn to_merkle_source(&self) -> MerkleSource<Self::Leaf>;
}
