// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

use bitcoin_hashes::{sha256, Hash, HashEngine};

use crate::{commit_encode, CommitEncode, CommitVerify, ConsensusCommit};

/// Marker trait for types that require merklization of the underlying data
/// during [`ConsensusCommit`] procedure. Allows specifying custom tag for the
/// tagged hash used in the merklization (see [`merklize`]).
pub trait ConsensusMerkleCommit:
    ConsensusCommit<Commitment = MerkleNode>
{
    /// The tag prefix which will be used in the merklization process (see
    /// [`merklize`])
    const MERKLE_NODE_PREFIX: &'static str;
}

hash_newtype!(
    MerkleNode,
    sha256::Hash,
    32,
    doc = "A hash type for LNPBP-81 Merkle tree leaves, branches and root",
    false // We do not reverse displaying MerkleNodes in hexadecimal
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
/// according to [LNPBP-81] standard of client-side-validation merklization
///
/// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
pub fn merklize<I>(prefix: &str, data: I) -> (MerkleNode, u8)
where
    I: IntoIterator<Item = MerkleNode>,
    <I as IntoIterator>::IntoIter: ExactSizeIterator<Item = MerkleNode>,
{
    let mut tag_engine = sha256::Hash::engine();
    tag_engine.input(prefix.as_bytes());
    tag_engine.input(":merkle:".as_bytes());

    let iter = data.into_iter();
    let width = iter.len();

    // Tagging merkle tree root
    let (root, height) = merklize_inner(&tag_engine, iter, 0, false, None);
    tag_engine.input("root:height=".as_bytes());
    tag_engine.input(&height.to_string().into_bytes());
    tag_engine.input(":width=".as_bytes());
    tag_engine.input(&width.to_string().into_bytes());
    let tag_hash = sha256::Hash::hash(&sha256::Hash::from_engine(tag_engine));
    let mut engine = MerkleNode::engine();
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    root.commit_encode(&mut engine);
    let tagged_root = MerkleNode::from_engine(engine);

    (tagged_root, height)
}

fn merklize_inner(
    engine_proto: &sha256::HashEngine,
    mut iter: impl ExactSizeIterator<Item = MerkleNode>,
    depth: u8,
    extend: bool,
    empty_node: Option<MerkleNode>,
) -> (MerkleNode, u8) {
    let len = iter.len();
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
            // Normally we should use `iter.by_ref().take(div)`, but currently
            // rust compilers is unable to parse recursion with generic types
            iter.by_ref().take(div).collect::<Vec<_>>().into_iter(),
            depth + 1,
            false,
            Some(empty_node),
        );
        let (node2, height2) = merklize_inner(
            engine_proto,
            iter,
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

/// The source data for the [LNPBP-81] merklization process.
///
/// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
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
        let leafs = self.0.iter().map(L::consensus_commit);
        merklize(L::MERKLE_NODE_PREFIX, leafs).0.commit_encode(e)
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
/// can be used in merklization process.
///
/// This dedicated structure is required since with
/// `impl From<_> for MerkleSource` we would not be able to specify a concrete
/// tagged hash, which we require in [LNPBP-81] merklization and which we
/// provide here via [`ToMerkleSource::Leaf`]` associated type holding
/// [`ConsensusMerkleCommit::MERKLE_NODE_PREFIX`] prefix value.
///
/// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
pub trait ToMerkleSource {
    /// Defining type of the commitment produced during merlization process
    type Leaf: ConsensusMerkleCommit;

    /// Performs transformation of the data type into a merkilzable data
    fn to_merkle_source(&self) -> MerkleSource<Self::Leaf>;
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::commit_encode::{strategies, Strategy};
    use crate::CommitConceal;
    use amplify::{bmap, s};
    use bitcoin_hashes::hex::ToHex;
    use bitcoin_hashes::{sha256d, Hash};
    use std::collections::BTreeMap;
    use strict_encoding::StrictEncode;

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
            StrictEncode,
            StrictDecode,
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

        let item = Item(s!("Some text"));
        assert_eq!(&b"\x09\x00Some text"[..], item.strict_serialize().unwrap());
        assert_eq!(
            "6680bbec0d05d3eaac9c8b658c40f28d2f0cb0f245c7b1cabf5a61c35bd03d8e",
            item.commit_serialize().to_hex()
        );
        assert_eq!(
            "3e4b2dcf9bca33400028c8947565c1ff421f6d561e9ec48f88f0c9a24ebc8c30",
            item.consensus_commit().to_hex()
        );
        assert_ne!(item.commit_serialize(), item.strict_serialize().unwrap());
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
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            "3b970fa581bcdf4987e6455e2e5a1ea575bcb3f5b37c25600f600cc8d44e5598",
            collection.commit_serialize().to_hex()
        );
        assert_eq!(
            "3b970fa581bcdf4987e6455e2e5a1ea575bcb3f5b37c25600f600cc8d44e5598",
            collection.consensus_commit().to_hex()
        );
        assert_ne!(
            collection.commit_serialize(),
            original.strict_serialize().unwrap()
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
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            "4ee97b1318fe417cac30790335033ece29ea4b6183ebf51d083d5a2e89ac33da",
            vec.commit_serialize().to_hex()
        );
        assert_eq!(
            "4ee97b1318fe417cac30790335033ece29ea4b6183ebf51d083d5a2e89ac33da",
            vec.consensus_commit().to_hex()
        );
        assert_ne!(
            vec.commit_serialize(),
            original.strict_serialize().unwrap()
        );
        assert_eq!(
            MerkleNode::from_slice(&vec.commit_serialize()).unwrap(),
            vec.consensus_commit()
        );
        assert_ne!(vec.consensus_commit(), collection.consensus_commit());
    }
}
