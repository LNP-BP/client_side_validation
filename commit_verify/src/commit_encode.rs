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

//! Encoding and data preparation for commitment procedures in
//! client-side-validation as defined by [LNPBP-9] standard.
//!
//! Client-side-validation commitment process requires special encoding of
//! the data. While [`strict_encoding`] is the main standard for atomic data
//! types in client-side-validation world and should be used during internal
//! protocol-specific data validation, commitments may require processes of
//! merklization arrays of data items, or hiding confidential parts of the
//! data via hashing, pedersen commitments and so on. Thus, additinally to
//! strict encoding, a set of different encodings and data convolution and
//! hiding procedures are defined in this `commit_encode` module of the
//! `commit_verify` library. This includes:
//! - **merklization** procedures operating special types of tagged hashes and
//!   committing to the depth of each node
//! - **commit conceal** procedures, making data confidential (transforming
//!   types into confidential versions)
//! - **commit encoding**, which should *conceal* all the data and merklize
//!   arrays, and only them performing their *strict encoding*
//! - **consensus commitment**, which wraps all of the above as a final API,
//!   producing of a single commitment to the client-validated data.
//!
//! [LNPBP-9]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0009.md

use std::io;
use std::iter::FromIterator;

use bitcoin_hashes::{sha256, sha256d, Hash, HashEngine};

use crate::CommitVerify;

/// Prepares the data to the *consensus commit* procedure by first running
/// necessary conceal and merklization procedures, and them performing strict
/// encoding for the resulted data.
pub trait CommitEncode {
    /// Encodes the data for the commitment by writing them directly into a
    /// [`io::Write`] writer instance
    fn commit_encode<E: io::Write>(&self, e: E) -> usize;

    /// Serializes data for the commitment in-memory into a newly allocated
    /// array
    fn commit_serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        self.commit_encode(&mut vec);
        vec
    }
}

/// Convenience macro for commit-encoding list of the data
#[macro_export]
macro_rules! commit_encode_list {
    ( $encoder:ident; $($item:expr),+ ) => {
        {
            let mut len = 0usize;
            $(
                len += $item.commit_encode(&mut $encoder);
            )+
            len
        }
    }
}

/// Marker trait defining specific encoding strategy which should be used for
/// automatic implementation of [`CommitEncode`].
pub trait Strategy {
    /// Specific strategy. List of supported strategies:
    /// - [`strategy::UsingStrict`]
    /// - [`strategy::UsingConceal`]
    /// - [`strategy::UsingHash`]
    type Strategy;
}

/// Strategies simplifying implementation of [`CommitEncode`] trait.
///
/// Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>
pub mod strategy {
    use super::*;
    use bitcoin_hashes::Hash;

    /// Encodes by running strict *encoding procedure* on the raw data without
    /// any pre-processing.
    ///
    /// Should not be used for array types (require manual [`CommitEncode`]
    /// implementation involving merklization) or data which may contain
    /// confidential or sensitive information (use [`UsingConceal`] in this
    /// case).
    pub struct UsingStrict;

    /// Encodes data by first converting them into confidential version
    /// (*concealing*) by running [`CommitConceal::commit_conceal`] first and
    /// returning its result serialized with strict encoding rules.
    pub struct UsingConceal;

    /// Encodes data by first hashing them with the provided hash function `H`
    /// and then returning its result serialized with strict encoding rules.
    pub struct UsingHash<H>(std::marker::PhantomData<H>)
    where
        H: Hash + strict_encoding::StrictEncode;

    impl<T> CommitEncode for amplify::Holder<T, UsingStrict>
    where
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().strict_encode(e).expect(
                "Strict encoding must not fail for types using `strategy::UsingStrict`",
            )
        }
    }

    impl<T> CommitEncode for amplify::Holder<T, UsingConceal>
    where
        T: CommitConceal,
        <T as CommitConceal>::ConcealedCommitment: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            self.as_inner().commit_conceal().commit_encode(e)
        }
    }

    impl<T, H> CommitEncode for amplify::Holder<T, UsingHash<H>>
    where
        H: Hash + strict_encoding::StrictEncode,
        T: strict_encoding::StrictEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            let mut engine = H::engine();
            engine
                .input(&strict_encoding::strict_serialize(self.as_inner()).expect(
                    "Strict encoding of hash strategy-based commitment data must not fail",
                ));
            let hash = H::from_engine(engine);
            hash.strict_encode(e).expect(
                "Strict encoding must not fail for types using `strategy::UsingHash`",
            )
        }
    }

    impl<K, V> CommitEncode for (K, V)
    where
        K: CommitEncode,
        V: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e) + self.1.commit_encode(&mut e)
        }
    }

    impl<A, B, C> CommitEncode for (A, B, C)
    where
        A: CommitEncode,
        B: CommitEncode,
        C: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, mut e: E) -> usize {
            self.0.commit_encode(&mut e)
                + self.1.commit_encode(&mut e)
                + self.2.commit_encode(&mut e)
        }
    }

    impl<T> CommitEncode for T
    where
        T: Strategy + Clone,
        amplify::Holder<T, <T as Strategy>::Strategy>: CommitEncode,
    {
        fn commit_encode<E: io::Write>(&self, e: E) -> usize {
            amplify::Holder::new(self.clone()).commit_encode(e)
        }
    }

    impl Strategy for usize {
        type Strategy = UsingStrict;
    }
    impl Strategy for u8 {
        type Strategy = UsingStrict;
    }
    impl Strategy for u16 {
        type Strategy = UsingStrict;
    }
    impl Strategy for u32 {
        type Strategy = UsingStrict;
    }
    impl Strategy for u64 {
        type Strategy = UsingStrict;
    }
    impl Strategy for i8 {
        type Strategy = UsingStrict;
    }
    impl Strategy for i16 {
        type Strategy = UsingStrict;
    }
    impl Strategy for i32 {
        type Strategy = UsingStrict;
    }
    impl Strategy for i64 {
        type Strategy = UsingStrict;
    }
    impl Strategy for String {
        type Strategy = UsingStrict;
    }
    impl Strategy for &str {
        type Strategy = UsingStrict;
    }
    impl Strategy for &[u8] {
        type Strategy = UsingStrict;
    }
    impl Strategy for Vec<u8> {
        type Strategy = UsingStrict;
    }
    impl Strategy for MerkleNode {
        type Strategy = UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl Strategy for secp256k1zkp::pedersen::Commitment {
        type Strategy = strategy::UsingStrict;
    }

    #[cfg(feature = "grin_secp256k1zkp")]
    impl Strategy for secp256k1zkp::pedersen::RangeProof {
        type Strategy = strategy::UsingHash<sha256::Hash>;
    }

    impl<T> Strategy for &T
    where
        T: Strategy,
    {
        type Strategy = T::Strategy;
    }
}

/// Trait that should perform conversion of a given client-side-validated data
/// type into its confidential version concealing all of its data.
///
/// Since the resulting concealed version must be unequally derived from the
/// original data with negligible risk of collisions, it is a form of
/// *commitment* – thus the procedure called *commit-conceal* and not just a
/// *conceal*.
pub trait CommitConceal {
    /// The resulting confidential type concealing and committing to the
    /// original data
    type ConcealedCommitment;

    /// Performs commit-conceal procedure returning confidential data
    /// concealing and committing to the original data
    fn commit_conceal(&self) -> Self::ConcealedCommitment;
}

/// High-level API used in client-side validation for producing a single
/// commitment to the data, which includes running all necessary procedures like
/// concealment with [`CommitConceal`], merklization, strict encoding,
/// wrapped into [`CommitEncode`], followed by the actual commitment to its
/// output.
pub trait ConsensusCommit: Sized + CommitEncode {
    /// Type of the resulting commitment
    type Commitment: CommitVerify<Vec<u8>>;

    /// Performs commitment to client-side-validated data
    #[inline]
    fn consensus_commit(&self) -> Self::Commitment {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        Self::Commitment::commit(&encoder.into_inner())
    }

    /// Verifies commitment to client-side-validated data
    #[inline]
    fn consensus_verify(&self, commitment: &Self::Commitment) -> bool {
        let mut encoder = io::Cursor::new(vec![]);
        self.commit_encode(&mut encoder);
        commitment.verify(&encoder.into_inner())
    }
}

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

hash_newtype!(
    MerkleNode,
    sha256d::Hash,
    32,
    doc = "A hash of a arbitrary Merkle tree branch or root"
);

impl strict_encoding::Strategy for MerkleNode {
    type Strategy = strict_encoding::strategies::HashFixedBytes;
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

/// Merklization procedure that uses tagged hashes with depth commitments
pub fn merklize(prefix: &str, data: &[MerkleNode], depth: u16) -> MerkleNode {
    let len = data.len();

    let mut engine = MerkleNode::engine();
    // Computing tagged hash as per BIP-340
    let tag = format!("{}:merkle:{}", prefix, depth);
    let tag_hash = sha256::Hash::hash(tag.as_bytes());
    engine.input(&tag_hash[..]);
    engine.input(&tag_hash[..]);
    match len {
        0 => {
            0u8.commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        1 => {
            data.first()
                .expect("We know that we have one element")
                .commit_encode(&mut engine);
            0u8.commit_encode(&mut engine);
        }
        2 => {
            data.first()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
            data.last()
                .expect("We know that we have at least two elements")
                .commit_encode(&mut engine);
        }
        _ => {
            let div = len / 2;
            merklize(prefix, &data[0..div], depth + 1)
                .commit_encode(&mut engine);
            merklize(prefix, &data[div..], depth + 1)
                .commit_encode(&mut engine);
        }
    }
    MerkleNode::from_engine(engine)
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
        let leafs = &self
            .0
            .iter()
            .map(L::consensus_commit)
            .collect::<Vec<MerkleNode>>();
        merklize(L::MERKLE_NODE_TAG, leafs, 0).commit_encode(e)
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

#[cfg(test)]
mod test {
    use super::*;
    use amplify::{bmap, s};
    use bitcoin_hashes::hex::ToHex;
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
            type Strategy = strategy::UsingStrict;
        }
        // Now, we define commitment encoding for our concealable type: it
        // should conceal the data
        impl Strategy for Item {
            type Strategy = strategy::UsingConceal;
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
            const MERKLE_NODE_TAG: &'static str = "item";
        }
        impl ConsensusMerkleCommit for (usize, Item) {
            const MERKLE_NODE_TAG: &'static str = "usize->item";
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
            "df08dc157bbd5676d5aeb1b437fa0cded8d3e21699adee2fcbbadef131a9e895",
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
            "b497ced8b6431336e4c66ffd56a504633c828ea3ec0c0495a31e9a14cb066406",
            collection.commit_serialize().to_hex()
        );
        assert_eq!(
            "066406cb149a1ea395040ceca38e823c6304a556fd6fc6e4361343b6d8ce97b4",
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
            "8a8ebc499d146b0ab551e0ff985cf8166dc05f20f04b0f5991c4b9242dbde205",
            vec.commit_serialize().to_hex()
        );
        assert_eq!(
            "05e2bd2d24b9c491590f4bf0205fc06d16f85c98ffe051b50a6b149d49bc8e8a",
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
