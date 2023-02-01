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

use amplify::Bytes32;

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
pub struct MerkleNode(Bytes32);

/// Converts given piece of client-side-validated data into a structure which
/// can be used in merklization process.
///
/// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
pub trait ToMerkleSource {
    /// Defining type of the commitment produced during merlization process
    type Leaf: CommitEncode;

    /// Performs transformation of the data type into a merkilzable data
    fn to_merkle_source(&self) -> MerkleSource<Self::Leaf>;
}

/// The source data for the [LNPBP-81] merklization process.
///
/// [LNPBP-81]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0081.md
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
pub struct MerkleSource<'leaf, T: CommitEncode>(
    /// Array of references to the data which can be merklized.
    Vec<&'leaf T>,
);

impl<'leaf, Leaf, Iter> From<Iter> for MerkleSource<'leaf, Leaf>
where
    Iter: IntoIterator<Item = &'leaf Leaf>,
    Leaf: CommitEncode,
{
    fn from(collection: Iter) -> Self { Self(collection.into_iter().collect()) }
}

impl<'leaf, Leaf> FromIterator<&'leaf Leaf> for MerkleSource<'leaf, Leaf>
where
    Leaf: CommitEncode,
{
    fn from_iter<T: IntoIterator<Item = &'leaf Leaf>>(iter: T) -> Self {
        iter.into_iter().collect::<Vec<_>>().into()
    }
}

/*
impl<L> CommitEncode for MerkleSource<L>
    where
        L: ConsensusMerkleCommit,
{
    fn commit_encode(&self, e: &mut impl io::Write) {
        let leafs = self.0.iter().map(L::consensus_commit);
        merklize(L::MERKLE_NODE_PREFIX, leafs).0.commit_encode(e);
    }
}

// Tag string: `urn:lnpbp:merkle:node?depth=0,height=A,width=AF16`

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

// TODO: Optimize to avoid allocations
// In current rust generic iterators do not work with recursion :(
fn merklize_inner(
    engine_proto: &sha256::HashEngine,
    mut iter: impl ExactSizeIterator<Item = MerkleNode>,
    depth: u8,
    extend: bool,
    empty_node: Option<MerkleNode>,
) -> (MerkleNode, u8) {
    let len = iter.len() + extend as usize;
    let empty_node = empty_node.unwrap_or_else(|| MerkleNode::hash(&[0xFF]));

    // Computing tagged hash as per BIP-340
    let mut tag_engine = engine_proto.clone();
    tag_engine.input("depth=".as_bytes());
    tag_engine.input(depth.to_string().as_bytes());
    tag_engine.input(":width=".as_bytes());
    tag_engine.input(len.to_string().as_bytes());
    tag_engine.input(":height=".as_bytes());

    let mut engine = MerkleNode::engine();
    if len <= 2 {
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
        let div = len / 2 + len % 2;

        let (node1, height1) = merklize_inner(
            engine_proto,
            // Normally we should use `iter.by_ref().take(div)`, but currently
            // rust compilers is unable to parse recursion with generic types
            iter.by_ref().take(div).collect::<Vec<_>>().into_iter(),
            depth + 1,
            false,
            Some(empty_node),
        );

        let iter = if extend {
            iter.chain(vec![empty_node]).collect::<Vec<_>>().into_iter()
        } else {
            iter.collect::<Vec<_>>().into_iter()
        };

        let (node2, height2) = merklize_inner(
            engine_proto,
            iter,
            depth + 1,
            (div % 2 + len % 2) / 2 == 1,
            Some(empty_node),
        );

        assert_eq!(
            height1,
            height2,
            "merklization algorithm failure: height of subtrees is not equal \
             (width = {}, depth = {}, prev_extend = {}, next_extend = {})",
            len,
            depth,
            extend,
            div % 2 == 1 && len % 2 == 1
        );

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
*/
