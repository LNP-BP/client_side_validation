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

use std::io::Write;

use amplify::confinement::SmallOrdMap;
use amplify::num::u4;
use amplify::{Bytes32, Wrapper};

use crate::id::CommitmentId;
use crate::merkle::MerkleNode;
use crate::CommitEncode;

/// Map from protocol ids to commitment messages.
pub type MessageMap = SmallOrdMap<ProtocolId, Message>;

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
pub struct ProtocolId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitEncode for ProtocolId {
    fn commit_encode(&self, e: &mut impl Write) { self.0.as_inner().commit_encode(e) }
}

/// Original message participating in multi-message commitment.
///
/// The message must be represented by a 32-byte hash.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, RangeOps)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Message(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitEncode for Message {
    fn commit_encode(&self, e: &mut impl Write) { self.0.as_inner().commit_encode(e) }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
pub enum Leaf {
    Inhabited {
        protocol: ProtocolId,
        message: Message,
    },
    Entropy {
        entropy: u64,
        pos: u16,
    },
}

impl Leaf {
    pub fn entropy(entropy: u64, pos: u16) -> Self { Self::Entropy { entropy, pos } }

    pub fn inhabited(protocol: ProtocolId, message: Message) -> Self {
        Self::Inhabited { protocol, message }
    }
}

impl CommitEncode for Leaf {
    fn commit_encode(&self, e: &mut impl Write) {
        match self {
            Leaf::Inhabited { protocol, message } => {
                protocol.commit_encode(e);
                message.commit_encode(e);
            }
            Leaf::Entropy { entropy, pos } => {
                entropy.commit_encode(e);
                pos.commit_encode(e);
            }
        }
    }
}

impl CommitmentId for Leaf {
    // TODO: Use a real midstate
    const TAG: [u8; 32] = [0u8; 32];
    type Id = MerkleNode;
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash of the merkle root of [`MerkleTree`] and
/// [`MerkleBlock`].
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, RangeOps)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
pub struct Commitment(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

// TODO: Either this type or [`MerkleTree`] should remain
/// Structured source multi-message data for commitment creation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MultiSource {
    /// Minimal depth of the created LNPBP-4 commitment tree
    pub min_depth: u4,
    /// Map of the messages by their respective protocol ids
    pub messages: MessageMap,
}

impl Default for MultiSource {
    fn default() -> Self {
        MultiSource {
            min_depth: u4::try_from(3).expect("hardcoded value"),
            messages: Default::default(),
        }
    }
}
