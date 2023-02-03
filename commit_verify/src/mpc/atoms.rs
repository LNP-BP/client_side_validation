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
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_COMMIT_VERIFY)]
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
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, RangeOps)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_COMMIT_VERIFY)]
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
    const TAG: [u8; 32] = *b"urn:lnpbp:lnpbp4:leaf:v01#230202";
    type Id = MerkleNode;
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash of the merkle root of [`super::MerkleTree`] and
/// [`super::MerkleBlock`].
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
