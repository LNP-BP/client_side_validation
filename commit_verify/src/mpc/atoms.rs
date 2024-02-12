// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use amplify::confinement::MediumOrdMap;
use amplify::num::u5;
use amplify::{Bytes32, FromSliceError, Wrapper};
use sha2::Sha256;
use strict_encoding::StrictDumb;

use crate::merkle::MerkleHash;
use crate::{CommitmentId, DigestExt};

pub const MPC_MINIMAL_DEPTH: u5 = u5::with(3);

/// Map from protocol ids to commitment messages.
pub type MessageMap = MediumOrdMap<ProtocolId, Message>;

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
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

impl ProtocolId {
    pub fn copy_from_slice(slice: &[u8]) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

/// Original message participating in multi-message commitment.
///
/// The message must be represented by a 32-byte hash.
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Default)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
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

impl Message {
    pub fn copy_from_slice(slice: &[u8]) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug, From)]
#[derive(StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_COMMIT_VERIFY, tags = custom)]
#[derive(CommitEncode)]
#[commit_encode(crate = crate, strategy = strict, id = MerkleHash)]
pub enum Leaf {
    // We use this constant since we'd like to be distinct from NodeBranching values
    #[strict_type(tag = 0x10)]
    Inhabited {
        protocol: ProtocolId,
        message: Message,
    },
    // We use this constant since we'd like to be distinct from NodeBranching values
    #[strict_type(tag = 0x11)]
    Entropy { entropy: u64, pos: u32 },
}

impl Leaf {
    pub fn entropy(entropy: u64, pos: u32) -> Self { Self::Entropy { entropy, pos } }

    pub fn inhabited(protocol: ProtocolId, message: Message) -> Self {
        Self::Inhabited { protocol, message }
    }
}

impl StrictDumb for Leaf {
    fn strict_dumb() -> Self { Self::Entropy { entropy: 0, pos: 0 } }
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash of the merkle root of [`super::MerkleTree`] and
/// [`super::MerkleBlock`].
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Wrapper, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From)]
#[wrapper(Deref, BorrowSlice, Display, FromStr, Hex, Index, RangeOps)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = crate::LIB_NAME_COMMIT_VERIFY)]
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

impl CommitmentId for Commitment {
    const TAG: &'static str = "urn:ubideco:mpc:commitment#2024-01-31";
}

impl Commitment {
    pub fn copy_from_slice(slice: &[u8]) -> Result<Self, FromSliceError> {
        Bytes32::copy_from_slice(slice).map(Self)
    }
}

impl From<Sha256> for Commitment {
    fn from(hasher: Sha256) -> Self { hasher.finish().into() }
}

/// Structured source multi-message data for commitment creation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MultiSource {
    /// Minimal depth of the created LNPBP-4 commitment tree
    pub min_depth: u5,
    /// Map of the messages by their respective protocol ids
    pub messages: MessageMap,
    pub static_entropy: Option<u64>,
}

impl Default for MultiSource {
    #[inline]
    fn default() -> Self {
        MultiSource {
            min_depth: MPC_MINIMAL_DEPTH,
            messages: Default::default(),
            static_entropy: None,
        }
    }
}

impl MultiSource {
    #[inline]
    pub fn with_static_entropy(static_entropy: u64) -> Self {
        MultiSource {
            static_entropy: Some(static_entropy),
            ..default!()
        }
    }
}
