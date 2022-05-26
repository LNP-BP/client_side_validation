// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

//! Multi-message commitments: implementation of [LNPBP-4] standard.
//!
//! [LNPBP-4] defines a commit-verify scheme for committing to a multiple
//! messages under distinct protocols with ability to partially reveal set of
//! the commitments and still be able to prove the commitment for each message
//! without exposing the exact number of other messages and their respective
//! protocol identifiers.
//!
//! [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

use std::collections::BTreeMap;
use std::io;

use amplify::num::u256;
use amplify::{Slice32, Wrapper};
use bitcoin_hashes::{sha256, sha256t};
use strict_encoding::StrictEncode;

#[cfg(feature = "rand")]
use crate::TryCommitVerify;
use crate::{
    commit_encode, CommitEncode, CommitVerify, ConsensusCommit, TaggedHash,
    UntaggedProtocol,
};

/// Source data for creation of multi-message commitments according to [LNPBP-4]
/// procedure.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
pub type ProtocolId = Slice32;

/// Original message participating in multi-message commitment.
///
/// The message must be represented by a SHA256 tagged hash. Since each message
/// may have a different tag, we can't use [`sha256t`] type directly and use its
/// [`sha256::Hash`] equivalent.
pub type Message = sha256::Hash;

/// Structured source multi-message data for commitment creation
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct MultiSource {
    /// Minimal length of the created LNPBP-4 commitment buffer
    pub min_length: u16,
    /// Map of the messages by their respective protocol ids
    pub messages: BTreeMap<ProtocolId, Message>,
}

impl Default for MultiSource {
    fn default() -> Self {
        MultiSource {
            min_length: 3,
            messages: Default::default(),
        }
    }
}

/// Errors generated during multi-message commitment process by
/// [`MultiCommitBlock::try_commit`]
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error, Debug, Display
)]
#[display(doc_comments)]
pub enum Error {
    /// Number of messages ({0}) for LNPBP-4 commitment which exceeds the
    /// protocol limit of 2^16
    TooManyMessages(usize),

    /// The provided number of messages can't fit LNPBP-4 commitment size
    /// limits for a given set of protocol ids.
    CantFitInMaxSlots,
}

/// Single item within a multi-message commitment, consisting of optional
/// protocol information (if known) and the actual single message commitment
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{message}")]
#[derive(StrictEncode, StrictDecode)]
pub struct MultiCommitItem {
    /// Protocol identifier, which may be hidden or absent for commitment
    /// placeholders
    pub protocol: Option<ProtocolId>,

    /// Message commitment (LNPBP-4 tagged hash of the message)
    pub message: Message,
}

impl MultiCommitItem {
    /// Constructs multi-message commitment item for a given protocol
    pub fn new(protocol: ProtocolId, message: Message) -> Self {
        Self {
            protocol: Some(protocol),
            message,
        }
    }
}

/// Multi-message commitment data according to [LNPBP-4] specification.
///
/// To create commitment use [`TryCommitVerify::try_commit`] method.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[derive(Getters, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default)]
#[derive(StrictEncode, StrictDecode)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
pub struct MultiCommitBlock {
    /// Array of commitment items (see [`MultiCommitItem`])
    commitments: Vec<MultiCommitItem>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`TryCommitVerify::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    #[getter(as_copy)]
    entropy: Option<u64>,
}

// When we commit to `MultiCommitBlock` we do not use `entropy`, since we
// already committed to its value inside `MultiCommitItem` using the entropy
impl CommitEncode for MultiCommitBlock {
    fn commit_encode<E: io::Write>(&self, e: E) -> usize {
        self.commitments
            .strict_encode(e)
            .expect("CommitEncode of Vec<MultiCommitItem> has failed")
    }
}

fn protocol_id_pos(protocol_id: ProtocolId, len: usize) -> u16 {
    let rem =
        u256::from_le_bytes(protocol_id.into_inner()) % u256::from(len as u64);
    rem.low_u64() as u16
}

/// Error merging two [`MultiCommitBlock`]s.
#[derive(
    Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display, Error
)]
#[display("LNPBP-4 blocks can't be merged since they commit to different data")]
pub struct BlocksMismatch;

impl MultiCommitBlock {
    /// Conceals all LNPBP-4 data except specific protocol.
    pub fn conceal_except(&mut self, protocols: &[ProtocolId]) -> usize {
        self.entropy = None;
        self.commitments.iter_mut().fold(0usize, |mut count, item| {
            if !item
                .protocol
                .map(|protocol| protocols.contains(&protocol))
                .unwrap_or_default()
            {
                item.protocol = None;
                count += 1;
            }
            count
        })
    }

    /// Merges two blocks keeping revealed data.
    pub fn merge(mut self, other: Self) -> Result<Self, BlocksMismatch> {
        if self.consensus_commit() != other.consensus_commit() {
            return Err(BlocksMismatch);
        }

        self.entropy = self.entropy.or(other.entropy);

        self.commitments.iter_mut().zip(other.commitments).for_each(
            |(item, other)| item.protocol = item.protocol.or(other.protocol),
        );

        Ok(self)
    }

    /// Verify that the LNPBP-4 structure contains commitment to the given
    /// message under the given protocol.
    pub fn verify(&self, protocol_id: ProtocolId, message: Message) -> bool {
        let pos = protocol_id_pos(protocol_id, self.commitments.len());
        self.commitments[pos as usize].message == message
    }
}

#[cfg(feature = "rand")]
const MIDSTATE_ENTROPY: [u8; 32] = [
    0xF4, 0x0D, 0x86, 0x94, 0x9F, 0xFF, 0xAD, 0xEE, 0x19, 0xEA, 0x50, 0x20,
    0x60, 0xAB, 0x6B, 0xAD, 0x11, 0x61, 0xB2, 0x35, 0x83, 0xD3, 0x78, 0x18,
    0x52, 0x0D, 0xD4, 0xD1, 0xD8, 0x88, 0x1E, 0x61,
];

#[cfg(feature = "rand")]
impl TryCommitVerify<MultiSource, UntaggedProtocol> for MultiCommitBlock {
    type Error = Error;

    fn try_commit(source: &MultiSource) -> Result<Self, Error> {
        use bitcoin_hashes::{Hash, HashEngine};
        use rand::{thread_rng, Rng};

        let m = source.messages.len();
        if m > u16::MAX as usize {
            return Err(Error::TooManyMessages(m));
        }
        let mut n = m;
        // We use some minimum number of items, to increase privacy
        n = n.max(source.min_length as usize);

        let ordered = loop {
            if n > u16::MAX as usize {
                return Err(Error::CantFitInMaxSlots);
            }

            let mut ordered = BTreeMap::<usize, (ProtocolId, Message)>::new();
            if source.messages.iter().all(|(protocol, message)| {
                let pos = protocol_id_pos(*protocol, n);
                ordered
                    .insert(pos as usize, (*protocol, *message))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
        };
        let n = n as u16;

        let entropy = {
            let mut rng = thread_rng();
            rng.gen::<u64>()
        };
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        let mut engine = sha256::HashEngine::from_midstate(midstate, 64);
        engine.input(&entropy.to_le_bytes());

        let mut commitments = Vec::<_>::with_capacity(n as usize);
        for i in 0..n {
            match ordered.get(&(i as usize)) {
                None => {
                    let mut subengine = engine.clone();
                    subengine.input(&i.to_le_bytes());
                    commitments.push(MultiCommitItem {
                        protocol: None,
                        message: Message::from_engine(subengine),
                    })
                }
                Some((contract_id, commitment)) => commitments
                    .push(MultiCommitItem::new(*contract_id, *commitment)),
            }
        }

        Ok(Self {
            commitments,
            entropy: Some(entropy),
        })
    }
}

static MIDSTATE_LNPBP4: [u8; 32] = [
    0x23, 0x4B, 0x4D, 0xBA, 0x22, 0x2A, 0x64, 0x1C, 0x7F, 0x74, 0xD5, 0xC9,
    0x80, 0x17, 0x36, 0x1A, 0x90, 0x76, 0x4F, 0xB3, 0xC2, 0xB1, 0xA1, 0x6F,
    0xDE, 0x28, 0x66, 0x89, 0xF1, 0xCC, 0x99, 0x3F,
];

/// Tag used for [`MultiCommitment`] hash type
pub struct Lnpbp4Tag;

impl sha256t::Tag for Lnpbp4Tag {
    #[inline]
    fn engine() -> sha256::HashEngine {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        sha256::HashEngine::from_midstate(midstate, 64)
    }
}

/// Final [LNPBP-4] commitment value.
///
/// Represents tagged hash (with [`Lnpbp4Tag`]) of the sequentially serialized
/// [`MultiCommitBlock::commitments`].
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default, From
)]
#[wrapper(
    Debug, Display, LowerHex, Index, IndexRange, IndexFrom, IndexTo, IndexFull
)]
pub struct MultiCommitment(sha256t::Hash<Lnpbp4Tag>);

impl<M> CommitVerify<M, UntaggedProtocol> for MultiCommitment
where
    M: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &M) -> MultiCommitment { MultiCommitment::hash(msg) }
}

#[cfg(feature = "rand")]
impl TryCommitVerify<MultiSource, UntaggedProtocol> for MultiCommitment {
    type Error = Error;

    fn try_commit(msg: &MultiSource) -> Result<Self, Self::Error> {
        Ok(MultiCommitBlock::try_commit(msg)?.consensus_commit())
    }
}

impl strict_encoding::Strategy for MultiCommitment {
    type Strategy = strict_encoding::strategies::Wrapped;
}

impl commit_encode::Strategy for MultiCommitment {
    type Strategy = commit_encode::strategies::UsingStrict;
}

impl ConsensusCommit for MultiCommitBlock {
    type Commitment = MultiCommitment;
}

#[cfg(test)]
mod test {
    #[cfg(feature = "rand")]
    use amplify::Wrapper;
    use bitcoin_hashes::{Hash, HashEngine};

    use super::*;

    #[cfg(feature = "rand")]
    fn entropy_tagged_engine() -> sha256::HashEngine {
        let tag_hash = sha256::Hash::hash("LNPBP4:entropy".as_bytes());
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_entropy_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        assert_eq!(midstate, entropy_tagged_engine().midstate());
    }

    #[test]
    fn test_lnpbp4_tag() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_LNPBP4);
        let tag_hash = sha256::Hash::hash("LNPBP4".as_bytes());
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        assert_eq!(midstate, engine.midstate());
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_commit() {
        let mut protocol = ProtocolId::from_inner([0u8; 32]);
        let message = Message::hash("First message".as_bytes());

        for index in 0u8..3 {
            let mut source = MultiSource::default();
            protocol[0u8] = index;
            source.messages.insert(protocol, message);
            let commitment = MultiCommitBlock::try_commit(&source).unwrap();

            let slot = commitment.commitments[index as usize];
            assert_eq!(slot.protocol, Some(protocol));
            assert_eq!(slot.message, message);

            for others in 0u8..3 {
                if index == others {
                    continue;
                }
                let slot = commitment.commitments[others as usize];
                assert_eq!(slot.protocol, None);
                assert_ne!(slot.message, message);

                let mut engine = entropy_tagged_engine();
                engine.input(&commitment.entropy.unwrap().to_le_bytes());
                engine.input(&[others, 0u8]);
                assert_eq!(slot.message, Message::from_engine(engine));
            }

            let lnpbp4 = commitment.consensus_commit();
            let crafted = MultiCommitment::hash(
                commitment.commitments.strict_serialize().unwrap(),
            );
            assert_eq!(lnpbp4, crafted);
            assert!(commitment.consensus_verify(&lnpbp4));
        }

        for index in 1u8..3 {
            let mut source = MultiSource::default();
            protocol[31u8] = index; // Checking endianness
            source.messages.insert(protocol, message);
            let commitment = MultiCommitBlock::try_commit(&source).unwrap();

            let slot = commitment.commitments[index as usize];
            assert_eq!(slot.protocol, None);
            assert_ne!(slot.message, message);
        }
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_extension() {
        let source = MultiSource {
            min_length: 1,
            messages: bmap! {
                ProtocolId::from_inner([0u8; 32]) => Message::hash("First message".as_bytes()),
                ProtocolId::from_inner([1u8; 32]) => Message::hash("Second message".as_bytes())
            },
        };

        MultiCommitment::try_commit(&source).unwrap();
    }
}
