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

use bitcoin_hashes::sha256;

use crate::Slice32;
#[cfg(feature = "rand")]
use crate::TryCommitVerify;

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
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error, Debug, Display,
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

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{message}")]
#[derive(StrictEncode, StrictDecode)]
/// Single item within a multi-message commitment, consisting of optional
/// protocol information (if known) and the actual single message commitment
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

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Default,
    StrictEncode,
    StrictDecode,
)]
/// Multi-message commitment data according to [LNPBP-4] specification.
///
/// To create commitment use [`TryCommitVerify::try_commit`] method.
///
/// [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md
pub struct MultiCommitBlock {
    /// Array of commitment items (see [`MultiCommitItem`])
    pub commitments: Vec<MultiCommitItem>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`TryCommitVerify::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    pub entropy: Option<u64>,
}

const MIDSTATE_ENTROPY: [u8; 32] = [
    0xF4, 0x0D, 0x86, 0x94, 0x9F, 0xFF, 0xAD, 0xEE, 0x19, 0xEA, 0x50, 0x20,
    0x60, 0xAB, 0x6B, 0xAD, 0x11, 0x61, 0xB2, 0x35, 0x83, 0xD3, 0x78, 0x18,
    0x52, 0x0D, 0xD4, 0xD1, 0xD8, 0x88, 0x1E, 0x61,
];

#[cfg(feature = "rand")]
impl TryCommitVerify<MultiSource> for MultiCommitBlock {
    type Error = Error;

    fn try_commit(source: &MultiSource) -> Result<Self, Error> {
        use amplify::num::u256;
        use bitcoin_hashes::{Hash, HashEngine};
        use rand::{thread_rng, Rng};

        let m = source.messages.len();
        if m > u16::MAX as usize {
            return Err(Error::TooManyMessages(m));
        }
        let mut n = m as u16;
        // We use some minimum number of items, to increase privacy
        n = n.max(source.min_length);

        let ordered = loop {
            if n > u16::MAX {
                return Err(Error::CantFitInMaxSlots);
            }

            let mut ordered = BTreeMap::<usize, (ProtocolId, Message)>::new();
            if source.messages.iter().all(|(protocol, message)| {
                let rem = u256::from_le_bytes(**protocol)
                    % u256::from_u64(n as u64).expect("u256 type is broken");
                ordered
                    .insert(rem.low_u64() as usize, (*protocol, *message))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
        };

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

#[cfg(test)]
mod test {
    use super::*;
    use amplify::Wrapper;
    use bitcoin_hashes::{Hash, HashEngine};

    fn entropy_tagged_engine() -> sha256::HashEngine {
        let tag_hash = sha256::Hash::hash("LNPBP4:entropy".as_bytes());
        let mut engine = Message::engine();
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        engine
    }

    #[test]
    fn test_lnpbp4_tags() {
        let midstate = sha256::Midstate::from_inner(MIDSTATE_ENTROPY);
        assert_eq!(midstate, entropy_tagged_engine().midstate());
    }

    #[test]
    #[cfg(feature = "rand")]
    fn test_commit() {
        let mut protocol = ProtocolId::from_inner([0u8; 32]);
        let message = Message::hash("First message".as_bytes());

        for index in 0u8..3 {
            let mut source = MultiSource::default();
            protocol[0] = index;
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
        }

        for index in 1u8..3 {
            let mut source = MultiSource::default();
            protocol[31] = index; // Checking endianness
            source.messages.insert(protocol, message);
            let commitment = MultiCommitBlock::try_commit(&source).unwrap();

            let slot = commitment.commitments[index as usize];
            assert_eq!(slot.protocol, None);
            assert_ne!(slot.message, message);
        }
    }
}
