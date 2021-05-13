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
//! LNPBP-4 defines a commit-verify scheme for committing to a multiple messages
//! under distinct protocols with ability to partially reveal set of the
//! commitments and still be able to prove the commitment for each message
//! without exposing the exact number of other messages and their respective
//! protocol identifiers.
//!
//! [LNPBP]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

use std::collections::BTreeMap;

use bitcoin_hashes::sha256;

use crate::Slice32;
#[cfg(feature = "rand")]
use crate::TryCommitVerify;

/// Source data for creation of multi-message commitments according to LNPBP-4
/// procedure
pub type ProtocolId = Slice32;

/// Original message participating in multi-message commitment.
///
/// The message must be represented by a SHA256 tagged hash. Since each message
/// may have a different tag, we can't use `sha256t` type directly and use its
/// `sha256::Hash` equivalent.
pub type Message = sha256::Hash;

/// Type alias for structured source multi-message data for commitment creation
pub type MessageMap = BTreeMap<ProtocolId, Message>;

/// LNPBP-4 commitment procedure is limited to 2^16 messages
#[derive(
    Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Error, Debug, Display,
)]
#[display(doc_comments)]
pub struct TooManyMessagesError;

#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate")
)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display)]
#[display("{commitment}")]
#[derive(StrictEncode, StrictDecode)]
/// Single item within a multi-message commitment, consisting of optional
/// protocol information (if known) and the actual single message commitment
pub struct MultiCommitItem {
    /// Protocol identifier, which may be hidden or absent for commitment
    /// placeholders
    pub protocol: Option<ProtocolId>,

    /// Message commitment (LNPBP-4 tagged hash of the message)
    pub commitment: Message,
}

impl MultiCommitItem {
    /// Constructs multi-message commitment item
    pub fn new(protocol: Option<ProtocolId>, commitment: Message) -> Self {
        Self {
            protocol,
            commitment,
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
/// Multi-message commitment data according to LNPBP-4 specification.
///
/// To create commitment use [`TryCommitVerify::try_commit`] method
pub struct MultiCommitBlock {
    /// Array of commitment items (see [`MultiCommitItem`])
    pub commitments: Vec<MultiCommitItem>,

    /// Entropy used for placeholders. May be unknown if the message is not
    /// constructed via [`TryCommitVerify::try_commit`] method but is provided
    /// by a third-party, whishing to conceal that information.
    pub entropy: Option<u64>,
}

#[cfg(feature = "rand")]
impl TryCommitVerify<MessageMap> for MultiCommitBlock {
    type Error = TooManyMessagesError;

    fn try_commit(
        multi_msg: &MessageMap,
    ) -> Result<Self, TooManyMessagesError> {
        use amplify::num::u256;
        use bitcoin_hashes::{Hash, HashEngine};
        use rand::{thread_rng, Rng};

        const SORT_LIMIT: usize = 2 << 16;

        let mut n = multi_msg.len();
        // We use some minimum number of items, to increase privacy
        n = n.max(3);
        let ordered = loop {
            let mut ordered = BTreeMap::<usize, (ProtocolId, Message)>::new();
            // TODO #6: Modify arithmetics in LNPBP-4 spec
            //       <https://github.com/LNP-BP/LNPBPs/issues/19>
            if multi_msg.iter().all(|(protocol, digest)| {
                let rem = u256::from_be_bytes(**protocol)
                    % u256::from_u64(n as u64)
                        .expect("Bitcoin U256 struct is broken");
                ordered
                    .insert(rem.low_u64() as usize, (*protocol, *digest))
                    .is_none()
            }) {
                break ordered;
            }
            n += 1;
            if n > SORT_LIMIT {
                // Memory allocation limit exceeded while trying to sort
                // multi-message commitment
                return Err(TooManyMessagesError);
            }
        };

        let entropy = {
            let mut rng = thread_rng();
            rng.gen::<u64>()
        };

        let mut commitments = Vec::<_>::with_capacity(n);
        for i in 0..n {
            match ordered.get(&i) {
                None => {
                    let mut engine = Message::engine();
                    for _ in 0..4 {
                        engine.input(&entropy.to_le_bytes());
                        engine.input(&i.to_le_bytes());
                    }
                    commitments.push(MultiCommitItem::new(
                        None,
                        Message::from_engine(engine),
                    ))
                }
                Some((contract_id, commitment)) => commitments.push(
                    MultiCommitItem::new(Some(*contract_id), *commitment),
                ),
            }
        }

        Ok(Self {
            commitments,
            entropy: Some(entropy),
        })
    }
}
