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

//! Multi-protocol commitments according to [LNPBP-4] standard.
//!
//! [LNPBP-4]: https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0004.md

mod atoms;
mod tree;
mod block;

pub use atoms::{Commitment, Message, MessageMap, MultiSource, ProtocolId};
pub use block::{LeafNotKnown, MerkleBlock, MerkleProof, UnrelatedProof};
pub(self) use tree::protocol_id_pos;
pub use tree::{Error, IntoIter, MerkleTree};

const LNPBP4_TAG: [u8; 16] = *b"urn:lnpbp:lnpbp4";
