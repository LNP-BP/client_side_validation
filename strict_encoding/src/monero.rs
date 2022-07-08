// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
//
// Written in 2022 by
//     h4sh3d <h4sh3d@protonmail.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

use std::io;

use monero::blockdata::block::{Block, BlockHeader};
use monero::blockdata::transaction::{
    ExtraField, KeyImage, SubField, Transaction, TransactionPrefix, TxIn,
    TxOut, TxOutTarget,
};
use monero::cryptonote::hash::{Hash, Hash8};
use monero::cryptonote::subaddress::Index;
use monero::util::address::{Address, PaymentId};
use monero::util::amount::{Amount, SignedAmount};
use monero::util::key::{KeyPair, PrivateKey, PublicKey, ViewPair};
use monero::util::ringct::{
    BoroSig, Bulletproof, Clsag, CtKey, EcdhInfo, Key, Key64, MgSig,
    MultisigKlrki, MultisigOut, RangeSig, RctSigBase, RctType, Signature,
};
use monero::VarInt;

use crate::{strategies, Error, Strategy, StrictDecode, StrictEncode};

impl Strategy for Transaction {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for TransactionPrefix {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Block {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for BlockHeader {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for SubField {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for TxIn {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for ExtraField {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for KeyImage {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for TxOut {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for TxOutTarget {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for EcdhInfo {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for RctType {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for PublicKey {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for PrivateKey {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Hash {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Hash8 {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Address {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for BoroSig {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Bulletproof {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Clsag {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for CtKey {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Key64 {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Key {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for MgSig {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for MultisigKlrki {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for MultisigOut {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for RangeSig {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for RctSigBase {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for Signature {
    type Strategy = strategies::MoneroConsensus;
}

impl Strategy for VarInt {
    type Strategy = strategies::MoneroConsensus;
}

impl StrictEncode for Amount {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_pico().strict_encode(&mut e)
    }
}

impl StrictDecode for Amount {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::from_pico(u64::strict_decode(&mut d)?))
    }
}

impl StrictEncode for SignedAmount {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_pico().strict_encode(&mut e)
    }
}

impl StrictDecode for SignedAmount {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::from_pico(i64::strict_decode(&mut d)?))
    }
}

impl StrictEncode for PaymentId {
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.to_fixed_bytes().strict_encode(e)
    }
}

impl StrictDecode for PaymentId {
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        <[u8; 8]>::strict_decode(d).map(Self::from)
    }
}

impl StrictEncode for Index {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.major, self.minor))
    }
}

impl StrictDecode for Index {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; major, minor; crate))
    }
}

impl StrictEncode for KeyPair {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.view, self.spend))
    }
}

impl StrictDecode for KeyPair {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; view, spend; crate))
    }
}

impl StrictEncode for ViewPair {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.view, self.spend))
    }
}

impl StrictDecode for ViewPair {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; view, spend; crate))
    }
}
