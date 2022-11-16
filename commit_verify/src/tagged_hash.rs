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

//! Bitcoin tagged hash helper types.

#![allow(clippy::needless_borrow)] // Due to amplify_derive::Display bug

use amplify::{Slice32, Wrapper};
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::{hex, sha256, sha256t, Error, Hash, HashEngine};

/// Helper class for tests and creation of tagged hashes with dynamically-
/// defined tags. Do not use in all other cases; utilize
/// [`bitcoin_hashes::sha256t`] type and
/// [`bitcoin_hashes::sha256t_hash_newtype`] macro instead.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display,
    From
)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct Midstate(Slice32);

impl Midstate {
    /// Constructs tagged hash midstate for a given tag data
    pub fn with(tag: impl AsRef<[u8]>) -> Self {
        let mut engine = sha256::Hash::engine();
        let tag_hash = sha256::Hash::hash(tag.as_ref());
        engine.input(&tag_hash[..]);
        engine.input(&tag_hash[..]);
        Self::from_inner(engine.midstate().into_inner().into())
    }
}

/// Trait with convenience functions, which is auto-implemented for all types
/// wrapping [`sha256t::Hash`], i.e. BIP-340-like hash types.
pub trait TaggedHash<Tag>
where
    Self: Sized + Wrapper<Inner = sha256t::Hash<Tag>>,
    Tag: sha256t::Tag + 'static,
{
    /// Constructs tagged hash out of a given message data
    fn hash(msg: impl AsRef<[u8]>) -> Self {
        Self::from_inner(sha256t::Hash::hash(msg.as_ref()))
    }

    /// Constructs tagged hash out of other hash type.
    ///
    /// Danger: this does not guarantees that the hash is tagged
    fn from_hash(hash: impl Hash<Inner = [u8; 32]>) -> Self {
        Self::from_inner(sha256t::Hash::from_inner(hash.into_inner()))
    }

    /// Constructs tagged hash from a given hexadecimal string
    fn from_hex(hex: &str) -> Result<Self, hex::Error> {
        Ok(Self::from_inner(sha256t::Hash::from_hex(hex)?))
    }

    /// Constructs tagged hash from byte slice. If slice length is not equal to
    /// 32 bytes, fails with [`Error::InvalidLength`] (this is just a
    /// wrapper for [`sha256t::Hash::from_slice`]).
    fn from_bytes(slice: impl AsRef<[u8]>) -> Result<Self, Error> {
        sha256t::Hash::from_slice(slice.as_ref()).map(Self::from_inner)
    }

    /// Constructs tagged hash type from a fixed-size array of 32 bytes.
    fn from_array(array: [u8; 32]) -> Self {
        Self::from_inner(sha256t::Hash::from_inner(array))
    }

    /// Constructs tagged hash type from a hash engine.
    fn from_engine(engine: sha256::HashEngine) -> Self {
        Self::from_inner(sha256t::Hash::from_engine(engine))
    }

    /// Returns a reference to a slice representing internal hash data
    fn as_slice(&self) -> &[u8] { self.as_inner().as_inner() }

    /// Converts to a 32-byte slice array representing internal hash data
    fn into_array(self) -> [u8; 32] { self.into_inner().into_inner() }

    /// Converts current tagged hash type into a base [`sha256t::Hash`] type
    fn into_sha356t(self) -> sha256t::Hash<Tag> { self.into_inner() }

    /// Converts tagged hash type into basic SHA256 hash
    fn into_sha256(self) -> sha256::Hash {
        sha256::Hash::from_inner(self.into_inner().into_inner())
    }

    /// Constructs vector representation of the data in tagged hash
    fn to_vec(self) -> Vec<u8> { self.into_array().to_vec() }
}

impl<H, Tag> TaggedHash<Tag> for H
where
    H: Wrapper<Inner = sha256t::Hash<Tag>>,
    Tag: sha256t::Tag + 'static,
{
}
