// LNP/BP client-side-validation library implementing respective LNPBP
// specifications & standards (LNPBP-7, 8, 9, 42)
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

//! Bitcoin tagged hash helper types.

use amplify::Wrapper;
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::{hex, sha256, sha256t, Error, Hash, HashEngine};
#[cfg(feature = "serde")]
use serde_with::{As, DisplayFromStr};

use crate::Slice32;

/// Helper class for tests and creation of tagged hashes with dynamically-
/// defined tags. Do not use in all other cases; utilize
/// [`bitcoin::hashes::sha256t`] type and [`bitcoin::sha256t_hash_newtype!`]
/// macro instead.
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", transparent)
)]
#[derive(
    Wrapper,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Debug,
    Display,
    From,
)]
#[display(LowerHex)]
#[wrapper(FromStr, LowerHex, UpperHex)]
pub struct Midstate(
    #[cfg_attr(feature = "serde", serde(with = "As::<DisplayFromStr>"))]
    Slice32,
);

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
pub trait TaggedHash<'a, T>
where
    Self: Wrapper<Inner = sha256t::Hash<T>>,
    T: 'a + sha256t::Tag,
{
    /// Constructs tagged hash out of a given message data
    fn hash(msg: impl AsRef<[u8]>) -> Self
    where
        Self: Sized,
    {
        Self::from_inner(sha256t::Hash::hash(msg.as_ref()))
    }

    /// Constructs tagged hash out of other hash type.
    ///
    /// Danger: this does not guarantees that the hash is tagged
    fn from_hash<X>(hash: X) -> Self
    where
        Self: Sized,
        X: Hash<Inner = [u8; 32]>,
    {
        Self::from_inner(sha256t::Hash::from_inner(hash.into_inner()))
    }

    /// Constructs tagged hash from byte slice. If slice length is not equal to
    /// 32 bytes, fails with [`Error::InvalidLength`] (this is just a
    /// wrapper for [`sha256t::Hash::from_slice`]).
    fn from_slice(slice: &[u8]) -> Result<Self, Error>
    where
        Self: Sized,
    {
        sha256t::Hash::from_slice(slice).map(Self::from_inner)
    }

    /// Returns 32-byte slice array representing internal hash data
    fn as_slice(&'a self) -> &'a [u8; 32] {
        self.as_inner().as_inner()
    }

    /// Constructs tagged hash from a given hexadecimal string
    fn from_hex(hex: &str) -> Result<Self, hex::Error>
    where
        Self: Sized,
    {
        Ok(Self::from_inner(sha256t::Hash::from_hex(hex)?))
    }
}

impl<'a, U, T> TaggedHash<'a, T> for U
where
    U: Wrapper<Inner = sha256t::Hash<T>>,
    T: 'a + sha256t::Tag,
{
}
