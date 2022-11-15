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

//! Strategies simplifying implementation of encoding traits.
//!
//! Implemented after concept by Martin Habovštiak <martin.habovstiak@gmail.com>

use std::io;

use amplify::Wrapper;

use super::{ConfinedDecode, ConfinedEncode, Error};

/// Encodes/decodes data as a [`bitcoin_hashes::Hash`]-based (wrapper) type,
/// i.e. as a fixed-size byte string of [`bitcoin_hashes::Hash::LEN`] length.
pub struct HashFixedBytes;

/// Encodes/decodes data as a wrapped type, i.e. according to the rules of
/// encoding for its inner representation. Applicable only for types
/// implementing [`amplify::Wrapper`]
pub struct Wrapped;

/// Marker trait defining specific encoding strategy which should be used for
/// automatic implementation of both [`ConfinedEncode`] and [`ConfinedDecode`].
pub trait Strategy {
    /// Specific strategy. List of supported strategies:
    /// - [`HashFixedBytes`]
    /// - [`Wrapped`]
    type Strategy;
}

impl<T> ConfinedEncode for T
where
    T: Strategy + Clone,
    amplify::Holder<T, <T as Strategy>::Strategy>: ConfinedEncode,
{
    #[inline]
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        amplify::Holder::new(self.clone()).confined_encode(e)
    }
}

impl<T> ConfinedDecode for T
where
    T: Strategy,
    amplify::Holder<T, <T as Strategy>::Strategy>: ConfinedDecode,
{
    #[inline]
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(amplify::Holder::confined_decode(d)?.into_inner())
    }
}

impl<W> ConfinedEncode for amplify::Holder<W, Wrapped>
where
    W: Wrapper,
    W::Inner: ConfinedEncode,
{
    #[inline]
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().as_inner().confined_encode(e)
    }
}

impl<W> ConfinedDecode for amplify::Holder<W, Wrapped>
where
    W: Wrapper,
    W::Inner: ConfinedDecode,
{
    #[inline]
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(W::from_inner(W::Inner::confined_decode(d)?)))
    }
}

impl<H> ConfinedEncode for amplify::Holder<H, HashFixedBytes>
where
    H: bitcoin_hashes::Hash,
{
    #[inline]
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.as_inner()[..])?;
        Ok(H::LEN)
    }
}

impl<H> ConfinedDecode for amplify::Holder<H, HashFixedBytes>
where
    H: bitcoin_hashes::Hash,
{
    #[inline]
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = vec![0u8; H::LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::new(H::from_slice(&buf).expect(
            "internal hash data representation length mismatch between \
             `from_slice` requirements and `LEN` constant value",
        )))
    }
}

impl From<bitcoin::hashes::Error> for Error {
    #[inline]
    fn from(_: bitcoin::hashes::Error) -> Self {
        Error::DataIntegrityError("Incorrect hash length".to_string())
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    #[inline]
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        if let bitcoin::consensus::encode::Error::Io(err) = e {
            err.into()
        } else {
            Error::DataIntegrityError(e.to_string())
        }
    }
}
