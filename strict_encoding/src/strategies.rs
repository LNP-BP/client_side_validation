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

use super::{net, Error, StrictDecode, StrictEncode};

/// Encodes/decodes data as a [`bitcoin_hashes::Hash`]-based (wrapper) type,
/// i.e. as a fixed-size byte string of [`bitcoin_hashes::Hash::LEN`] length.
pub struct HashFixedBytes;

/// Encodes/decodes data in the same way as they are encoded/decoded according
/// to bitcoin consensus rules from Bitcoin Core
#[cfg(feature = "bitcoin")]
pub struct BitcoinConsensus;

/// Encodes/decodes data in the same way as they are encoded/decoded according
/// to monero consensus rules from monero-project/monero
#[cfg(feature = "monero")]
pub struct MoneroConsensus;

/// Encodes/decodes data as a wrapped type, i.e. according to the rules of
/// encoding for its inner representation. Applicable only for types
/// implementing [`amplify::Wrapper`]
pub struct Wrapped;

/// Encodes/decodes internet address according to LNPBP-42 "Uniform address
/// encoding" rules. Applicable only for types implementing [`net::Uniform`].
pub struct UsingUniformAddr;

/// Marker trait defining specific encoding strategy which should be used for
/// automatic implementation of both [`StrictEncode`] and [`StrictDecode`].
pub trait Strategy {
    /// Specific strategy. List of supported strategies:
    /// - [`HashFixedBytes`]
    /// - [`BitcoinConsensus`]
    /// - [`Wrapped`]
    /// - [`UsingUniformAddr`]
    type Strategy;
}

impl<T> StrictEncode for T
where
    T: Strategy + Clone,
    amplify::Holder<T, <T as Strategy>::Strategy>: StrictEncode,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        amplify::Holder::new(self.clone()).strict_encode(e)
    }
}

impl<T> StrictDecode for T
where
    T: Strategy,
    amplify::Holder<T, <T as Strategy>::Strategy>: StrictDecode,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(amplify::Holder::strict_decode(d)?.into_inner())
    }
}

impl<W> StrictEncode for amplify::Holder<W, Wrapped>
where
    W: Wrapper,
    W::Inner: StrictEncode,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().as_inner().strict_encode(e)
    }
}

impl<W> StrictDecode for amplify::Holder<W, Wrapped>
where
    W: Wrapper,
    W::Inner: StrictDecode,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(W::from_inner(W::Inner::strict_decode(d)?)))
    }
}

impl<H> StrictEncode for amplify::Holder<H, HashFixedBytes>
where
    H: bitcoin_hashes::Hash,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        e.write_all(&self.as_inner()[..])?;
        Ok(H::LEN)
    }
}

impl<H> StrictDecode for amplify::Holder<H, HashFixedBytes>
where
    H: bitcoin_hashes::Hash,
{
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let mut buf = vec![0u8; H::LEN];
        d.read_exact(&mut buf)?;
        Ok(Self::new(H::from_slice(&buf).expect(
            "internal hash data representation length mismatch between \
             `from_slice` requirements and `LEN` constant balue",
        )))
    }
}

#[cfg(feature = "bitcoin")]
impl<B> StrictEncode for amplify::Holder<B, BitcoinConsensus>
where
    B: bitcoin::consensus::Encodable,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().consensus_encode(e).map_err(Error::from)
    }
}

#[cfg(feature = "bitcoin")]
impl<B> StrictDecode for amplify::Holder<B, BitcoinConsensus>
where
    B: bitcoin::consensus::Decodable,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(B::consensus_decode(d).map_err(Error::from)?))
    }
}

#[cfg(feature = "monero")]
impl<B> StrictEncode for amplify::Holder<B, MoneroConsensus>
where
    B: monero::consensus::Encodable,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        self.as_inner()
            .consensus_encode(&mut e)
            .map_err(Error::from)
    }
}

#[cfg(feature = "monero")]
impl<B> StrictDecode for amplify::Holder<B, MoneroConsensus>
where
    B: monero::consensus::Decodable,
{
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(Self::new(B::consensus_decode(&mut d).map_err(Error::from)?))
    }
}

impl<A> StrictEncode for amplify::Holder<A, UsingUniformAddr>
where
    A: net::Uniform,
{
    #[inline]
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().to_raw_uniform().strict_encode(e)
    }
}

impl<A> StrictDecode for amplify::Holder<A, UsingUniformAddr>
where
    A: net::Uniform,
{
    #[inline]
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(
            A::from_raw_uniform_addr(net::RawUniformAddr::strict_decode(d)?)
                .map_err(|err| Error::DataIntegrityError(err.to_string()))?,
        ))
    }
}

#[cfg(feature = "bitcoin")]
impl From<bitcoin::hashes::Error> for Error {
    #[inline]
    fn from(_: bitcoin::hashes::Error) -> Self {
        Error::DataIntegrityError("Incorrect hash length".to_string())
    }
}

#[cfg(feature = "bitcoin")]
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

#[cfg(feature = "monero")]
impl From<monero::consensus::encode::Error> for Error {
    #[inline]
    fn from(e: monero::consensus::encode::Error) -> Self {
        if let monero::consensus::encode::Error::Io(err) = e {
            err.into()
        } else {
            Error::DataIntegrityError(e.to_string())
        }
    }
}
