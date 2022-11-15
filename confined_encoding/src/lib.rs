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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! Library implementing **strict encoding** standard, defined by
//! [LNPBP-7](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0007.md).
//! Strict encoding is a binary conservative encoding extensively used in
//! client-side-validation for deterministic portable (platform-independent)
//! serialization of data with a known internal data structure. Strict encoding
//! is a schema-less encoding.
//!
//! As a part of strict encoding, crate also includes implementation of
//! network address **uniform encoding** standard
//! ([LMPBP-42]([LNPBP-7](https://github.com/LNP-BP/LNPBPs/blob/master/lnpbp-0042.md))),
//! which allows representation of any kind of network address as a fixed-size
//! byte string occupying 37 bytes. This standard is used for the strict
//! encoding of networking addresses.
//!
//! Library defines two main traits, [`StrictEncode`] and [`StrictDecode`],
//! which should be implemented on each type that requires to be represented
//! for client-side-validation. It also defines possible encoding error cases
//! with [`derive@Error`] and provides derivation macros
//! `#[derive(StrictEncode, StrictDecode)]`, which are a part of
//! `strict_encode_derive` sub-crate and represented by a default feature
//! `derive`. Finally, it implements strict encoding traits for main data types
//! defined by rust standard library and frequently used crates; the latter
//! increases the number of dependencies and thus can be controlled with
//! feature flags:
//! - `chrono` (used by default): date & time types from `chrono` crate
//! - `miniscript`: types defined in bitcoin Miniscript
//! - `crypto`: non-bitcoin cryptographic primitives, which include Ed25519
//!   curve, X25519 signatures from `ed25519-dalek` library and pedersen
//!   commitments + bulletproofs from `grin_secp256k1zkp` library. Encodings for
//!   other cryptography-related types, such as Secp256k1 and hashes, are always
//!   included as a part of the library - see NB below.
//!
//! NB: this crate requires `bitcoin` as an upstream dependency since many of
//!     strict-encoded formats are standardized as using *bitcoin consensus
//!     encoding*.

#[cfg(feature = "derive")]
pub extern crate confined_encoding_derive as derive;
#[cfg(feature = "derive")]
pub use derive::{NetworkDecode, NetworkEncode, StrictDecode, StrictEncode};

#[macro_use]
extern crate amplify;
#[cfg(test)]
#[macro_use]
extern crate confined_encoding_test;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[macro_use]
mod macros;

mod amplify_types;
mod bitcoin;
mod bitcoin_hashes;
mod bulletproofs;
mod collections;
mod pointers;
mod primitives;
mod slice32;
pub mod strategies;

use std::io::Seek;
use std::ops::Range;
use std::path::Path;
use std::string::FromUtf8Error;
use std::{fmt, fs, io};

/// Re-exporting extended read and write functions from bitcoin consensus
/// module so others may use semantic convenience
/// `strict_encode::ReadExt`
pub use ::bitcoin::consensus::encode::{ReadExt, WriteExt};
use amplify::IoError;
pub use collections::{LargeVec, MediumVec};
pub use strategies::Strategy;

/// Binary encoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications;
/// in some circumstances may be used for commitment procedures; however it must
/// be kept in mind that sometime commitment may follow "fold" scheme
/// (Merklization or nested commitments) and in such cases this trait can't be
/// applied. It is generally recommended for consensus-related commitments to
/// utilize `CommitVerify`, `TryCommitVerify` and `EmbedCommitVerify` traits  
/// from `commit_verify` module.
pub trait StrictEncode {
    /// Encode with the given [`std::io::Write`] instance; must return result
    /// with either amount of bytes encoded – or implementation-specific
    /// error type.
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error>;

    /// Serializes data as a byte array using [`StrictEncode::strict_encode`]
    /// function
    fn strict_serialize(&self) -> Result<Vec<u8>, Error> {
        let mut e = vec![];
        let _ = self.strict_encode(&mut e)?;
        Ok(e)
    }

    /// Saves data to a file at a given `path`. If the file does not exists,
    /// attempts to create the file. If the file already exists, it gets
    /// truncated.
    fn strict_file_save(&self, path: impl AsRef<Path>) -> Result<usize, Error> {
        let file = fs::File::create(path)?;
        self.strict_encode(file)
    }
}

/// Binary decoding according to the strict rules that usually apply to
/// consensus-critical data structures. May be used for network communications.
/// MUST NOT be used for commitment verification: even if the commit procedure
/// uses [`StrictEncode`], the actual commit verification MUST be done with
/// `CommitVerify`, `TryCommitVerify` and `EmbedCommitVerify` traits, which,
/// instead of deserializing (nonce operation for commitments) repeat the
/// commitment procedure for the revealed message and verify it against the
/// provided commitment.
pub trait StrictDecode: Sized {
    /// Decode with the given [`std::io::Read`] instance; must either
    /// construct an instance or return implementation-specific error type.
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error>;

    /// Tries to deserialize byte array into the current type using
    /// [`StrictDecode::strict_decode`]. If there are some data remains in the
    /// buffer once deserialization is completed, fails with
    /// [`Error::DataNotEntirelyConsumed`]. Use `io::Cursor` over the buffer and
    /// [`StrictDecode::strict_decode`] to avoid such failures.
    fn strict_deserialize(data: impl AsRef<[u8]>) -> Result<Self, Error> {
        Self::strict_decode(data.as_ref())
    }

    /// Reads data from file at `path` and reconstructs object from it. Fails
    /// with [`Error::DataNotEntirelyConsumed`] if file contains remaining
    /// data after the object reconstruction.
    fn strict_file_load(path: impl AsRef<Path>) -> Result<Self, Error> {
        let mut file = fs::File::open(path)?;
        let obj = Self::strict_decode(&mut file)?;
        if file.stream_position()? != file.metadata()?.len() {
            Err(Error::DataNotEntirelyConsumed)
        } else {
            Ok(obj)
        }
    }
}

/// Convenience method for strict encoding of data structures implementing
/// [`StrictEncode`] into a byte vector.
pub fn strict_serialize<T>(data: &T) -> Result<Vec<u8>, Error>
where
    T: StrictEncode,
{
    let mut encoder = io::Cursor::new(vec![]);
    data.strict_encode(&mut encoder)?;
    Ok(encoder.into_inner())
}

/// Convenience method for strict decoding of data structures implementing
/// [`StrictDecode`] from any byt data source.
pub fn strict_deserialize<T>(data: impl AsRef<[u8]>) -> Result<T, Error>
where
    T: StrictDecode,
{
    let mut decoder = io::Cursor::new(data.as_ref());
    let rv = T::strict_decode(&mut decoder)?;
    let consumed = decoder.position() as usize;

    // Fail if data are not consumed entirely.
    if consumed == data.as_ref().len() {
        Ok(rv)
    } else {
        Err(Error::DataNotEntirelyConsumed)
    }
}

/// Possible errors during strict encoding and decoding process
#[derive(Clone, PartialEq, Eq, Debug, Display, From, Error)]
#[display(doc_comments)]
pub enum Error {
    /// I/O error during data strict encoding
    #[from(io::Error)]
    #[from(io::ErrorKind)]
    Io(IoError),

    /// String data are not in valid UTF-8 encoding
    #[from]
    Utf8Conversion(std::str::Utf8Error),

    /// A collection (slice, vector or other type) has more items ({0}) than
    /// 2^16 (i.e. maximum value which may be held by `u16` `size`
    /// representation according to the LNPBP-6 spec)
    ExceedMaxItems(usize),

    /// In terms of strict encoding, we interpret `Option` as a zero-length
    /// `Vec` (for `Optional::None`) or single-item `Vec` (for
    /// `Optional::Some`). For decoding an attempt to read `Option` from a
    /// encoded non-0 or non-1 length Vec will result in
    /// `Error::WrongOptionalEncoding`.
    #[display(
        "Invalid value {0} met as an optional type byte, which must be equal \
         to either 0 (no value) or 1"
    )]
    WrongOptionalEncoding(u8),

    /// Enum `{0}` value does not fit into representation bit dimensions
    EnumValueOverflow(&'static str),

    /// An unsupported value `{0}` for enum `{0}` encountered during decode
    /// operation
    EnumValueNotKnown(&'static str, usize),

    /// The data are correct, however their structure indicate that they were
    /// created with the future software version which has a functional absent
    /// in the current implementation.
    /// {0}
    UnsupportedDataStructure(&'static str),

    /// Decoding resulted in value `{2}` for type `{0}` that exceeds the
    /// supported range {1:#?}
    ValueOutOfRange(&'static str, Range<u128>, u128),

    /// A repeated value for `{0}` found during set collection deserialization
    RepeatedValue(String),

    /// Returned by the convenience method [`StrictDecode::strict_decode`] if
    /// not all provided data were consumed during decoding process
    #[display(
        "Data were not consumed entirely during strict decoding procedure"
    )]
    DataNotEntirelyConsumed,

    /// Data integrity problem during strict decoding operation: {0}
    DataIntegrityError(String),
}

impl From<Error> for fmt::Error {
    #[inline]
    fn from(_: Error) -> Self { fmt::Error }
}

impl From<FromUtf8Error> for Error {
    fn from(err: FromUtf8Error) -> Self {
        Error::Utf8Conversion(err.utf8_error())
    }
}

/// Possible errors during TLV extension encoding and decoding process
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum TlvError {
    /// deterministic order of TLV records is broken: type {read} follows after
    /// type {max}
    Order {
        /// TLV type id read at the current position
        read: u64,
        /// maximum value of TLV type id read previously
        max: u64,
    },

    /// incorrect length of TLV record value: expected {expected}, but only
    /// {actual} bytes read
    Len {
        /// TLV value length encoded in the TLV record
        expected: u64,
        /// Actual remaining length of the TLV stream
        actual: u64,
    },

    /// repeated TLV record with id {0}
    Repeated(u64),

    /// an unknown even TLV type {0}
    UnknownEvenType(u64),
}

// TODO: With 2.0 release add Tlv case to the Error enum
impl From<TlvError> for Error {
    fn from(err: TlvError) -> Self {
        match err {
            TlvError::Repeated(size) => Error::RepeatedValue(size.to_string()),
            err => Error::DataIntegrityError(err.to_string()),
        }
    }
}
