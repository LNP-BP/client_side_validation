// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems
// (InDCS), Switzerland. Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Coding conventions
#![deny(
    unsafe_code,
    dead_code,
    missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! Standard cryptographic commitment library, created and supported by the
//! LNP/BP Labs.
// TODO: Extend description and readme

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_encoding_derive;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

#[cfg(feature = "derive")]
pub use commit_encoding_derive::CommitEncode;

mod commit;
mod conceal;
mod convolve;
mod embed;
mod id;
#[cfg(feature = "stl")]
pub mod stl;

pub mod merkle;
pub mod mpc;
mod digest;
#[cfg(feature = "vesper")]
pub mod vesper;

pub use commit::{CommitVerify, TryCommitVerify, VerifyError};
pub use conceal::Conceal;
pub use convolve::{ConvolveCommit, ConvolveCommitProof, ConvolveVerifyError};
pub use digest::{Digest, DigestExt, Ripemd160, Sha256};
pub use embed::{EmbedCommitProof, EmbedCommitVerify, EmbedVerifyError, VerifyEq};
pub use id::{
    CommitColType, CommitEncode, CommitEngine, CommitId, CommitLayout, CommitStep, CommitmentId,
    CommitmentLayout, StrictHash,
};
pub use merkle::{MerkleBuoy, MerkleHash, MerkleLeaves, MerkleNode, NodeBranching};

/// Name of the CommitVerify strict type library.
pub const LIB_NAME_COMMIT_VERIFY: &str = "CommitVerify";

/// Marker trait for specific commitment protocols.
///
/// Generic parameter `Protocol` used in commitment scheme traits provides a
/// context & configuration for the concrete implementations.
///
/// Introduction of such generic allows to:
/// - implement trait for foreign data types;
/// - add multiple implementations under different commitment protocols to the
///   combination of the same message and container type (each of each will have
///   its own `Proof` type defined as an associated generic).
pub trait CommitmentProtocol {}

/// Protocol defining commits created by using externally created hash value
/// *optionally pre-tagged*.
pub struct UntaggedProtocol;
impl CommitmentProtocol for UntaggedProtocol {}

/// Reserved bytes.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
#[display("reserved")]
#[derive(StrictType, StrictEncode)]
#[strict_type(lib = LIB_NAME_COMMIT_VERIFY)]
pub struct ReservedBytes<const LEN: usize, const VAL: u8 = 0>([u8; LEN]);

impl<const LEN: usize, const VAL: u8> Default for ReservedBytes<LEN, VAL> {
    fn default() -> Self { Self([VAL; LEN]) }
}

impl<const LEN: usize, const VAL: u8> From<[u8; LEN]> for ReservedBytes<LEN, VAL> {
    fn from(value: [u8; LEN]) -> Self {
        assert_eq!(value, [VAL; LEN]);
        Self(value)
    }
}

mod _reserved {
    use strict_encoding::{DecodeError, ReadTuple, StrictDecode, TypedRead};

    use crate::{CommitEncode, CommitEngine, ReservedBytes, StrictHash};

    impl<const LEN: usize, const VAL: u8> CommitEncode for ReservedBytes<LEN, VAL> {
        type CommitmentId = StrictHash;

        fn commit_encode(&self, e: &mut CommitEngine) { e.commit_to_serialized(self) }
    }

    impl<const LEN: usize, const VAL: u8> StrictDecode for ReservedBytes<LEN, VAL> {
        fn strict_decode(reader: &mut impl TypedRead) -> Result<Self, DecodeError> {
            let reserved = reader.read_tuple(|r| r.read_field().map(Self))?;
            if reserved != ReservedBytes::<LEN, VAL>::default() {
                Err(DecodeError::DataIntegrityError(format!(
                    "unsupported reserved byte value indicating a future RGB version. Please \
                     update your software, or, if the problem persists, contact your vendor \
                     providing the following version information: {reserved}"
                )))
            } else {
                Ok(reserved)
            }
        }
    }

    #[cfg(feature = "serde")]
    mod _serde {
        use std::fmt;

        use serde::de::Visitor;
        use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

        use super::*;

        impl<const LEN: usize, const VAL: u8> Serialize for ReservedBytes<LEN, VAL> {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where S: Serializer {
                // Doing nothing
                serializer.serialize_unit()
            }
        }

        impl<'de, const LEN: usize, const VAL: u8> Deserialize<'de> for ReservedBytes<LEN, VAL> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where D: Deserializer<'de> {
                #[derive(Default)]
                pub struct UntaggedUnitVisitor;

                impl Visitor<'_> for UntaggedUnitVisitor {
                    type Value = ();

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "reserved unit")
                    }

                    fn visit_none<E>(self) -> Result<(), E>
                    where E: de::Error {
                        Ok(())
                    }

                    fn visit_unit<E>(self) -> Result<(), E>
                    where E: de::Error {
                        Ok(())
                    }
                }

                deserializer.deserialize_unit(UntaggedUnitVisitor)?;
                Ok(default!())
            }
        }
    }
}

/// Helpers for writing test functions working with commit schemes
#[cfg(test)]
pub mod test_helpers {
    #![cfg_attr(coverage_nightly, coverage(off))]

    use amplify::confinement::SmallVec;
    use amplify::hex::FromHex;

    pub use super::commit::test_helpers::*;
    pub use super::embed::test_helpers::*;
    use super::*;

    /// Generates a set of messages for testing purposes
    ///
    /// All of these messages MUST produce different commitments, otherwise the
    /// commitment algorithm is not collision-resistant
    pub fn gen_messages() -> Vec<SmallVec<u8>> {
        vec![
            // empty message
            b"".to_vec(),
            // zero byte message
            b"\x00".to_vec(),
            // text message
            b"test".to_vec(),
            // text length-extended message
            b"test*".to_vec(),
            // short binary message
            Vec::from_hex("deadbeef").unwrap(),
            // length-extended version
            Vec::from_hex("deadbeef00").unwrap(),
            // prefixed version
            Vec::from_hex("00deadbeef").unwrap(),
            // serialized public key as text
            b"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_vec(),
            // the same public key binary data
            Vec::from_hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
                .unwrap(),
            // different public key
            Vec::from_hex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9")
                .unwrap(),
        ]
        .into_iter()
        .map(|v| SmallVec::try_from(v).unwrap())
        .collect()
    }
}
