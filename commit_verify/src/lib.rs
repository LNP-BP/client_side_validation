// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    // TODO: uncomment missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;
#[macro_use]
extern crate commit_encoding_derive;
#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;
extern crate core;

#[cfg(feature = "derive")]
pub use commit_encoding_derive::CommitEncode;

pub(self) mod commit;
mod conceal;
mod convolve;
pub(self) mod embed;
mod encode;
mod id;
#[cfg(feature = "stl")]
pub mod stl;

pub mod merkle;
pub mod mpc;
mod sha256;

pub use commit::{CommitVerify, StrictEncodedProtocol, TryCommitVerify};
pub use conceal::Conceal;
pub use convolve::{ConvolveCommit, ConvolveCommitProof};
pub use embed::{EmbedCommitProof, EmbedCommitVerify, VerifyEq};
pub use encode::{strategies, CommitEncode, CommitStrategy};
pub use id::CommitmentId;
pub use sha256::Sha256;

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
/// *optionally pretagged).
pub struct UntaggedProtocol;
impl CommitmentProtocol for UntaggedProtocol {}

/// Helpers for writing test functions working with commit schemes
#[cfg(test)]
pub mod test_helpers {
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
