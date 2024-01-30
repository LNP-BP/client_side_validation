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

//! Base commit-verify scheme interface.

use amplify::Bytes32;
use sha2::Sha256;
use strict_encoding::{StrictEncode, StrictWriter};

use crate::digest::DigestExt;
use crate::CommitmentProtocol;

/// Trait for commit-verify scheme. A message for the commitment may be any
/// structure that can be represented as a byte array (i.e. implements
/// `AsRef<[u8]>`).
pub trait CommitVerify<Msg, Protocol: CommitmentProtocol>
where
    Self: Eq + Sized,
{
    // We use `Protocol` as a generic parameter, and not as an associated type
    // to allow downstream to implement the trait on foreign types.

    /// Creates a commitment to a byte representation of a given message
    fn commit(msg: &Msg) -> Self;

    /// Verifies commitment against the message; default implementation just
    /// repeats the commitment to the message and check it against the `self`.
    #[inline]
    fn verify(&self, msg: &Msg) -> bool {
        Self::commit(msg) == *self
    }
}

/// Trait for a failable version of commit-verify scheme. A message for the
/// commitment may be any structure that can be represented as a byte array
/// (i.e. implements `AsRef<[u8]>`).
pub trait TryCommitVerify<Msg, Protocol: CommitmentProtocol>
where
    Self: Eq + Sized,
{
    /// Error type that may be reported during [`TryCommitVerify::try_commit`]
    /// and [`TryCommitVerify::try_verify`] procedures
    type Error: std::error::Error;

    /// Tries to create commitment to a byte representation of a given message
    fn try_commit(msg: &Msg) -> Result<Self, Self::Error>;

    /// Tries to verify commitment against the message; default implementation
    /// just repeats the commitment to the message and check it against the
    /// `self`.
    #[inline]
    fn try_verify(&self, msg: &Msg) -> Result<bool, Self::Error> {
        Ok(Self::try_commit(msg)? == *self)
    }
}
/// Static entropy version of TryCommitVerify
pub trait TryCommitVerifyStatic<Msg, Protocol: CommitmentProtocol>
where
    Self: Eq + Sized,
{
    /// Error type that may be reported during [`TryCommitVerifyStatic::try_commit`]
    /// and [`TryCommitVerifyStatic::try_verify`] procedures
    type Error: std::error::Error;

    /// Static entropy vesion of [`TryCommitVerify::try_commit`]
    fn try_commit_static(msg: &Msg) -> Result<Self, Self::Error>;

    /// Static entropy vesion of [`TryCommitVerify::try_verify`]
    fn try_verify_static(&self, msg: &Msg) -> Result<bool, Self::Error> {
        Ok(Self::try_commit_static(msg)? == *self)
    }
}

/// Commitment protocol which writes strict-encoded data into a hasher.
pub struct StrictEncodedProtocol;

impl CommitmentProtocol for StrictEncodedProtocol {}

impl<T> CommitVerify<T, StrictEncodedProtocol> for Bytes32
where
    T: StrictEncode,
{
    fn commit(msg: &T) -> Self {
        let mut engine = Sha256::from_tag(*b"urn:lnpbp:lnpbp0007:strict:v01#A");
        let w = StrictWriter::with(u32::MAX as usize, &mut engine);
        msg.strict_encode(w).ok();
        engine.finish().into()
    }
}

/// Helpers for writing test functions working with commit-verify scheme
#[cfg(test)]
pub(crate) mod test_helpers {
    use core::fmt::Debug;
    use core::hash::Hash;
    use std::collections::HashSet;

    use super::*;
    use crate::UntaggedProtocol;

    /// Runs round-trip of commitment and verification for a given set of
    /// messages
    pub fn commit_verify_suite<Msg, Cmt>(messages: Vec<Msg>)
    where
        Msg: AsRef<[u8]> + Eq,
        Cmt: CommitVerify<Msg, UntaggedProtocol> + Eq + Hash + Debug,
    {
        messages
            .iter()
            .fold(HashSet::<Cmt>::with_capacity(messages.len()), |mut acc, msg| {
                let commitment = Cmt::commit(msg);

                // Commitments MUST be deterministic: each message should
                // produce unique commitment
                (1..10).for_each(|_| {
                    assert_eq!(Cmt::commit(msg), commitment);
                });

                // Testing verification
                assert!(commitment.verify(msg));

                messages.iter().for_each(|m| {
                    // Testing that commitment verification succeeds only
                    // for the original message and fails for the rest
                    assert_eq!(commitment.verify(m), m == msg);
                });

                acc.iter().for_each(|cmt| {
                    // Testing that verification against other commitments
                    // returns `false`
                    assert!(!cmt.verify(msg));
                });

                // Detecting collision
                assert!(acc.insert(commitment));

                acc
            });
    }
}

#[cfg(test)]
mod test {
    use core::fmt::Debug;
    use core::hash::Hash;

    use amplify::confinement::SmallVec;
    use sha2::Digest;

    use super::test_helpers::*;
    use super::*;
    use crate::test_helpers::gen_messages;
    use crate::UntaggedProtocol;

    #[derive(Debug, Display, Error)]
    #[display(Debug)]
    struct Error;

    #[derive(Clone, PartialEq, Eq, Debug, Hash)]
    struct DummyHashCommitment([u8; 32]);
    impl<T> CommitVerify<T, UntaggedProtocol> for DummyHashCommitment
    where
        T: AsRef<[u8]>,
    {
        fn commit(msg: &T) -> Self {
            Self(Sha256::digest(msg.as_ref()).into())
        }
    }

    #[test]
    fn test_commit_verify() {
        commit_verify_suite::<SmallVec<u8>, DummyHashCommitment>(gen_messages());
    }
}
