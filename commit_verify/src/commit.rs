// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use crate::CommitmentProtocol;

/// Error during commitment verification
#[derive(Copy, Clone, Eq, PartialEq, Debug, Display, Error)]
#[display(doc_comments)]
pub enum VerifyError {
    /// commitment doesn't match the message.
    InvalidCommitment,
    /// the message is invalid since a valid commitment to it can't be created.
    InvalidMessage,
}

/// Trait for commit-verify scheme.
pub trait CommitVerify<Msg, Protocol: CommitmentProtocol>
where Self: Eq + Sized
{
    // We use `Protocol` as a generic parameter, and not as an associated type
    // to allow downstream to implement the trait on foreign types.

    /// Creates a commitment to a byte representation of a given message
    fn commit(msg: &Msg) -> Self;

    /// Verifies commitment against the message; default implementation just
    /// repeats the commitment to the message and check it against the `self`.
    #[inline]
    fn verify(&self, msg: &Msg) -> Result<(), VerifyError> {
        match Self::commit(msg) == *self {
            false => Err(VerifyError::InvalidCommitment),
            true => Ok(()),
        }
    }
}

/// Trait for a failable version of commit-verify scheme.
pub trait TryCommitVerify<Msg, Protocol: CommitmentProtocol>
where Self: Eq + Sized
{
    /// Error type that may be reported during [`TryCommitVerify::try_commit`].
    type Error: std::error::Error;

    /// Tries to create commitment to a byte representation of a given message.
    fn try_commit(msg: &Msg) -> Result<Self, Self::Error>;

    /// Verifies the commitment against the message; default implementation
    /// just repeats the commitment to the message and check it against the
    /// `self`.
    #[inline]
    fn verify(&self, msg: &Msg) -> Result<(), VerifyError> {
        let other_commitment = Self::try_commit(msg).map_err(|_| VerifyError::InvalidMessage)?;
        if other_commitment != *self {
            return Err(VerifyError::InvalidCommitment);
        }
        Ok(())
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
                assert!(commitment.verify(msg).is_ok());

                messages.iter().for_each(|m| {
                    // Testing that commitment verification succeeds only
                    // for the original message and fails for the rest
                    assert_eq!(commitment.verify(m).is_ok(), m == msg);
                });

                acc.iter().for_each(|cmt| {
                    // Testing that verification against other commitments
                    // returns `false`
                    assert!(cmt.verify(msg).is_err());
                });

                // Detecting collision
                assert!(acc.insert(commitment));

                acc
            });
    }
}
