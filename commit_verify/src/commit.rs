// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
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

//! Base commit-verify scheme interface.

use bitcoin_hashes::{hash160, ripemd160, sha1, sha256, sha256d, sha512, siphash24, Hash};

use crate::{CommitmentProtocol, UntaggedProtocol};

/// Trait for commit-verify scheme. A message for the commitment may be any
/// structure that can be represented as a byte array (i.e. implements
/// `AsRef<[u8]>`).
pub trait CommitVerify<Msg>
where Self: Eq + Sized
{
    type Protocol: CommitmentProtocol;

    /// Creates a commitment to a byte representation of a given message
    fn commit(msg: &Msg) -> Self;

    /// Verifies commitment against the message; default implementation just
    /// repeats the commitment to the message and check it against the `self`.
    #[inline]
    fn verify(&self, msg: &Msg) -> bool { Self::commit(msg) == *self }
}

/// Trait for a failable version of commit-verify scheme. A message for the
/// commitment may be any structure that can be represented as a byte array
/// (i.e. implements `AsRef<[u8]>`).
pub trait TryCommitVerify<Msg>
where Self: Eq + Sized
{
    type Protocol: CommitmentProtocol;

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

impl<Msg> CommitVerify<Msg> for sha1::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;
    #[inline]
    fn commit(msg: &Msg) -> sha1::Hash { sha1::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for ripemd160::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> ripemd160::Hash { ripemd160::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for hash160::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> hash160::Hash { hash160::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for sha256::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> sha256::Hash { sha256::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for sha256d::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> sha256d::Hash { sha256d::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for siphash24::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> siphash24::Hash { siphash24::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for sha512::Hash
where Msg: AsRef<[u8]>
{
    type Protocol = UntaggedProtocol;

    #[inline]
    fn commit(msg: &Msg) -> sha512::Hash { sha512::Hash::hash(msg.as_ref()) }
}

/// Helpers for writing test functions working with commit-verify scheme
#[cfg(test)]
pub(crate) mod test_helpers {
    use core::fmt::Debug;
    use core::hash::Hash;
    use std::collections::HashSet;

    use bitcoin_hashes::hex::FromHex;

    use super::*;

    /// Runs round-trip of commitment and verification for a given set of
    /// messages
    pub fn commit_verify_suite<Msg, Cmt>(messages: Vec<Msg>)
    where
        Msg: AsRef<[u8]> + Eq,
        Cmt: CommitVerify<Msg> + Eq + Hash + Debug,
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

    use bitcoin_hashes::*;

    use super::test_helpers::*;
    use super::*;
    use crate::test_helpers::gen_messages;

    #[derive(Debug, Display, Error)]
    #[display(Debug)]
    struct Error;

    #[derive(Clone, PartialEq, Eq, Debug, Hash)]
    struct DummyHashCommitment(sha256d::Hash);
    impl<T> CommitVerify<T> for DummyHashCommitment
    where T: AsRef<[u8]>
    {
        type Protocol = UntaggedProtocol;

        fn commit(msg: &T) -> Self { Self(bitcoin_hashes::Hash::hash(msg.as_ref())) }
    }

    #[test]
    fn test_commit_verify() { commit_verify_suite::<Vec<u8>, DummyHashCommitment>(gen_messages()); }

    #[test]
    fn test_sha256_commitment() { commit_verify_suite::<Vec<u8>, sha256::Hash>(gen_messages()); }

    #[test]
    fn test_sha256d_commitment() { commit_verify_suite::<Vec<u8>, sha256d::Hash>(gen_messages()); }

    #[test]
    fn test_ripemd160_commitment() {
        commit_verify_suite::<Vec<u8>, ripemd160::Hash>(gen_messages());
    }

    #[test]
    fn test_hash160_commitment() { commit_verify_suite::<Vec<u8>, hash160::Hash>(gen_messages()); }

    #[test]
    fn test_sha1_commitment() { commit_verify_suite::<Vec<u8>, sha1::Hash>(gen_messages()); }

    #[test]
    fn test_sha512_commitment() { commit_verify_suite::<Vec<u8>, sha512::Hash>(gen_messages()); }

    #[test]
    fn test_siphash24_commitment() {
        commit_verify_suite::<Vec<u8>, siphash24::Hash>(gen_messages());
    }
}
