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

use bitcoin_hashes::{
    hash160, ripemd160, sha1, sha256, sha256d, sha256t, sha512, siphash24, Hash,
};

use crate::CommitVerify;

impl<Msg> CommitVerify<Msg> for sha1::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> sha1::Hash { sha1::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for ripemd160::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> ripemd160::Hash {
        ripemd160::Hash::hash(msg.as_ref())
    }
}

impl<Msg> CommitVerify<Msg> for hash160::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> hash160::Hash { hash160::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for sha256::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> sha256::Hash { sha256::Hash::hash(msg.as_ref()) }
}

impl<Msg> CommitVerify<Msg> for sha256d::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> sha256d::Hash { sha256d::Hash::hash(msg.as_ref()) }
}

impl<Msg, T> CommitVerify<Msg> for sha256t::Hash<T>
where
    Msg: AsRef<[u8]>,
    T: sha256t::Tag,
{
    #[inline]
    fn commit(msg: &Msg) -> sha256t::Hash<T> {
        sha256t::Hash::hash(msg.as_ref())
    }
}

impl<Msg> CommitVerify<Msg> for siphash24::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> siphash24::Hash {
        siphash24::Hash::hash(msg.as_ref())
    }
}

impl<Msg> CommitVerify<Msg> for sha512::Hash
where
    Msg: AsRef<[u8]>,
{
    #[inline]
    fn commit(msg: &Msg) -> sha512::Hash { sha512::Hash::hash(msg.as_ref()) }
}

#[cfg(test)]
mod test {
    use bitcoin_hashes::*;

    use crate::api::test_helpers::*;

    #[test]
    fn test_sha256_commitment() {
        commit_verify_suite::<Vec<u8>, sha256::Hash>(gen_messages());
    }

    #[test]
    fn test_sha256d_commitment() {
        commit_verify_suite::<Vec<u8>, sha256d::Hash>(gen_messages());
    }

    #[test]
    fn test_ripemd160_commitment() {
        commit_verify_suite::<Vec<u8>, ripemd160::Hash>(gen_messages());
    }

    #[test]
    fn test_hash160_commitment() {
        commit_verify_suite::<Vec<u8>, hash160::Hash>(gen_messages());
    }

    #[test]
    fn test_sha1_commitment() {
        commit_verify_suite::<Vec<u8>, sha1::Hash>(gen_messages());
    }

    #[test]
    fn test_sha512_commitment() {
        commit_verify_suite::<Vec<u8>, sha512::Hash>(gen_messages());
    }

    #[test]
    fn test_siphash24_commitment() {
        commit_verify_suite::<Vec<u8>, siphash24::Hash>(gen_messages());
    }
}
