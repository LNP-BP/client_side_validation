// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

use bitcoin_hashes::{
    hash160, hmac, ripemd160, sha256, sha256d, sha256t, sha512, Hash,
};

use crate::{strategies, Strategy};

impl Strategy for sha256::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for sha256d::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl<T> Strategy for sha256t::Hash<T>
where
    T: sha256t::Tag,
{
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for sha512::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for ripemd160::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl Strategy for hash160::Hash {
    type Strategy = strategies::HashFixedBytes;
}
impl<T> Strategy for hmac::Hmac<T>
where
    T: Hash,
{
    type Strategy = strategies::HashFixedBytes;
}
