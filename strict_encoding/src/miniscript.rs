// LNP/BP client-side-validation library implementing respective LNPBP
// specifications & standards (LNPBP-7, 8, 9, 42)
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

use std::io;

use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use miniscript::descriptor::{
    Bare, DescriptorSinglePub, Pkh, Sh, ShInner, Wpkh, Wsh, WshInner,
};
use miniscript::policy::concrete::Policy;
use miniscript::{policy, Descriptor, Miniscript, MiniscriptKey, Terminal};

use crate::{Error, StrictDecode, StrictEncode};

impl StrictEncode for DescriptorSinglePub {
    #[inline]
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.key, self.origin))
    }
}

impl StrictDecode for DescriptorSinglePub {
    #[inline]
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; key, origin; crate))
    }
}

const MS_FALSE: u8 = 0;
const MS_TRUE: u8 = 1;

const MS_KEY: u8 = 0x02;
const MS_KEY_HASH: u8 = 0x03;
const MS_THRESH: u8 = 0x20;
const MS_MULTI: u8 = 0x21;

const MS_AFTER: u8 = 0x09;
const MS_OLDER: u8 = 0x08;
const MS_SHA256: u8 = 0x04;
const MS_HASH256: u8 = 0x05;
const MS_RIPEMD160: u8 = 0x06;
const MS_HASH160: u8 = 0x07;

const MS_AND_V: u8 = 0x22;
const MS_AND_B: u8 = 0x23;
const MS_AND_OR: u8 = 0x24;
const MS_OR_B: u8 = 0x28;
const MS_OR_D: u8 = 0x29;
const MS_OR_C: u8 = 0x2a;
const MS_OR_I: u8 = 0x2b;

const MS_ALT: u8 = 0x10;
const MS_SWAP: u8 = 0x11;
const MS_CHECK: u8 = 0x12;
const MS_DUP_IF: u8 = 0x13;
const MS_VERIFY: u8 = 0x18;
const MS_NON_ZERO: u8 = 0x19;
const MS_ZERO_NE: u8 = 0x1a;

impl<Pk> StrictEncode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Policy::Unsatisfiable => MS_FALSE.strict_encode(e)?,
            Policy::Trivial => MS_TRUE.strict_encode(e)?,
            Policy::Key(pk) => strict_encode_list!(e; MS_KEY, pk),
            Policy::After(tl) => strict_encode_list!(e; MS_AFTER, tl),
            Policy::Older(tl) => strict_encode_list!(e; MS_OLDER, tl),
            Policy::Sha256(hash) => strict_encode_list!(e; MS_SHA256, hash),
            Policy::Hash256(hash) => strict_encode_list!(e; MS_HASH256, hash),
            Policy::Ripemd160(hash) => {
                strict_encode_list!(e; MS_RIPEMD160, hash)
            }
            Policy::Hash160(hash) => strict_encode_list!(e; MS_HASH160, hash),
            Policy::And(ast) => strict_encode_list!(e; MS_AND_B, ast),
            Policy::Or(ast) => strict_encode_list!(e; MS_OR_B, ast),
            Policy::Threshold(thresh, ast) => {
                strict_encode_list!(e; MS_THRESH, thresh, ast)
            }
        })
    }
}

impl<Pk> StrictDecode for policy::Concrete<Pk>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let byte = u8::strict_decode(&mut d)?;
        Ok(match byte {
            MS_TRUE => Policy::Trivial,
            MS_FALSE => Policy::Unsatisfiable,
            MS_KEY => Policy::Key(Pk::strict_decode(&mut d)?),
            MS_AFTER => Policy::After(u32::strict_decode(&mut d)?),
            MS_OLDER => Policy::Older(u32::strict_decode(&mut d)?),
            MS_SHA256 => Policy::Sha256(sha256::Hash::strict_decode(&mut d)?),
            MS_HASH256 => {
                Policy::Hash256(sha256d::Hash::strict_decode(&mut d)?)
            }
            MS_RIPEMD160 => {
                Policy::Ripemd160(ripemd160::Hash::strict_decode(&mut d)?)
            }
            MS_HASH160 => {
                Policy::Hash160(hash160::Hash::strict_decode(&mut d)?)
            }
            MS_AND_B => Policy::And(Vec::strict_decode(&mut d)?),
            MS_OR_B => Policy::Or(Vec::strict_decode(&mut d)?),
            MS_THRESH => Policy::Threshold(
                usize::strict_decode(&mut d)?,
                Vec::strict_decode(&mut d)?,
            ),

            MS_KEY_HASH | MS_ALT | MS_SWAP | MS_CHECK | MS_DUP_IF
            | MS_VERIFY | MS_NON_ZERO | MS_ZERO_NE | MS_AND_V | MS_AND_OR
            | MS_OR_D | MS_OR_C | MS_OR_I | MS_MULTI => {
                return Err(Error::DataIntegrityError(format!(
                    "byte {:#04X} is a valid miniscript instruction, but does  \
                     not belong to a set of concrete policy instructions. Try \
                     to decode data using different miniscript type", 
                    byte
                )))
            }

            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "byte {:#04X} does not correspond to any of miniscript \
                     concrete policy instructions",
                    wrong
                )))
            }
        })
    }
}

impl<Pk, Ctx> StrictEncode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey,
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
    Ctx: miniscript::ScriptContext,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match &self.node {
            Terminal::False => MS_FALSE.strict_encode(e)?,
            Terminal::True => MS_TRUE.strict_encode(e)?,
            Terminal::PkK(pk) => strict_encode_list!(e; MS_KEY, pk),
            Terminal::PkH(hash) => strict_encode_list!(e; MS_KEY_HASH, hash),
            Terminal::After(tl) => strict_encode_list!(e; MS_AFTER, tl),
            Terminal::Older(tl) => strict_encode_list!(e; MS_OLDER, tl),
            Terminal::Sha256(hash) => strict_encode_list!(e; MS_SHA256, hash),
            Terminal::Hash256(hash) => strict_encode_list!(e; MS_HASH256, hash),
            Terminal::Ripemd160(hash) => {
                strict_encode_list!(e; MS_RIPEMD160, hash)
            }
            Terminal::Hash160(hash) => strict_encode_list!(e; MS_HASH160, hash),

            Terminal::Alt(ms) => strict_encode_list!(e; MS_ALT, ms),
            Terminal::Swap(ms) => strict_encode_list!(e; MS_SWAP, ms),
            Terminal::Check(ms) => strict_encode_list!(e; MS_CHECK, ms),
            Terminal::DupIf(ms) => strict_encode_list!(e; MS_DUP_IF, ms),
            Terminal::Verify(ms) => strict_encode_list!(e; MS_VERIFY, ms),
            Terminal::NonZero(ms) => strict_encode_list!(e; MS_NON_ZERO, ms),
            Terminal::ZeroNotEqual(ms) => {
                strict_encode_list!(e; MS_ZERO_NE, ms)
            }

            Terminal::AndV(ms1, ms2) => {
                strict_encode_list!(e; MS_AND_V, ms1, ms2)
            }
            Terminal::AndB(ms1, ms2) => {
                strict_encode_list!(e; MS_AND_B, ms1, ms2)
            }
            Terminal::AndOr(ms1, ms2, ms3) => {
                strict_encode_list!(e; MS_AND_OR, ms1, ms2, ms3)
            }
            Terminal::OrB(ms1, ms2) => {
                strict_encode_list!(e; MS_OR_B, ms1, ms2)
            }
            Terminal::OrD(ms1, ms2) => {
                strict_encode_list!(e; MS_OR_D, ms1, ms2)
            }
            Terminal::OrC(ms1, ms2) => {
                strict_encode_list!(e; MS_OR_C, ms1, ms2)
            }
            Terminal::OrI(ms1, ms2) => {
                strict_encode_list!(e; MS_OR_I, ms1, ms2)
            }
            Terminal::Multi(thresh, vec) => {
                strict_encode_list!(e; MS_MULTI, thresh, vec)
            }
            Terminal::Thresh(thresh, vec) => {
                strict_encode_list!(e; MS_THRESH, thresh, vec)
            }
        })
    }
}

impl<Pk, Ctx> StrictDecode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
    Ctx: miniscript::ScriptContext,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let term = match u8::strict_decode(&mut d)? {
            MS_TRUE => Terminal::True,
            MS_FALSE => Terminal::False,
            MS_KEY => Terminal::PkK(Pk::strict_decode(&mut d)?),
            MS_KEY_HASH => Terminal::PkH(Pk::Hash::strict_decode(&mut d)?),

            MS_AFTER => Terminal::After(u32::strict_decode(&mut d)?),
            MS_OLDER => Terminal::Older(u32::strict_decode(&mut d)?),
            MS_SHA256 => Terminal::Sha256(sha256::Hash::strict_decode(&mut d)?),
            MS_HASH256 => {
                Terminal::Hash256(sha256d::Hash::strict_decode(&mut d)?)
            }
            MS_RIPEMD160 => {
                Terminal::Ripemd160(ripemd160::Hash::strict_decode(&mut d)?)
            }
            MS_HASH160 => {
                Terminal::Hash160(hash160::Hash::strict_decode(&mut d)?)
            }

            MS_ALT => Terminal::Alt(StrictDecode::strict_decode(&mut d)?),
            MS_SWAP => Terminal::Swap(StrictDecode::strict_decode(&mut d)?),
            MS_CHECK => Terminal::Check(StrictDecode::strict_decode(&mut d)?),
            MS_DUP_IF => Terminal::DupIf(StrictDecode::strict_decode(&mut d)?),
            MS_VERIFY => Terminal::Verify(StrictDecode::strict_decode(&mut d)?),
            MS_NON_ZERO => {
                Terminal::NonZero(StrictDecode::strict_decode(&mut d)?)
            }
            MS_ZERO_NE => {
                Terminal::ZeroNotEqual(StrictDecode::strict_decode(&mut d)?)
            }

            MS_AND_V => Terminal::AndV(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_AND_B => Terminal::AndB(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_AND_OR => Terminal::AndOr(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_OR_B => Terminal::OrB(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_OR_D => Terminal::OrD(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_OR_C => Terminal::OrC(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_OR_I => Terminal::OrI(
                StrictDecode::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_MULTI => Terminal::Multi(
                usize::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),
            MS_THRESH => Terminal::Thresh(
                usize::strict_decode(&mut d)?,
                StrictDecode::strict_decode(&mut d)?,
            ),

            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "byte {:#04X} does not correspond to any of miniscript instructions",
                    wrong
                )))
            }
        };
        Miniscript::from_ast(term).map_err(|err| {
            Error::DataIntegrityError(format!(
                "miniscript does not pass check: {}",
                err
            ))
        })
    }
}

const DESCRIPTOR_BARE: u8 = 0x00;
const DESCRIPTOR_PKH: u8 = 0x01;
const DESCRIPTOR_SH: u8 = 0x02;
const DESCRIPTOR_SH_SORTED_MULTI: u8 = 0x03;
const DESCRIPTOR_SH_WPKH: u8 = 0x08;
const DESCRIPTOR_SH_WSH: u8 = 0x09;
const DESCRIPTOR_SH_WSH_SORTED_MULTI: u8 = 0x0a;
const DESCRIPTOR_WPKH: u8 = 0x10;
const DESCRIPTOR_WSH: u8 = 0x11;
const DESCRIPTOR_WSH_SORTED_MULTI: u8 = 0x12;
// Taproot: 0x2_

impl<Pk> StrictEncode for Descriptor<Pk>
where
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Descriptor::Bare(bare) => {
                strict_encode_list!(e; DESCRIPTOR_BARE, bare.as_inner())
            }
            Descriptor::Pkh(pkh) => {
                strict_encode_list!(e; DESCRIPTOR_PKH, pkh.as_inner())
            }
            Descriptor::Wpkh(wpkh) => {
                strict_encode_list!(e; DESCRIPTOR_WPKH, wpkh.as_inner())
            }
            Descriptor::Sh(sh) => match sh.as_inner() {
                ShInner::Wsh(wsh) => match wsh.as_inner() {
                    WshInner::SortedMulti(multi) => {
                        strict_encode_list!(e; DESCRIPTOR_SH_WSH_SORTED_MULTI, multi.k, multi.pks)
                    }
                    WshInner::Ms(ms) => {
                        strict_encode_list!(e; DESCRIPTOR_SH_WSH, ms)
                    }
                },
                ShInner::Wpkh(wpkh) => {
                    strict_encode_list!(e; DESCRIPTOR_SH_WPKH, wpkh.as_inner())
                }
                ShInner::SortedMulti(multi) => {
                    strict_encode_list!(e; DESCRIPTOR_SH_SORTED_MULTI, multi.k, multi.pks)
                }
                ShInner::Ms(ms) => strict_encode_list!(e; DESCRIPTOR_SH, ms),
            },
            Descriptor::Wsh(wsh) => match wsh.as_inner() {
                WshInner::SortedMulti(multi) => {
                    strict_encode_list!(e; DESCRIPTOR_WSH_SORTED_MULTI, multi.k, multi.pks)
                }
                WshInner::Ms(ms) => strict_encode_list!(e; DESCRIPTOR_WSH, ms),
            },
        })
    }
}

impl<Pk> StrictDecode for Descriptor<Pk>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        impl From<miniscript::Error> for Error {
            fn from(err: miniscript::Error) -> Self {
                Error::DataIntegrityError(format!(": {}", err))
            }
        }

        Ok(match u8::strict_decode(&mut d)? {
            DESCRIPTOR_BARE => {
                Descriptor::Bare(Bare::new(Miniscript::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_PKH => {
                Descriptor::Pkh(Pkh::new(Pk::strict_decode(&mut d)?))
            }
            DESCRIPTOR_SH => {
                Descriptor::Sh(Sh::new(Miniscript::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_SH_SORTED_MULTI => Descriptor::Sh(Sh::new_sortedmulti(
                usize::strict_decode(&mut d)?,
                Vec::strict_decode(&mut d)?,
            )?),
            DESCRIPTOR_SH_WPKH => {
                Descriptor::Sh(Sh::new_wpkh(Pk::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_SH_WSH => {
                Descriptor::Sh(Sh::new_wsh(Miniscript::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_SH_WSH_SORTED_MULTI => {
                Descriptor::Sh(Sh::new_wsh_sortedmulti(
                    usize::strict_decode(&mut d)?,
                    Vec::strict_decode(&mut d)?,
                )?)
            }
            DESCRIPTOR_WPKH => {
                Descriptor::Wpkh(Wpkh::new(Pk::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_WSH => {
                Descriptor::Wsh(Wsh::new(Miniscript::strict_decode(&mut d)?)?)
            }
            DESCRIPTOR_WSH_SORTED_MULTI => {
                Descriptor::Wsh(Wsh::new_sortedmulti(
                    usize::strict_decode(&mut d)?,
                    Vec::strict_decode(&mut d)?,
                )?)
            }
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "unknown miniscript descriptor type: #{:#04X}",
                    wrong
                )))
            }
        })
    }
}
