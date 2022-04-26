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

use std::io;
use std::io::{Read, Write};
use std::sync::Arc;

use bitcoin::consensus::ReadExt;
use bitcoin::hashes::{hash160, ripemd160, sha256, sha256d};
use bitcoin::XOnlyPublicKey;
use miniscript::descriptor::{
    self, Descriptor, DescriptorPublicKey, DescriptorSinglePub, DescriptorXKey,
    InnerXKey, SinglePubKey, TapTree, Wildcard,
};
use miniscript::policy::concrete::Policy;
use miniscript::{
    BareCtx, Legacy, Miniscript, MiniscriptKey, ScriptContext, Segwitv0, Tap,
    Terminal,
};

use crate::{Error, StrictDecode, StrictEncode};

/// Maximum level of nested miniscript and miniscript concrete policy levels
/// supported by strict encoding process.
///
/// This is required in order to prevent attacks in client-side-validated data
/// when limitations on the maximum number of items is bypassed due to the
/// nested nature of miniscript AST. While this may is controlled by miniscript
/// implementation and bitcoin consensus script length rules, this control does
/// not takes place during deserialization (plus miniscript may be used outside
/// of bitcoin transactions), and thus we need this redundant control.
pub const MINISCRIPT_DEPTH_LIMIT: u8 = 64;

const MS_FALSE: u8 = 0;
const MS_TRUE: u8 = 1;

const MS_KEY: u8 = 0x02;
const MS_KEY_HASH: u8 = 0x03;
const MS_THRESH: u8 = 0x20;
const MS_MULTI: u8 = 0x21;
const MS_MULTI_A: u8 = 0x2c;

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

/// We need this because of rust compiler limitations.
///
/// The macros below were introduced because rust compiler dies on recursion
/// overflow each time when a generic type calls itself in a recursive mode
/// passing one of its arguments by a mutable reference to itself. Thus, we had
/// to split the implementation logic in such a way that we do not pass a
/// mutable reference to a variable, and just re-use the reference instead. This
/// contradicts rust API guidelines, but in fact it is a rust compiler who
/// contradicts them, we just do not have other choice.
macro_rules! strict_encode_tuple {
    ($encoder:ident; $tag:ident, $item:ident) => {{
        $encoder.write_all(&[$tag])?;
        1 + $item.strict_encode($encoder)?
    }};
}

macro_rules! strict_encode_usize {
    ( $encoder:ident; $int:expr ) => { {
        let count = $int; // Evaluating expression to reduce number of function calls
        if count > u16::MAX as usize {
            return Err(Error::ExceedMaxItems(count));
        }
        $encoder.write_all(&(count as u16).to_le_bytes())?;
        2 // We know that we write exactly two bytes
    } };
}

impl From<miniscript::Error> for Error {
    fn from(err: miniscript::Error) -> Self {
        Error::DataIntegrityError(format!(": {}", err))
    }
}

impl StrictEncode for BareCtx {
    #[inline]
    fn strict_encode<E: Write>(&self, _: E) -> Result<usize, Error> { Ok(0) }
}

impl StrictDecode for BareCtx {
    fn strict_decode<D: Read>(_: D) -> Result<Self, Error> {
        unreachable!("attempt to construct miniscript context object")
    }
}

impl StrictEncode for Legacy {
    #[inline]
    fn strict_encode<E: Write>(&self, _: E) -> Result<usize, Error> { Ok(0) }
}

impl StrictDecode for Legacy {
    fn strict_decode<D: Read>(_: D) -> Result<Self, Error> {
        unreachable!("attempt to construct miniscript context object")
    }
}

impl StrictEncode for Segwitv0 {
    #[inline]
    fn strict_encode<E: Write>(&self, _: E) -> Result<usize, Error> { Ok(0) }
}

impl StrictDecode for Segwitv0 {
    fn strict_decode<D: Read>(_: D) -> Result<Self, Error> {
        unreachable!("attempt to construct miniscript context object")
    }
}

impl StrictEncode for Tap {
    #[inline]
    fn strict_encode<E: Write>(&self, _: E) -> Result<usize, Error> { Ok(0) }
}

impl StrictDecode for Tap {
    fn strict_decode<D: Read>(_: D) -> Result<Self, Error> {
        unreachable!("attempt to construct miniscript context object")
    }
}

impl<Pk> StrictEncode for TapTree<Pk>
where
    Pk: MiniscriptKey + StrictEncode,
    Pk::Hash: StrictEncode,
{
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            TapTree::Tree(tree1, tree2) => {
                let mut len = 2u8.strict_encode(&mut e)?;
                len += tree1.strict_serialize()?.strict_encode(&mut e)?;
                len += tree2.strict_serialize()?.strict_encode(&mut e)?;
                len
            }
            TapTree::Leaf(pk) => {
                strict_encode_list!(e; 1u8, pk)
            }
        })
    }
}

impl<Pk> StrictDecode for TapTree<Pk>
where
    Pk: MiniscriptKey + StrictDecode,
    Pk::Hash: StrictDecode,
{
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        match u8::strict_decode(&mut d)? {
            1u8 => Ok(TapTree::Leaf(StrictDecode::strict_decode(&mut d)?)),
            2u8 => {
                let vec1 = Vec::<u8>::strict_decode(&mut d)?;
                let vec2 = Vec::<u8>::strict_decode(&mut d)?;
                Ok(TapTree::Tree(
                    Arc::new(TapTree::strict_deserialize(&vec1)?),
                    Arc::new(TapTree::strict_deserialize(&vec2)?),
                ))
            }
            wrong => Err(Error::EnumValueNotKnown("TapTree", wrong as usize)),
        }
    }
}

impl<Pk> StrictEncode for Policy<Pk>
where
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        // We need this because of the need to control maximum number of nested
        // miniscript code
        fn encode_policy_inner<Pk>(
            policy: &Policy<Pk>,
            e: &mut impl io::Write,
            mut depth: u8,
        ) -> Result<usize, Error>
        where
            Pk: MiniscriptKey + StrictEncode,
            <Pk as MiniscriptKey>::Hash: StrictEncode,
        {
            if depth > MINISCRIPT_DEPTH_LIMIT {
                return Err(Error::ExceedMaxItems(
                    MINISCRIPT_DEPTH_LIMIT as usize,
                ));
            }
            depth += 1;

            Ok(match policy {
                Policy::Unsatisfiable => MS_FALSE.strict_encode(e)?,
                Policy::Trivial => MS_TRUE.strict_encode(e)?,
                Policy::Key(pk) => strict_encode_tuple!(e; MS_KEY, pk),
                Policy::After(tl) => strict_encode_tuple!(e; MS_AFTER, tl),
                Policy::Older(tl) => strict_encode_tuple!(e; MS_OLDER, tl),
                Policy::Sha256(hash) => {
                    strict_encode_tuple!(e; MS_SHA256, hash)
                }
                Policy::Hash256(hash) => {
                    strict_encode_tuple!(e; MS_HASH256, hash)
                }
                Policy::Ripemd160(hash) => {
                    strict_encode_tuple!(e; MS_RIPEMD160, hash)
                }
                Policy::Hash160(hash) => {
                    strict_encode_tuple!(e; MS_HASH160, hash)
                }
                Policy::And(vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_AND_B])?;
                    len += strict_encode_usize!(e; vec.len());
                    for p in vec {
                        len += encode_policy_inner(p, e, depth)?;
                    }
                    len
                }
                Policy::Or(vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_OR_B])?;
                    len += strict_encode_usize!(e; vec.len());
                    for (x, p) in vec {
                        len += strict_encode_usize!(e; *x);
                        len += encode_policy_inner(p, e, depth)?;
                    }
                    len
                }
                Policy::Threshold(thresh, vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_THRESH])?;
                    len += strict_encode_usize!(e; *thresh);
                    len += strict_encode_usize!(e; vec.len());
                    for p in vec {
                        len += encode_policy_inner(p, e, depth)?;
                    }
                    len
                }
            })
        }

        encode_policy_inner(self, &mut e, 1)
    }
}

impl<Pk> StrictDecode for Policy<Pk>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        // We need this first because of the need to control maximum number of
        // nested miniscript code, and than because of the rust compiler
        // limitations in working with recursive generic functions
        fn decode_policy_inner<Pk>(
            d: &mut impl io::Read,
            mut depth: u8,
        ) -> Result<Policy<Pk>, Error>
        where
            Pk: MiniscriptKey + StrictDecode,
            <Pk as MiniscriptKey>::Hash: StrictDecode,
        {
            if depth > MINISCRIPT_DEPTH_LIMIT {
                return Err(Error::ExceedMaxItems(
                    MINISCRIPT_DEPTH_LIMIT as usize,
                ));
            }
            depth += 1;

            let byte = d.read_u8()?;
            Ok(match byte {
                MS_TRUE => Policy::Trivial,
                MS_FALSE => Policy::Unsatisfiable,
                MS_KEY => Policy::Key(Pk::strict_decode(d)?),
                MS_AFTER => Policy::After(u32::strict_decode(d)?),
                MS_OLDER => Policy::Older(u32::strict_decode(d)?),
                MS_SHA256 => Policy::Sha256(sha256::Hash::strict_decode(d)?),
                MS_HASH256 => Policy::Hash256(sha256d::Hash::strict_decode(d)?),
                MS_RIPEMD160 => {
                    Policy::Ripemd160(ripemd160::Hash::strict_decode(d)?)
                }
                MS_HASH160 => Policy::Hash160(hash160::Hash::strict_decode(d)?),
                MS_AND_B => {
                    let len = d.read_u16()?;
                    let mut vec = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        vec.push(decode_policy_inner(d, depth)?);
                    }
                    Policy::And(vec)
                }
                MS_OR_B => {
                    let len = d.read_u16()?;
                    let mut vec = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        vec.push((
                            d.read_u16()? as usize,
                            decode_policy_inner(d, depth)?,
                        ));
                    }
                    Policy::Or(vec)
                }
                MS_THRESH => {
                    let thresh = d.read_u16()? as usize;
                    let len = d.read_u16()?;
                    let mut vec = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        vec.push(decode_policy_inner(d, depth)?);
                    }
                    Policy::Threshold(thresh, vec)
                }

                MS_KEY_HASH | MS_ALT | MS_SWAP | MS_CHECK | MS_DUP_IF
                | MS_VERIFY | MS_NON_ZERO | MS_ZERO_NE | MS_AND_V
                | MS_AND_OR | MS_OR_D | MS_OR_C | MS_OR_I | MS_MULTI => {
                    return Err(Error::DataIntegrityError(format!(
                        "byte {:#04X} is a valid miniscript instruction, but \
                         does  not belong to a set of concrete policy \
                         instructions. Try to decode data using different \
                         miniscript type",
                        byte
                    )))
                }

                wrong => {
                    return Err(Error::DataIntegrityError(format!(
                        "byte {:#04X} does not correspond to any of \
                         miniscript concrete policy instructions",
                        wrong
                    )))
                }
            })
        }

        decode_policy_inner(&mut d, 1)
    }
}

impl<Pk, Ctx> StrictEncode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
    Ctx: miniscript::ScriptContext,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        // We need this macro and inner function because of the need to control
        // maximum number of nested miniscript code, and because of the rust
        // compiler limitations in working with recursive generic functions

        macro_rules! strict_encode_ms {
            ($encoder:ident; $tag:ident, $depth:expr, $($ms:expr),+) => { {
                let mut len = 1usize;
                $encoder.write_all(&[$tag])?;
                $( len += encode_miniscript_inner($ms, $encoder, $depth)?; )+
                len
            } };
        }

        fn encode_miniscript_inner<Pk, Ctx>(
            ms: &Miniscript<Pk, Ctx>,
            mut e: &mut impl io::Write,
            mut depth: u8,
        ) -> Result<usize, Error>
        where
            Pk: MiniscriptKey + StrictEncode,
            <Pk as MiniscriptKey>::Hash: StrictEncode,
            Ctx: miniscript::ScriptContext,
        {
            if depth > MINISCRIPT_DEPTH_LIMIT {
                return Err(Error::ExceedMaxItems(
                    MINISCRIPT_DEPTH_LIMIT as usize,
                ));
            }
            depth += 1;

            Ok(match &ms.node {
                Terminal::False => MS_FALSE.strict_encode(e)?,
                Terminal::True => MS_TRUE.strict_encode(e)?,
                Terminal::PkK(pk) => strict_encode_tuple!(e; MS_KEY, pk),
                Terminal::PkH(hash) => {
                    strict_encode_tuple!(e; MS_KEY_HASH, hash)
                }
                Terminal::After(tl) => strict_encode_tuple!(e; MS_AFTER, tl),
                Terminal::Older(tl) => strict_encode_tuple!(e; MS_OLDER, tl),
                Terminal::Sha256(hash) => {
                    strict_encode_tuple!(e; MS_SHA256, hash)
                }
                Terminal::Hash256(hash) => {
                    strict_encode_tuple!(e; MS_HASH256, hash)
                }
                Terminal::Ripemd160(hash) => {
                    strict_encode_tuple!(e; MS_RIPEMD160, hash)
                }
                Terminal::Hash160(hash) => {
                    strict_encode_tuple!(e; MS_HASH160, hash)
                }

                Terminal::Alt(ms) => strict_encode_ms!(e; MS_ALT, depth, ms),
                Terminal::Swap(ms) => strict_encode_ms!(e; MS_SWAP, depth, ms),
                Terminal::Check(ms) => {
                    strict_encode_ms!(e; MS_CHECK, depth, ms)
                }
                Terminal::DupIf(ms) => {
                    strict_encode_ms!(e; MS_DUP_IF, depth, ms)
                }
                Terminal::Verify(ms) => {
                    strict_encode_ms!(e; MS_VERIFY, depth, ms)
                }
                Terminal::NonZero(ms) => {
                    strict_encode_ms!(e; MS_NON_ZERO, depth, ms)
                }
                Terminal::ZeroNotEqual(ms) => {
                    strict_encode_ms!(e; MS_ZERO_NE, depth, ms)
                }

                Terminal::AndV(ms1, ms2) => {
                    strict_encode_ms!(e; MS_AND_V, depth, ms1, ms2)
                }
                Terminal::AndB(ms1, ms2) => {
                    strict_encode_ms!(e; MS_AND_B, depth, ms1, ms2)
                }
                Terminal::AndOr(ms1, ms2, ms3) => {
                    strict_encode_ms!(e; MS_AND_OR, depth, ms1, ms2, ms3)
                }
                Terminal::OrB(ms1, ms2) => {
                    strict_encode_ms!(e; MS_OR_B, depth, ms1, ms2)
                }
                Terminal::OrD(ms1, ms2) => {
                    strict_encode_ms!(e; MS_OR_D, depth, ms1, ms2)
                }
                Terminal::OrC(ms1, ms2) => {
                    strict_encode_ms!(e; MS_OR_C, depth, ms1, ms2)
                }
                Terminal::OrI(ms1, ms2) => {
                    strict_encode_ms!(e; MS_OR_I, depth, ms1, ms2)
                }
                Terminal::Multi(thresh, vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_MULTI])?;
                    len += strict_encode_usize!(e; *thresh);
                    len += strict_encode_usize!(e; vec.len());
                    for pk in vec {
                        len += pk.strict_encode(&mut e)?;
                    }
                    len
                }
                Terminal::Thresh(thresh, vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_THRESH])?;
                    len += strict_encode_usize!(e; *thresh);
                    len += strict_encode_usize!(e; vec.len());
                    for ms in vec {
                        len += encode_miniscript_inner(ms, e, depth)?;
                    }
                    len
                }
                Terminal::MultiA(thresh, vec) => {
                    let mut len = 1usize;
                    e.write_all(&[MS_MULTI_A])?;
                    len += strict_encode_usize!(e; *thresh);
                    len += strict_encode_usize!(e; vec.len());
                    for pk in vec {
                        len += pk.strict_encode(&mut e)?;
                    }
                    len
                }
            })
        }

        encode_miniscript_inner(self, &mut e, 1)
    }
}

impl<Pk, Ctx> StrictDecode for Miniscript<Pk, Ctx>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
    Ctx: miniscript::ScriptContext,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        // We need this first because of the need to control maximum number of
        // nested miniscript code, and than because of the rust compiler
        // limitations in working with recursive generic functions
        fn decode_miniscript_inner<Pk, Ctx>(
            d: &mut impl io::Read,
            mut depth: u8,
        ) -> Result<Miniscript<Pk, Ctx>, Error>
        where
            Pk: MiniscriptKey + StrictDecode,
            <Pk as MiniscriptKey>::Hash: StrictDecode,
            Ctx: miniscript::ScriptContext,
        {
            if depth > MINISCRIPT_DEPTH_LIMIT {
                return Err(Error::ExceedMaxItems(
                    MINISCRIPT_DEPTH_LIMIT as usize,
                ));
            }
            depth += 1;
            let term = match d.read_u8()? {
                MS_TRUE => Terminal::True,
                MS_FALSE => Terminal::False,
                MS_KEY => Terminal::PkK(Pk::strict_decode(d)?),
                MS_KEY_HASH => Terminal::PkH(Pk::Hash::strict_decode(d)?),

                MS_AFTER => Terminal::After(u32::strict_decode(d)?),
                MS_OLDER => Terminal::Older(u32::strict_decode(d)?),
                MS_SHA256 => Terminal::Sha256(sha256::Hash::strict_decode(d)?),
                MS_HASH256 => {
                    Terminal::Hash256(sha256d::Hash::strict_decode(d)?)
                }
                MS_RIPEMD160 => {
                    Terminal::Ripemd160(ripemd160::Hash::strict_decode(d)?)
                }
                MS_HASH160 => {
                    Terminal::Hash160(hash160::Hash::strict_decode(d)?)
                }

                MS_ALT => {
                    Terminal::Alt(decode_miniscript_inner(d, depth)?.into())
                }
                MS_SWAP => {
                    Terminal::Swap(decode_miniscript_inner(d, depth)?.into())
                }
                MS_CHECK => {
                    Terminal::Check(decode_miniscript_inner(d, depth)?.into())
                }
                MS_DUP_IF => {
                    Terminal::DupIf(decode_miniscript_inner(d, depth)?.into())
                }
                MS_VERIFY => {
                    Terminal::Verify(decode_miniscript_inner(d, depth)?.into())
                }
                MS_NON_ZERO => {
                    Terminal::NonZero(decode_miniscript_inner(d, depth)?.into())
                }
                MS_ZERO_NE => Terminal::ZeroNotEqual(
                    decode_miniscript_inner(d, depth)?.into(),
                ),

                MS_AND_V => Terminal::AndV(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_AND_B => Terminal::AndB(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_AND_OR => Terminal::AndOr(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_OR_B => Terminal::OrB(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_OR_D => Terminal::OrD(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_OR_C => Terminal::OrC(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_OR_I => Terminal::OrI(
                    decode_miniscript_inner(d, depth)?.into(),
                    decode_miniscript_inner(d, depth)?.into(),
                ),
                MS_MULTI => Terminal::Multi(
                    d.read_u16()? as usize,
                    Vec::strict_decode(d)?,
                ),
                MS_THRESH => {
                    let thresh = d.read_u16()? as usize;
                    let len = d.read_u16()?;
                    let mut vec = Vec::with_capacity(len as usize);
                    for _ in 0..len {
                        vec.push(decode_miniscript_inner(d, depth)?.into());
                    }
                    Terminal::Thresh(thresh, vec)
                }
                MS_MULTI_A => Terminal::MultiA(
                    d.read_u16()? as usize,
                    Vec::strict_decode(d)?,
                ),

                wrong => {
                    return Err(Error::DataIntegrityError(format!(
                        "byte {:#04X} does not correspond to any of \
                         miniscript instructions",
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

        decode_miniscript_inner(&mut d, 1)
    }
}

const DESCRIPTOR_BARE: u8 = 0x00;
const DESCRIPTOR_PKH: u8 = 0x01;
const DESCRIPTOR_SH: u8 = 0x02;
const DESCRIPTOR_WPKH: u8 = 0x10;
const DESCRIPTOR_WSH: u8 = 0x11;
const DESCRIPTOR_TR: u8 = 0x20;
const DESCRIPTOR_SORTED_MULTI: u8 = 0x03;
const DESCRIPTOR_MINISCRIPT: u8 = 0x04;

impl StrictEncode for SinglePubKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            SinglePubKey::FullKey(pk) => {
                strict_encode_list!(e; 0x01u8, pk)
            }
            SinglePubKey::XOnly(xpk) => {
                strict_encode_list!(e; 0x02u8, xpk)
            }
        })
    }
}

impl StrictDecode for SinglePubKey {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(&mut d)? {
            0x01 => SinglePubKey::FullKey(bitcoin::PublicKey::strict_decode(
                &mut d,
            )?),
            0x02 => SinglePubKey::XOnly(XOnlyPublicKey::strict_decode(&mut d)?),
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "unknown miniscript single pubkey tag `{:#04X}",
                    wrong
                )))
            }
        })
    }
}

impl StrictEncode for DescriptorPublicKey {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            DescriptorPublicKey::SinglePub(pk) => {
                strict_encode_list!(e; 0x01u8, pk)
            }
            DescriptorPublicKey::XPub(xpub) => {
                strict_encode_list!(e; 0x02u8, xpub)
            }
        })
    }
}

impl StrictDecode for DescriptorPublicKey {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(&mut d)? {
            0x01 => DescriptorPublicKey::SinglePub(
                DescriptorSinglePub::strict_decode(&mut d)?,
            ),
            0x02 => DescriptorPublicKey::XPub(DescriptorXKey::strict_decode(
                &mut d,
            )?),
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "unknown descriptor key tag `{:#04X}",
                    wrong
                )))
            }
        })
    }
}

impl StrictEncode for DescriptorSinglePub {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.origin, self.key))
    }
}

impl StrictDecode for DescriptorSinglePub {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(strict_decode_self!(d; origin, key; crate))
    }
}

impl<Pk> StrictEncode for DescriptorXKey<Pk>
where
    Pk: InnerXKey + StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(
            strict_encode_list!(e; self.origin, self.derivation_path, self.xkey, self.wildcard),
        )
    }
}

impl<Pk> StrictDecode for DescriptorXKey<Pk>
where
    Pk: InnerXKey + StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(
            strict_decode_self!(d; origin, derivation_path, xkey, wildcard; crate),
        )
    }
}

impl StrictEncode for Wildcard {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        match self {
            Wildcard::None => 0u8,
            Wildcard::Unhardened => 1u8,
            Wildcard::Hardened => 2u8,
        }
        .strict_encode(e)
    }
}

impl StrictDecode for Wildcard {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(d)? {
            0 => Wildcard::None,
            1 => Wildcard::Unhardened,
            2 => Wildcard::Hardened,
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "unknown descriptor xpub wildcard type `{:#04X}`",
                    wrong
                )))
            }
        })
    }
}

impl<Pk> StrictEncode for Descriptor<Pk>
where
    Pk: MiniscriptKey + StrictEncode,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            Descriptor::Bare(bare) => {
                strict_encode_list!(e; DESCRIPTOR_BARE, bare)
            }
            Descriptor::Pkh(pkh) => {
                strict_encode_list!(e; DESCRIPTOR_PKH, pkh)
            }
            Descriptor::Wpkh(wpkh) => {
                strict_encode_list!(e; DESCRIPTOR_WPKH, wpkh)
            }
            Descriptor::Sh(sh) => {
                strict_encode_list!(e; DESCRIPTOR_SH, sh)
            }
            Descriptor::Wsh(wsh) => {
                strict_encode_list!(e; DESCRIPTOR_WSH, wsh)
            }
            Descriptor::Tr(tr) => {
                strict_encode_list!(e; DESCRIPTOR_TR, tr)
            }
        })
    }
}

impl<Pk> StrictDecode for Descriptor<Pk>
where
    Pk: MiniscriptKey + StrictDecode,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(&mut d)? {
            DESCRIPTOR_BARE => {
                Descriptor::Bare(descriptor::Bare::strict_decode(&mut d)?)
            }
            DESCRIPTOR_PKH => {
                Descriptor::Pkh(descriptor::Pkh::strict_decode(&mut d)?)
            }
            DESCRIPTOR_SH => {
                Descriptor::Sh(descriptor::Sh::strict_decode(&mut d)?)
            }
            DESCRIPTOR_WPKH => {
                Descriptor::Wpkh(descriptor::Wpkh::strict_decode(&mut d)?)
            }
            DESCRIPTOR_WSH => {
                Descriptor::Wsh(descriptor::Wsh::strict_decode(&mut d)?)
            }
            DESCRIPTOR_TR => {
                Descriptor::Tr(descriptor::Tr::strict_decode(&mut d)?)
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

impl<Pk> StrictEncode for descriptor::Bare<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    #[inline]
    fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().strict_encode(e)
    }
}

impl<Pk> StrictDecode for descriptor::Bare<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
        Self::new(StrictDecode::strict_decode(d)?).map_err(Error::from)
    }
}

impl<Pk> StrictEncode for descriptor::Pkh<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    #[inline]
    fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().strict_encode(e)
    }
}

impl<Pk> StrictDecode for descriptor::Pkh<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(Self::new(StrictDecode::strict_decode(d)?))
    }
}

impl<Pk> StrictEncode for descriptor::Wpkh<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    #[inline]
    fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().strict_encode(e)
    }
}

impl<Pk> StrictDecode for descriptor::Wpkh<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
        Self::new(StrictDecode::strict_decode(d)?).map_err(Error::from)
    }
}

impl<Pk> StrictEncode for descriptor::Sh<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    #[inline]
    fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().strict_encode(e)
    }
}

impl<Pk> StrictDecode for descriptor::Sh<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
        Ok(match descriptor::ShInner::strict_decode(d)? {
            descriptor::ShInner::Wsh(wsh) => descriptor::Sh::new_with_wsh(wsh),
            descriptor::ShInner::Wpkh(wpkh) => {
                descriptor::Sh::new_with_wpkh(wpkh)
            }
            descriptor::ShInner::SortedMulti(inner) => {
                descriptor::Sh::new_sortedmulti(inner.k, inner.pks)?
            }
            descriptor::ShInner::Ms(ms) => descriptor::Sh::new(ms)?,
        })
    }
}

impl<Pk> StrictEncode for descriptor::Wsh<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    #[inline]
    fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
        self.as_inner().strict_encode(e)
    }
}

impl<Pk> StrictDecode for descriptor::Wsh<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    #[inline]
    fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
        match descriptor::WshInner::strict_decode(d)? {
            descriptor::WshInner::SortedMulti(inner) => {
                descriptor::Wsh::new_sortedmulti(inner.k, inner.pks)
            }
            descriptor::WshInner::Ms(ms) => descriptor::Wsh::new(ms),
        }
        .map_err(Error::from)
    }
}

impl<Pk> StrictEncode for descriptor::Tr<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.internal_key(), self.taptree()))
    }
}

impl<Pk> StrictDecode for descriptor::Tr<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        descriptor::Tr::new(
            StrictDecode::strict_decode(&mut d)?,
            StrictDecode::strict_decode(&mut d)?,
        )
        .map_err(Error::from)
    }
}

impl<Pk, Ctx> StrictEncode for descriptor::SortedMultiVec<Pk, Ctx>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
    Ctx: ScriptContext,
{
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(strict_encode_list!(e; self.k, self.pks))
    }
}

impl<Pk, Ctx> StrictDecode for descriptor::SortedMultiVec<Pk, Ctx>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
    Ctx: ScriptContext,
{
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        descriptor::SortedMultiVec::new(
            StrictDecode::strict_decode(&mut d)?,
            StrictDecode::strict_decode(&mut d)?,
        )
        .map_err(Error::from)
    }
}

impl<Pk> StrictEncode for descriptor::ShInner<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            descriptor::ShInner::Wsh(wsh) => {
                strict_encode_list!(e; DESCRIPTOR_WSH, wsh)
            }
            descriptor::ShInner::Wpkh(wpkh) => {
                strict_encode_list!(e; DESCRIPTOR_WPKH, wpkh)
            }
            descriptor::ShInner::SortedMulti(multi) => {
                strict_encode_list!(e; DESCRIPTOR_SORTED_MULTI, multi)
            }
            descriptor::ShInner::Ms(ms) => {
                strict_encode_list!(e; DESCRIPTOR_MINISCRIPT, ms)
            }
        })
    }
}

impl<Pk> StrictDecode for descriptor::ShInner<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(&mut d)? {
            DESCRIPTOR_MINISCRIPT => {
                descriptor::ShInner::Ms(StrictDecode::strict_decode(&mut d)?)
            }
            DESCRIPTOR_SORTED_MULTI => descriptor::ShInner::SortedMulti(
                StrictDecode::strict_decode(&mut d)?,
            ),
            DESCRIPTOR_WPKH => {
                descriptor::ShInner::Wpkh(StrictDecode::strict_decode(&mut d)?)
            }
            DESCRIPTOR_WSH => {
                descriptor::ShInner::Wsh(StrictDecode::strict_decode(&mut d)?)
            }
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "invalid miniscript ShInner descriptor type: #{:#04X}",
                    wrong
                )))
            }
        })
    }
}

impl<Pk> StrictEncode for descriptor::WshInner<Pk>
where
    Pk: StrictEncode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictEncode,
{
    fn strict_encode<E: Write>(&self, mut e: E) -> Result<usize, Error> {
        Ok(match self {
            descriptor::WshInner::SortedMulti(multi) => {
                strict_encode_list!(e; DESCRIPTOR_SORTED_MULTI, multi)
            }
            descriptor::WshInner::Ms(ms) => {
                strict_encode_list!(e; DESCRIPTOR_MINISCRIPT, ms)
            }
        })
    }
}

impl<Pk> StrictDecode for descriptor::WshInner<Pk>
where
    Pk: StrictDecode + MiniscriptKey,
    <Pk as MiniscriptKey>::Hash: StrictDecode,
{
    fn strict_decode<D: Read>(mut d: D) -> Result<Self, Error> {
        Ok(match u8::strict_decode(&mut d)? {
            DESCRIPTOR_MINISCRIPT => {
                descriptor::WshInner::Ms(StrictDecode::strict_decode(&mut d)?)
            }
            DESCRIPTOR_SORTED_MULTI => descriptor::WshInner::SortedMulti(
                StrictDecode::strict_decode(&mut d)?,
            ),
            wrong => {
                return Err(Error::DataIntegrityError(format!(
                    "invalid miniscript WshInner descriptor type: #{:#04X}",
                    wrong
                )))
            }
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use miniscript::{
        policy, BareCtx, Descriptor, Legacy, Miniscript, Segwitv0,
    };
    use strict_encoding_test::*;

    use crate::StrictDecode;

    #[test]
    #[should_panic]
    fn test_bare_ctx() { BareCtx::strict_deserialize(&[0u8]).unwrap(); }

    #[test]
    #[should_panic]
    fn test_legacy_ctx() { Legacy::strict_deserialize(&[0u8]).unwrap(); }

    #[test]
    #[should_panic]
    fn test_segwitv0_ctx() { Segwitv0::strict_deserialize(&[0u8]).unwrap(); }

    #[test]
    fn test_policy() {
        const SET: [&str; 12] = [
            "and(pk(A),or(and(after(9),pk(B)),and(after(1000000000),pk(C))))",
            "pk(A)",
            "after(9)",
            "older(1)",
            "sha256(1111111111111111111111111111111111111111111111111111111111111111)",
            "and(pk(A),pk(B))",
            "or(pk(A),pk(B))",
            "thresh(2,pk(A),pk(B),pk(C))",
            "thresh(2,after(9),after(9),pk(A))",
            "and(pk(A),or(after(9),after(9)))",
            "or(1@and(pk(A),pk(B)),127@pk(C))",
            "and(and(and(or(127@thresh(2,pk(A),pk(B),thresh(2,or(127@pk(A),1@pk(B)),after(100),or(and(pk(C),after(200)),and(pk(D),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925))),pk(E))),1@pk(F)),sha256(66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925)),or(127@pk(G),1@after(300))),or(127@after(400),pk(H)))",
        ];

        for s in &SET {
            let policy = policy::Concrete::<String>::from_str(s).unwrap();
            test_object_encoding_roundtrip(&policy).unwrap();
        }
    }

    #[test]
    fn test_miniscript() {
        const SET: [&str; 27] = [
            "lltvln:after(1231488000)",
            "uuj:and_v(v:multi(2,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a,025601570cb47f238d2b0286db4a990fa0f3ba28d1a319f5e7cf55c2a2444da7cc),after(1231488000))",
            "or_b(un:multi(2,03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),al:older(16))",
            "j:and_v(vdv:after(1567547623),older(2016))",
            "t:and_v(vu:hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),v:sha256(ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5))",
            "t:andor(multi(3,02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,02e493dbf1c10d80f3581e4904930b1404cc6c13900ee0758474fa94abe8c4cd13),v:older(4194305),v:sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2))",
            "or_d(multi(1,02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9),or_b(multi(3,022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01,032fa2104d6b38d11b0230010559879124e42ab8dfeff5ff29dc9cdadd4ecacc3f,03d01115d548e7561b15c38f004d734633687cf4419620095bc5b0f47070afe85a),su:after(500000)))",
            "or_d(sha256(38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6),and_n(un:after(499999999),older(4194305)))",
            "and_v(or_i(v:multi(2,02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5,03774ae7f858a9411e5ef4246b70c65aac5649980be5c17891bbec17895da008cb),v:multi(2,03e60fce93b59e9ec53011aabc21c23e97b2a31369b87a5ae9c44ee89e2a6dec0a,025cbdf0646e5db4eaa398f365f2ea7a0e3d419b7e0330e39ce92bddedcac4f9bc)),sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68))",
            "j:and_b(multi(2,0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798,024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),s:or_i(older(1),older(4252898)))",
            "and_b(older(16),s:or_d(sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),n:after(1567547623)))",
            "j:and_v(v:hash160(20195b5a3d650c17f0f29f91c33f8f6335193d07),or_d(sha256(96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47),older(16)))",
            "and_b(hash256(32ba476771d01e37807990ead8719f08af494723de1d228f2c2c07cc0aa40bac),a:and_b(hash256(131772552c01444cd81360818376a040b7c3b2b7b0a53550ee3edde216cec61b),a:older(1)))",
            "thresh(2,multi(2,03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),a:multi(1,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00),ac:pk_k(022f01e5e15cca351daff3843fb70f3c2f0a1bdd05e5af888a67784ef3e10a2a01))",
            "and_n(sha256(d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68),t:or_i(v:older(4252898),v:older(144)))",
            "c:and_v(or_c(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),v:multi(1,02c44d12c7065d812e8acf28d7cbb19f9011ecd9e9fdf281b0e6a3b5e87d22e7db)),pk_k(03acd484e2f0c7f65309ad178a9f559abde09796974c57e714c35f110dfc27ccbe))",
            "c:and_v(or_c(multi(2,036d2b085e9e382ed10b69fc311a03f8641ccfff21574de0927513a49d9a688a00,02352bbf4a4cdd12564f93fa332ce333301d9ad40271f8107181340aef25be59d5),v:ripemd160(1b0f3c404d12075c68c938f9f60ebea4f74941a0)),pk_k(03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556))",
            "and_v(andor(hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),v:hash256(939894f70e6c3a25da75da0cc2071b4076d9b006563cf635986ada2e93c0d735),v:older(50000)),after(499999999))",
            "andor(hash256(5f8d30e655a7ba0d7596bb3ddfb1d2d20390d23b1845000e1e118b3be1b3f040),j:and_v(v:hash160(3a2bff0da9d96868e66abc4427bea4691cf61ccd),older(4194305)),ripemd160(44d90e2d3714c8663b632fcf0f9d5f22192cc4c8))",
            "or_i(c:and_v(v:after(500000),pk_k(02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5)),sha256(d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946))",
            "thresh(2,c:pk_h(5dedfbf9ea599dd4e3ca6a80b333c472fd0b3f69),s:sha256(e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f),a:hash160(dd69735817e0e3f6f826a9238dc2e291184f0131))",
            "and_n(sha256(9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2),uc:and_v(v:older(144),pk_k(03fe72c435413d33d48ac09c9161ba8b09683215439d62b7940502bda8b202e6ce)))",
            "and_n(c:pk_k(03daed4f2be3a8bf278e70132fb0beb7522f570e144bf615c07e996d443dee8729),and_b(l:older(4252898),a:older(16)))",
            "c:or_i(and_v(v:older(16),pk_h(9fc5dbe5efdce10374a4dd4053c93af540211718)),pk_h(2fbd32c8dd59ee7c17e66cb6ebea7e9846c3040f))",
            "or_d(c:pk_h(c42e7ef92fdb603af844d064faad95db9bcdfd3d),andor(c:pk_k(024ce119c96e2fa357200b559b2f7dd5a5f02d5290aff74b03f3e471b273211c97),older(2016),after(1567547623)))",
            "c:andor(ripemd160(6ad07d21fd5dfc646f0b30577045ce201616b9ba),pk_h(9fc5dbe5efdce10374a4dd4053c93af540211718),and_v(v:hash256(8a35d9ca92a48eaade6f53a64985e9e2afeb74dcf8acb4c3721e0dc7e4294b25),pk_h(dd100be7d9aea5721158ebde6d6a1fd8fff93bb1)))",
            "c:or_i(andor(c:pk_h(fcd35ddacad9f2d5be5e464639441c6065e6955d),pk_h(9652d86bedf43ad264362e6e6eba6eb764508127),pk_h(06afd46bcdfd22ef94ac122aa11f241244a37ecc)),pk_k(02d7924d4f7d43ea965a465ae3095ff41131e5946f3c85f79e44adbcf8e27e080e))"
        ];

        for s in &SET {
            let ms =
                Miniscript::<bitcoin::PublicKey, Segwitv0>::from_str_insane(s)
                    .unwrap();
            test_object_encoding_roundtrip(&ms).unwrap();
        }
    }

    #[test]
    fn test_descriptor() {
        const SET: [&str; 16] = [
            "pk(020000000000000000000000000000000000000000000000000000000000000002)",
            "multi(1,020000000000000000000000000000000000000000000000000000000000000002)",
            "pkh(020000000000000000000000000000000000000000000000000000000000000002)",
            "wsh(c:pk_k(020000000000000000000000000000000000000000000000000000000000000002))",
            "sh(wsh(c:pk_k(020000000000000000000000000000000000000000000000000000000000000002)))",
            "wsh(after(1000))",
            "wsh(older(1000))",
            "wpkh(025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357)",
            "sh(wpkh(03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873))",
            "wsh(multi(2,03789ed0bb717d88f7d321a368d905e7430207ebbd82bd342cf11ae157a7ace5fd,03dbc6764b8884a92e871274b87583e6d5c2a58819473e17e107ef3f6aa5a61626))",
            "sh(sortedmulti(1,03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556,0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352))#uetvewm2",
            "wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH))#7etm7zk7",
            "sh(wsh(sortedmulti(1,xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB/1/0/*,xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH/0/0/*)))#u60cee0u",
            "wpkh(tprv8ZgxMBicQKsPcwcD4gSnMti126ZiETsuX7qwrtMypr6FBwAP65puFn4v6c3jrN9VwtMRMph6nyT63NrfUL4C3nBzPcduzVSuHD7zbX2JKVc/44'/0'/0'/0/*)",
            "wpkh([2cbe2a6d/44'/0'/0']tpubDCvNhURocXGZsLNqWcqD3syHTqPXrMSTwi8feKVwAcpi29oYKsDD3Vex7x2TDneKMVN23RbLprfxB69v94iYqdaYHsVz3kPR37NQXeqouVz/0/*)#nhdxg96s",
            "sh(multi(2,[00000000/111'/222]xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc,xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L/0))#ggrsrxfy",
        ];

        let secp = bitcoin::secp256k1::Secp256k1::new();

        for s in SET {
            let (descr, _) = Descriptor::parse_descriptor(&secp, s).unwrap();
            test_object_encoding_roundtrip(&descr).unwrap();
        }
    }
}
