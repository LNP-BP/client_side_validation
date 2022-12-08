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

//! Module defining type system used by strict encoding

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::iter::Sum;
use std::ops::{Add, AddAssign};

use amplify::confinement::Confined;
use amplify::num::u5;

#[macro_export]
macro_rules! fields {
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeMap::new();
            $(
                m.insert($key, Box::new($value)).expect("repeated field");
            )+
            $crate::schema::Fields::try_from(m).expect("too many fields")
        }
    }
}

#[macro_export]
macro_rules! alternatives {
    { $($key:expr => $val:expr => $ty:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeMap::new();
            $(
                m.insert($key, $crate::schema::Alternative::new($val, $ty)).expect("repeated union alternative");
            )+
            $crate::schema::Alternatives::try_from(m).expect("too many union alternatives")
        }
    }
}

#[macro_export]
macro_rules! variants {
    { $($key:expr => $value:expr),+ } => {
        {
            let mut m = ::std::collections::BTreeSet::new();
            $(
                assert!(m.insert($crate::schema::Variant::new($key, $value)), "repeated enum variant");
            )+
            $crate::schema::Variants::try_from(m).expect("too many enum variants")
        }
    }
}

pub const U8: u8 = 0x01;
pub const U16: u8 = 0x02;
pub const U24: u8 = 0x03;
pub const U32: u8 = 0x04;
pub const U48: u8 = 0x06;
pub const U64: u8 = 0x08;
pub const U128: u8 = 0x10;
pub const U160: u8 = 0x14;
pub const U256: u8 = 0x20;
pub const U512: u8 = 0x22;
pub const U1024: u8 = 0x36;
pub const I8: u8 = 0x41;
pub const I16: u8 = 0x42;
pub const I24: u8 = 0x43;
pub const I32: u8 = 0x44;
pub const I48: u8 = 0x46;
pub const I64: u8 = 0x48;
pub const I128: u8 = 0x50;
pub const I256: u8 = 0x60;
pub const I512: u8 = 0x62;
pub const I1024: u8 = 0x76;
pub const N8: u8 = 0x81;
pub const N16: u8 = 0x82;
pub const N24: u8 = 0x83;
pub const N32: u8 = 0x84;
pub const N48: u8 = 0x86;
pub const N64: u8 = 0x88;
pub const N128: u8 = 0x91;
pub const F16: u8 = 0xC1;
pub const F32: u8 = 0xC4;
pub const F64: u8 = 0xC8;
pub const F80: u8 = 0xCA;
pub const F128: u8 = 0xD0;
pub const F256: u8 = 0xE0;

pub const UNIT: u8 = 0x00;
pub const BYTE: u8 = 0x40;
pub const CHAR: u8 = 0x80;
pub const F16B: u8 = 0xC0;

/// Information about numeric type
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct NumInfo {
    /// Class of the number
    pub ty: NumTy,
    /// Size of the number, in bytes
    pub size: NumSize,
}

impl NumInfo {
    pub fn from_code(id: u8) -> Self {
        NumInfo {
            ty: NumTy::from_code(id),
            size: NumSize::from_code(id),
        }
    }

    pub fn into_code(self) -> u8 { self.ty.into_code() | self.size.into_code() }

    pub fn size(self) -> u16 { self.size.size() }
}

/// The way how the size is computed and encoded in the type id
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NumSize {
    /// Lowest 5 bits contain type size in bytes
    Bytes(u5),
    /// Lowest 5 bits contain a factor defining the size according to the
    /// equation `16 * (2 + factor)`
    Factored(u5),
}

impl NumSize {
    pub fn from_code(id: u8) -> Self {
        let code = id & 0x1F;
        match id & 0x20 / 0x20 {
            0 => NumSize::Bytes(code.try_into().expect("bit masked")),
            1 => NumSize::Factored(code.try_into().expect("bit masked")),
            _ => unreachable!(),
        }
    }

    pub fn into_code(self) -> u8 {
        match self {
            NumSize::Bytes(bytes) => bytes.as_u8(),
            NumSize::Factored(factor) => factor.as_u8() | 0x20,
        }
    }

    pub fn size(self) -> u16 {
        match self {
            NumSize::Bytes(bytes) => bytes.as_u8() as u16,
            NumSize::Factored(factor) => 2 * (factor.as_u8() as u16 + 1),
        }
    }
}

/// Class of the number type
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NumTy {
    Unsigned = 0x00,
    Signed = 0x40,
    NonZero = 0x80,
    Float = 0xC0,
}

impl NumTy {
    pub fn from_code(id: u8) -> Self {
        match id & 0xC0 {
            x if x == NumTy::Unsigned as u8 => NumTy::Unsigned,
            x if x == NumTy::Signed as u8 => NumTy::Signed,
            x if x == NumTy::NonZero as u8 => NumTy::NonZero,
            x if x == NumTy::Float as u8 => NumTy::Float,
            _ => unreachable!(),
        }
    }

    pub fn into_code(self) -> u8 { self as u8 }
}

pub type Alternatives =
    Confined<BTreeMap<&'static str, Alternative>, 1, { u8::MAX as usize }>;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Alternative {
    pub id: u8,
    pub ty: Box<Ty>,
}

impl Alternative {
    pub fn new(id: u8, ty: Ty) -> Alternative {
        Alternative {
            id,
            ty: Box::new(ty),
        }
    }
}

pub type Fields =
    Confined<BTreeMap<&'static str, Box<Ty>>, 1, { u8::MAX as usize }>;

pub type Variants = Confined<BTreeSet<Variant>, 1, { u8::MAX as usize }>;

#[derive(Copy, Clone, Eq, Debug)]
pub struct Variant {
    pub name: &'static str,
    pub value: u8,
}

impl Variant {
    pub fn new(name: &'static str, value: u8) -> Variant {
        Variant { name, value }
    }
}

impl PartialEq for Variant {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name || self.value == other.value
    }
}

impl PartialOrd for Variant {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Variant {
    fn cmp(&self, other: &Self) -> Ordering {
        if self == other {
            return Ordering::Equal;
        }
        self.value.cmp(&other.value)
    }
}

/// Lexicographically sortable types which may serve as map keys.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum KeyTy {
    Primitive(u8),
    Enum(Variants),
    Array(Box<Ty>, u16),
    Ascii(Sizing),
    Unicode(Sizing),
    Bytes(Sizing),
}

#[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
pub struct Sizing {
    pub min: usize,
    pub max: usize,
}

impl Sizing {
    pub const U8: Sizing = Sizing {
        min: 0,
        max: u8::MAX as usize,
    };

    pub const U16: Sizing = Sizing {
        min: 0,
        max: u16::MAX as usize,
    };

    pub const U8_NONEMPTY: Sizing = Sizing {
        min: 1,
        max: u8::MAX as usize,
    };
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Ty {
    Primitive(u8),
    Enum(Variants),
    Union(Alternatives),
    Struct(Fields),
    Array(Box<Ty>, u16),
    Ascii(Sizing),
    Unicode(Sizing),
    List(Box<Ty>, Sizing),
    Set(Box<Ty>, Sizing),
    Map(KeyTy, Box<Ty>, Sizing),
}

impl Ty {
    pub fn unit() -> Ty { Ty::Primitive(UNIT) }
    pub fn byte() -> Ty { Ty::Primitive(BYTE) }
    pub fn char() -> Ty { Ty::Primitive(CHAR) }

    pub fn u8() -> Ty { Ty::Primitive(U8) }
    pub fn u16() -> Ty { Ty::Primitive(U16) }
    pub fn u24() -> Ty { Ty::Primitive(U24) }
    pub fn u32() -> Ty { Ty::Primitive(U32) }
    pub fn u64() -> Ty { Ty::Primitive(U64) }
    pub fn u128() -> Ty { Ty::Primitive(U128) }
    pub fn u256() -> Ty { Ty::Primitive(U256) }
    pub fn u512() -> Ty { Ty::Primitive(U512) }
    pub fn u1024() -> Ty { Ty::Primitive(U1024) }

    pub fn i8() -> Ty { Ty::Primitive(I8) }
    pub fn i16() -> Ty { Ty::Primitive(I16) }
    pub fn i24() -> Ty { Ty::Primitive(I24) }
    pub fn i32() -> Ty { Ty::Primitive(I32) }
    pub fn i64() -> Ty { Ty::Primitive(I64) }
    pub fn i128() -> Ty { Ty::Primitive(I128) }
    pub fn i256() -> Ty { Ty::Primitive(I256) }
    pub fn i512() -> Ty { Ty::Primitive(I512) }
    pub fn i1024() -> Ty { Ty::Primitive(I1024) }

    pub fn f16b() -> Ty { Ty::Primitive(F16B) }
    pub fn f16() -> Ty { Ty::Primitive(F16) }
    pub fn f32() -> Ty { Ty::Primitive(F32) }
    pub fn f64() -> Ty { Ty::Primitive(F64) }
    pub fn f80() -> Ty { Ty::Primitive(F80) }
    pub fn f128() -> Ty { Ty::Primitive(F128) }
    pub fn f256() -> Ty { Ty::Primitive(F256) }

    pub fn enumerate(variants: Variants) -> Ty { Ty::Enum(variants) }

    pub fn byte_array(len: u16) -> Ty {
        Ty::Array(Box::new(Ty::Primitive(BYTE)), len)
    }

    pub fn bytes() -> Ty {
        Ty::List(Box::new(Ty::Primitive(BYTE)), Sizing::U16)
    }
    pub fn list(ty: Ty, sizing: Sizing) -> Ty { Ty::List(Box::new(ty), sizing) }
    pub fn set(ty: Ty, sizing: Sizing) -> Ty { Ty::Set(Box::new(ty), sizing) }
    pub fn map(key: KeyTy, val: Ty, sizing: Sizing) -> Ty {
        Ty::Map(key, Box::new(val), sizing)
    }

    pub fn option(ty: Ty) -> Ty {
        Ty::Union(alternatives![
            "None" => 0 => Ty::unit(),
            "Some" => 1 => ty
        ])
    }

    pub fn try_into_ty(self) -> Result<KeyTy, Ty> {
        Ok(match self {
            Ty::Primitive(code) => KeyTy::Primitive(code),
            Ty::Enum(vars) => KeyTy::Enum(vars),
            Ty::Array(ty, len) => KeyTy::Array(ty, len),
            Ty::Ascii(sizing) => KeyTy::Ascii(sizing),
            Ty::Unicode(sizing) => KeyTy::Unicode(sizing),
            me @ Ty::Union(_)
            | me @ Ty::Struct(_)
            | me @ Ty::List(_, _)
            | me @ Ty::Set(_, _)
            | me @ Ty::Map(_, _, _) => return Err(me),
        })
    }
}

/// Measure of a type size in bytes
#[derive(Copy, Clone, PartialEq, Eq, Debug, Display)]
pub enum Size {
    /// Type has a fixed size known at compile time
    #[display(inner)]
    Fixed(u16),

    /// Type has variable size
    #[display("variable")]
    Variable,
}

impl PartialOrd for Size {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Size {
    fn cmp(&self, other: &Self) -> Ordering {
        match (self, other) {
            (Size::Variable, Size::Variable) => Ordering::Equal,
            (Size::Variable, _) => Ordering::Greater,
            (_, Size::Variable) => Ordering::Less,
            (Size::Fixed(a), Size::Fixed(b)) => a.cmp(b),
        }
    }
}

impl Add for Size {
    type Output = Size;

    fn add(self, rhs: Self) -> Self::Output {
        match (self, rhs) {
            (Size::Fixed(a), Size::Fixed(b)) => Size::Fixed(a + b),
            _ => Size::Variable,
        }
    }
}

impl AddAssign for Size {
    fn add_assign(&mut self, rhs: Self) { *self = *self + rhs; }
}

impl Sum for Size {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let mut acc = Size::Fixed(0);
        for item in iter {
            acc += item;
        }
        acc
    }
}

impl Ty {
    pub fn size(&self) -> Size {
        match self {
            Ty::Primitive(UNIT) | Ty::Primitive(BYTE) | Ty::Primitive(CHAR) => {
                Size::Fixed(1)
            }
            Ty::Primitive(F16B) => Size::Fixed(2),
            Ty::Primitive(code) => {
                Size::Fixed(NumInfo::from_code(*code).size())
            }
            Ty::Union(fields) => fields
                .values()
                .map(|alt| alt.ty.size())
                .max()
                .unwrap_or(Size::Fixed(0)),
            Ty::Struct(fields) => fields.values().map(|ty| ty.size()).sum(),
            Ty::Enum(_) => Size::Fixed(1),
            Ty::Array(_, len) => Size::Fixed(*len),
            Ty::Unicode(..)
            | Ty::Ascii(..)
            | Ty::List(..)
            | Ty::Set(..)
            | Ty::Map(..) => Size::Variable,
        }
    }
}
