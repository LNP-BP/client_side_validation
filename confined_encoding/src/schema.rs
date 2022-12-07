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

#![allow(missing_docs)]
//! Module defining type system used by strict encoding

use std::cmp::Ordering;
use std::iter::Sum;
use std::ops::{Add, AddAssign};

use amplify::confinement::TinyVec;
use amplify::num::u5;

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
pub const I8: u8 = 0x41;
pub const I16: u8 = 0x42;
pub const I24: u8 = 0x43;
pub const I32: u8 = 0x44;
pub const I48: u8 = 0x46;
pub const I64: u8 = 0x48;
pub const I128: u8 = 0x50;
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

#[derive(Clone, Debug)]
pub enum Ty {
    Primitive(&'static str, u8),
    Composed(&'static str, Comp, TinyVec<Field>),
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
pub enum Comp {
    Union,
    Product,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: &'static str,
    pub ty: Box<Ty>,
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
            Ty::Primitive(_, UNIT)
            | Ty::Primitive(_, BYTE)
            | Ty::Primitive(_, CHAR) => Size::Fixed(1),
            Ty::Primitive(_, F16B) => Size::Fixed(2),
            Ty::Primitive(_, code) => {
                Size::Fixed(NumInfo::from_code(*code).size())
            }
            Ty::Composed(_, Comp::Union, fields) => fields
                .iter()
                .map(|field| field.ty.size())
                .max()
                .unwrap_or(Size::Fixed(0)),
            Ty::Composed(_, Comp::Product, fields) => {
                fields.iter().map(|field| field.ty.size()).sum()
            }
        }
    }
}
