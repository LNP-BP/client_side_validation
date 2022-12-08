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

use std::collections::{BTreeMap, BTreeSet};
use std::hash::Hash;
use std::io;

use amplify::ascii::AsciiString;
use amplify::confinement::Confined;
use amplify::num::apfloat::ieee::{
    Double, Half, Oct, Quad, Single, X87DoubleExtended,
};
use amplify::num::apfloat::Float;
use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
use half::bf16;

use crate::path::{Path, Step};
use crate::schema::Ty;
use crate::{ConfinedEncode, ConfinedType, Error};

pub trait ConfinedWrite: Sized {
    fn step_in(&mut self, step: Step);
    fn step_out(&mut self);

    fn write_u8(&mut self, val: u8) -> Result<(), Error>;
    fn write_u16(&mut self, val: u16) -> Result<(), Error>;
    fn write_u24(&mut self, val: u24) -> Result<(), Error>;
    fn write_u32(&mut self, val: u32) -> Result<(), Error>;
    fn write_u64(&mut self, val: u64) -> Result<(), Error>;
    fn write_u128(&mut self, val: u128) -> Result<(), Error>;
    fn write_u256(&mut self, val: u256) -> Result<(), Error>;
    fn write_u512(&mut self, val: u512) -> Result<(), Error>;
    fn write_u1024(&mut self, val: u1024) -> Result<(), Error>;

    fn write_i8(&mut self, val: i8) -> Result<(), Error>;
    fn write_i16(&mut self, val: i16) -> Result<(), Error>;
    fn write_i32(&mut self, val: i32) -> Result<(), Error>;
    fn write_i64(&mut self, val: i64) -> Result<(), Error>;
    fn write_i128(&mut self, val: i128) -> Result<(), Error>;
    fn write_i256(&mut self, val: i256) -> Result<(), Error>;
    fn write_i512(&mut self, val: i512) -> Result<(), Error>;
    fn write_i1024(&mut self, val: i1024) -> Result<(), Error>;

    fn write_f16b(&mut self, val: bf16) -> Result<(), Error>;
    fn write_f16(&mut self, val: Half) -> Result<(), Error>;
    fn write_f32(&mut self, val: Single) -> Result<(), Error>;
    fn write_f64(&mut self, val: Double) -> Result<(), Error>;
    fn write_f80(&mut self, val: X87DoubleExtended) -> Result<(), Error>;
    fn write_f128(&mut self, val: Quad) -> Result<(), Error>;
    fn write_f256(&mut self, val: Oct) -> Result<(), Error>;

    fn write_enum(&mut self, val: u8, ty: Ty) -> Result<(), Error>;
    fn write_union<T: ConfinedEncode>(
        &mut self,
        var: &'static str,
        ty: Ty,
        inner: &T,
    ) -> Result<(), Error>;

    fn write_option<T: ConfinedEncode>(
        &mut self,
        val: Option<&T>,
    ) -> Result<(), Error>;

    fn write_byte_array<const LEN: usize>(
        &mut self,
        array: [u8; LEN],
    ) -> Result<(), Error>;

    fn write_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error>;

    fn write_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<AsciiString, MIN, MAX>,
    ) -> Result<(), Error>;

    fn write_string<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<String, MIN, MAX>,
    ) -> Result<(), Error>;

    fn write_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<Vec<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode;

    fn write_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeSet<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode + Hash + Ord;

    fn write_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeMap<K, V>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        K: ConfinedEncode + Hash + Ord,
        V: ConfinedEncode;

    fn build_struct(self) -> StructBuilder<Self>;
}

impl<'w, W> ConfinedWrite for &'w mut W
where
    W: ConfinedWrite,
{
    fn step_in(&mut self, _step: Step) {}
    fn step_out(&mut self) {}

    fn write_u8(&mut self, val: u8) -> Result<(), Error> {
        W::write_u8(self, val)
    }
    fn write_u16(&mut self, val: u16) -> Result<(), Error> {
        W::write_u16(self, val)
    }
    fn write_u24(&mut self, val: u24) -> Result<(), Error> {
        W::write_u24(self, val)
    }
    fn write_u32(&mut self, val: u32) -> Result<(), Error> {
        W::write_u32(self, val)
    }
    fn write_u64(&mut self, val: u64) -> Result<(), Error> {
        W::write_u64(self, val)
    }
    fn write_u128(&mut self, val: u128) -> Result<(), Error> {
        W::write_u128(self, val)
    }
    fn write_u256(&mut self, val: u256) -> Result<(), Error> {
        W::write_u256(self, val)
    }
    fn write_u512(&mut self, val: u512) -> Result<(), Error> {
        W::write_u512(self, val)
    }
    fn write_u1024(&mut self, val: u1024) -> Result<(), Error> {
        W::write_u1024(self, val)
    }
    fn write_i8(&mut self, val: i8) -> Result<(), Error> {
        W::write_i8(self, val)
    }
    fn write_i16(&mut self, val: i16) -> Result<(), Error> {
        W::write_i16(self, val)
    }
    fn write_i32(&mut self, val: i32) -> Result<(), Error> {
        W::write_i32(self, val)
    }
    fn write_i64(&mut self, val: i64) -> Result<(), Error> {
        W::write_i64(self, val)
    }
    fn write_i128(&mut self, val: i128) -> Result<(), Error> {
        W::write_i128(self, val)
    }
    fn write_i256(&mut self, val: i256) -> Result<(), Error> {
        W::write_i256(self, val)
    }
    fn write_i512(&mut self, val: i512) -> Result<(), Error> {
        W::write_i512(self, val)
    }
    fn write_i1024(&mut self, val: i1024) -> Result<(), Error> {
        W::write_i1024(self, val)
    }
    fn write_f16b(&mut self, val: bf16) -> Result<(), Error> {
        W::write_f16b(self, val)
    }
    fn write_f16(&mut self, val: Half) -> Result<(), Error> {
        W::write_f16(self, val)
    }
    fn write_f32(&mut self, val: Single) -> Result<(), Error> {
        W::write_f32(self, val)
    }
    fn write_f64(&mut self, val: Double) -> Result<(), Error> {
        W::write_f64(self, val)
    }
    fn write_f80(&mut self, val: X87DoubleExtended) -> Result<(), Error> {
        W::write_f80(self, val)
    }
    fn write_f128(&mut self, val: Quad) -> Result<(), Error> {
        W::write_f128(self, val)
    }
    fn write_f256(&mut self, val: Oct) -> Result<(), Error> {
        W::write_f256(self, val)
    }
    fn write_enum(&mut self, val: u8, ty: Ty) -> Result<(), Error> {
        W::write_enum(self, val, ty)
    }

    fn write_union<T: ConfinedEncode>(
        &mut self,
        var: &'static str,
        ty: Ty,
        inner: &T,
    ) -> Result<(), Error> {
        W::write_union(self, var, ty, inner)
    }

    fn write_option<T: ConfinedEncode>(
        &mut self,
        val: Option<&T>,
    ) -> Result<(), Error> {
        W::write_option(self, val)
    }

    fn write_byte_array<const LEN: usize>(
        &mut self,
        array: [u8; LEN],
    ) -> Result<(), Error> {
        W::write_byte_array(self, array)
    }

    fn write_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        W::write_bytes::<MIN, MAX>(self, data)
    }

    fn write_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<AsciiString, MIN, MAX>,
    ) -> Result<(), Error> {
        W::write_ascii(self, data)
    }

    fn write_string<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<String, MIN, MAX>,
    ) -> Result<(), Error> {
        W::write_string(self, data)
    }

    fn write_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<Vec<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode,
    {
        W::write_list(self, data)
    }

    fn write_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeSet<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode + Hash + Ord,
    {
        W::write_set(self, data)
    }

    fn write_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeMap<K, V>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        K: ConfinedEncode + Hash + Ord,
        V: ConfinedEncode,
    {
        W::write_map(self, data)
    }

    fn build_struct(self) -> StructBuilder<Self> { StructBuilder::start(self) }
}

pub struct Writer<W: io::Write>(W);

impl<W: io::Write> Writer<W> {
    pub fn unbox(self) -> W { self.0 }

    fn write_len(&mut self, len: usize, max: usize) -> Result<(), Error> {
        assert!(
            max <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        if max <= u8::MAX as usize {
            let len = len as u8;
            self.0.write_all(&[len])?;
        } else {
            let len = len as u16;
            self.0.write_all(&len.to_le_bytes())?;
        }
        Ok(())
    }
}

impl<W: io::Write> From<W> for Writer<W> {
    fn from(writer: W) -> Self { Self(writer) }
}

macro_rules! write_num {
    ($ty:ty, $name:ident) => {
        fn $name(&mut self, val: $ty) -> Result<(), Error> {
            self.0.write_all(&val.to_le_bytes()).map_err(Error::from)
        }
    };
}

macro_rules! write_float {
    ($ty:ident, $name:ident) => {
        fn $name(&mut self, val: $ty) -> Result<(), Error> {
            let bytes = val.to_bits().to_le_bytes();
            self.0
                .write_all(&bytes[..($ty::BITS as usize / 8)])
                .map_err(Error::from)
        }
    };
}

impl<W: io::Write> ConfinedWrite for Writer<W> {
    fn step_in(&mut self, _step: Step) {}

    fn step_out(&mut self) {}

    fn write_u8(&mut self, val: u8) -> Result<(), Error> {
        self.0.write_all(&[val]).map_err(Error::from)
    }

    write_num!(u16, write_u16);
    write_num!(u24, write_u24);
    write_num!(u32, write_u32);
    write_num!(u64, write_u64);
    write_num!(u128, write_u128);
    write_num!(u256, write_u256);
    write_num!(u512, write_u512);
    write_num!(u1024, write_u1024);

    write_num!(i8, write_i8);
    write_num!(i16, write_i16);
    write_num!(i32, write_i32);
    write_num!(i64, write_i64);
    write_num!(i128, write_i128);
    write_num!(i256, write_i256);
    write_num!(i512, write_i512);
    write_num!(i1024, write_i1024);

    fn write_f16b(&mut self, val: bf16) -> Result<(), Error> {
        self.0
            .write_all(&val.to_bits().to_le_bytes())
            .map_err(Error::from)
    }

    write_float!(Half, write_f16);
    write_float!(Single, write_f32);
    write_float!(Double, write_f64);
    write_float!(X87DoubleExtended, write_f80);
    write_float!(Quad, write_f128);
    write_float!(Oct, write_f256);

    fn write_enum(&mut self, val: u8, ty: Ty) -> Result<(), Error> {
        let Ty::Enum(variants) = ty else {
            panic!("write_enum requires Ty::Enum type")
        };
        if variants
            .iter()
            .find(|variant| variant.value == val)
            .is_none()
        {
            panic!("invalid enum variant {}", val);
        }
        self.0.write_all(&[val]).map_err(Error::from)
    }

    fn write_union<T: ConfinedEncode>(
        &mut self,
        name: &'static str,
        ty: Ty,
        inner: &T,
    ) -> Result<(), Error> {
        let Ty::Union(ref variants) = ty else {
            panic!("write_union requires Ty::Union type")
        };
        let Some(alt) = variants.get(name) else {
            panic!("invalid union alternative {}", name);
        };
        let actual_ty = ty
            .path(&Path::with(Step::Alt(name)))
            .expect("unknown union alternative");
        if alt.ty.as_ref() != actual_ty {
            panic!(
                "wrong data type for union alternative {}; expected {:?}, \
                 found {:?}",
                name, alt.ty, actual_ty
            );
        }
        self.0.write_all(&[alt.id])?;
        inner.confined_encode(self)
    }

    fn write_option<T: ConfinedEncode>(
        &mut self,
        val: Option<&T>,
    ) -> Result<(), Error> {
        let ty = Option::<T>::confined_type();
        match val {
            Some(val) => self.write_union("Some", ty, val),
            None => self.write_union("None", ty, &()),
        }
    }

    fn write_byte_array<const LEN: usize>(
        &mut self,
        array: [u8; LEN],
    ) -> Result<(), Error> {
        debug_assert!(
            LEN < u16::MAX as usize,
            "only arrays under u16::MAX are allowed"
        );
        self.0.write_all(&array[..]).map_err(Error::from)
    }

    fn write_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let data = data.as_ref();
        self.write_len(data.len(), MAX)?;
        self.0.write_all(data).map_err(Error::from)
    }

    fn write_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<AsciiString, MIN, MAX>,
    ) -> Result<(), Error> {
        self.write_len(data.len(), MAX)?;
        self.0.write_all(data.as_bytes()).map_err(Error::from)
    }

    fn write_string<const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<String, MIN, MAX>,
    ) -> Result<(), Error> {
        self.write_len(data.len(), MAX)?;
        self.0.write_all(data.as_bytes()).map_err(Error::from)
    }

    fn write_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<Vec<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode,
    {
        self.write_len(data.len(), MAX)?;
        for item in data {
            item.confined_encode(&mut *self)?;
        }
        Ok(())
    }

    fn write_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeSet<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode + Hash + Ord,
    {
        self.write_len(data.len(), MAX)?;
        for item in data {
            item.confined_encode(&mut *self)?;
        }
        Ok(())
    }

    fn write_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeMap<K, V>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        K: ConfinedEncode + Hash + Ord,
        V: ConfinedEncode,
    {
        self.write_len(data.len(), MAX)?;
        for (k, v) in data {
            k.confined_encode(&mut *self)?;
            v.confined_encode(&mut *self)?;
        }
        Ok(())
    }

    fn build_struct(self) -> StructBuilder<Self> { StructBuilder::start(self) }
}

pub struct StructBuilder<W: ConfinedWrite>(W);

impl<W: ConfinedWrite> StructBuilder<W> {
    pub fn start(writer: W) -> Self { StructBuilder(writer) }

    pub fn field(
        mut self,
        name: &'static str,
        data: &impl ConfinedEncode,
    ) -> Result<Self, Error> {
        self.0.step_in(Step::Field(name));
        data.confined_encode(&mut self.0)?;
        self.0.step_out();
        Ok(self)
    }

    pub fn finish(self) -> W {
        // Do nothing
        self.0
    }
}
