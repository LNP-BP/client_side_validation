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

use amplify::ascii::AsciiString;
use amplify::confinement::Confined;
use amplify::num::apfloat::ieee::{
    Double, Half, Oct, Quad, Single, X87DoubleExtended,
};
use amplify::num::apfloat::Float;
use amplify::num::{i1024, i256, i512, u1024, u24, u256, u512};
use half::bf16;

use crate::path::{Step, TyIter};
use crate::schema::{Sizing, Ty};
use crate::write::ConfinedWrite;
use crate::{ConfinedEncode, Error, StructWriter};

#[derive(Clone, Hash, Debug, Display, Error)]
#[display(doc_comments)]
pub enum CheckError {}

pub struct CheckedWriter {
    iter: TyIter,
    count: u16,
}

impl CheckedWriter {
    pub fn new(ty: Ty) -> Self {
        CheckedWriter {
            iter: TyIter::from(ty),
            count: 0,
        }
    }

    pub fn size(&self) -> u16 { self.count as u16 }
}

macro_rules! write_num {
    ($ty:ident, $name:ident) => {
        fn $name(&mut self, _: $ty) -> Result<(), Error> {
            self.iter.check(&Ty::$ty());
            self.count += $ty::BITS as u16 / 8;
            Ok(())
        }
    };
}

macro_rules! write_float {
    ($ty:ident, $id:ident, $name:ident) => {
        fn $name(&mut self, _: $ty) -> Result<(), Error> {
            self.iter.check(&Ty::$id());
            self.count += $ty::BITS as u16 / 8;
            Ok(())
        }
    };
}

impl<'a> ConfinedWrite for CheckedWriter {
    fn step_in(&mut self, step: Step) { self.iter.step_in(step) }
    fn step_out(&mut self) { self.iter.step_out() }

    write_num!(u8, write_u8);
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

    fn write_f16b(&mut self, _: bf16) -> Result<(), Error> {
        self.iter.check(&Ty::f16b());
        self.count += 2;
        Ok(())
    }

    write_float!(Half, f16, write_f16);
    write_float!(Single, f32, write_f32);
    write_float!(Double, f64, write_f64);
    write_float!(X87DoubleExtended, f80, write_f80);
    write_float!(Quad, f128, write_f128);
    write_float!(Oct, f256, write_f256);

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
        self.count += 1;
        Ok(())
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
            panic!("invalid union variant {}", name);
        };
        if alt.ty.as_ref() != &ty {
            panic!("wrong enum type for variant {}", name);
        }
        self.count += 1;
        inner.confined_encode(self)?;
        Ok(())
    }

    fn write_option<T: ConfinedEncode>(
        &mut self,
        val: Option<&T>,
    ) -> Result<(), Error> {
        self.count += 1;
        if let Some(val) = val {
            val.confined_encode(self)?;
        }
        Ok(())
    }

    fn write_byte_array<const LEN: usize>(
        &mut self,
        _: [u8; LEN],
    ) -> Result<(), Error> {
        self.iter.check(&Ty::byte_array(LEN as u16));
        self.count += LEN as u16;
        Ok(())
    }

    fn write_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
        data: impl AsRef<[u8]>,
    ) -> Result<(), Error> {
        let len = data.as_ref().len();
        assert!(len <= u16::MAX as usize, "writing more than U16::MAX bytes");
        self.count += len as u16;
        self.count += 2;
        Ok(())
    }

    fn write_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
        s: &Confined<AsciiString, MIN, MAX>,
    ) -> Result<(), Error> {
        assert!(
            MAX <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        self.count += if MAX < u8::MAX as usize { 1 } else { 2 };
        self.count += s.len() as u16;
        self.iter.check(&Ty::Ascii(Sizing { min: MIN, max: MAX }));
        Ok(())
    }

    fn write_string<const MIN: usize, const MAX: usize>(
        &mut self,
        s: &Confined<String, MIN, MAX>,
    ) -> Result<(), Error> {
        assert!(
            MAX <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        self.count += if MAX < u8::MAX as usize { 1 } else { 2 };
        self.count += s.len() as u16;
        self.iter.check(&Ty::Ascii(Sizing { min: MIN, max: MAX }));
        Ok(())
    }

    fn write_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<Vec<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode,
    {
        assert!(
            MAX <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        self.iter.check(&Ty::list(T::confined_type(), Sizing {
            min: MIN,
            max: MAX,
        }));
        self.count += if MAX < u8::MAX as usize { 1 } else { 2 };
        self.step_in(Step::List);
        for item in data {
            item.confined_encode(&mut *self)?;
        }
        self.step_out();
        Ok(())
    }

    fn write_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
        data: &Confined<BTreeSet<T>, MIN, MAX>,
    ) -> Result<(), Error>
    where
        T: ConfinedEncode + Hash + Ord,
    {
        assert!(
            MAX <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        self.iter
            .check(&Ty::set(T::confined_type(), Sizing { min: MIN, max: MAX }));
        self.count += if MAX < u8::MAX as usize { 1 } else { 2 };
        self.step_in(Step::Set);
        for item in data {
            item.confined_encode(&mut *self)?;
        }
        self.step_out();
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
        assert!(
            MAX <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        self.iter.check(&Ty::map(
            K::confined_type().try_into_ty().expect("invalid key type"),
            V::confined_type(),
            Sizing { min: MIN, max: MAX },
        ));
        self.count += if MAX < u8::MAX as usize { 1 } else { 2 };
        self.step_in(Step::Map);
        for (k, v) in data {
            k.confined_encode(&mut *self)?;
            v.confined_encode(&mut *self)?;
        }
        self.step_out();

        Ok(())
    }

    fn write_struct(self) -> StructWriter<Self> { StructWriter::start(self) }
}
