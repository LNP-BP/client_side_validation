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
use std::fmt::Debug;
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

use crate::path::Step;
use crate::schema::{Alternative, Ty};
use crate::{ConfinedDecode, ConfinedType, Error};

pub trait ConfinedRead: Sized {
    fn step_in(&mut self, step: Step);
    fn step_out(&mut self);

    fn read_u8(&mut self) -> Result<u8, Error>;
    fn read_u16(&mut self) -> Result<u16, Error>;
    fn read_u24(&mut self) -> Result<u24, Error>;
    fn read_u32(&mut self) -> Result<u32, Error>;
    fn read_u64(&mut self) -> Result<u64, Error>;
    fn read_u128(&mut self) -> Result<u128, Error>;
    fn read_u256(&mut self) -> Result<u256, Error>;
    fn read_u512(&mut self) -> Result<u512, Error>;
    fn read_u1024(&mut self) -> Result<u1024, Error>;

    fn read_i8(&mut self) -> Result<i8, Error>;
    fn read_i16(&mut self) -> Result<i16, Error>;
    fn read_i32(&mut self) -> Result<i32, Error>;
    fn read_i64(&mut self) -> Result<i64, Error>;
    fn read_i128(&mut self) -> Result<i128, Error>;
    fn read_i256(&mut self) -> Result<i256, Error>;
    fn read_i512(&mut self) -> Result<i512, Error>;
    fn read_i1024(&mut self) -> Result<i1024, Error>;

    fn read_f16b(&mut self) -> Result<bf16, Error>;
    fn read_f16(&mut self) -> Result<Half, Error>;
    fn read_f32(&mut self) -> Result<Single, Error>;
    fn read_f64(&mut self) -> Result<Double, Error>;
    fn read_f80(&mut self) -> Result<X87DoubleExtended, Error>;
    fn read_f128(&mut self) -> Result<Quad, Error>;
    fn read_f256(&mut self) -> Result<Oct, Error>;

    fn read_enum(&mut self, name: &'static str, ty: Ty) -> Result<u8, Error>;
    fn read_union(
        &mut self,
        name: &'static str,
        ty: Ty,
    ) -> Result<(&'static str, Alternative), Error>;

    fn read_option<T: ConfinedDecode>(&mut self) -> Result<Option<T>, Error>;

    fn read_byte_array<const LEN: usize>(&mut self)
        -> Result<[u8; LEN], Error>;

    fn read_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<u8>, MIN, MAX>, Error>;

    fn read_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<AsciiString, MIN, MAX>, Error>;

    fn read_string<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<String, MIN, MAX>, Error>;

    fn read_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode;

    fn read_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeSet<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode + Hash + Ord + Debug;

    fn read_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeMap<K, V>, MIN, MAX>, Error>
    where
        K: ConfinedDecode + Hash + Ord + Debug,
        V: ConfinedDecode;

    fn read_struct(self) -> StructReader<Self>;
}

impl<'r, R> ConfinedRead for &'r mut R
where
    R: ConfinedRead,
{
    fn step_in(&mut self, step: Step) { R::step_in(self, step) }
    fn step_out(&mut self) { R::step_out(self) }

    fn read_u8(&mut self) -> Result<u8, Error> { R::read_u8(self) }
    fn read_u16(&mut self) -> Result<u16, Error> { R::read_u16(self) }
    fn read_u24(&mut self) -> Result<u24, Error> { R::read_u24(self) }
    fn read_u32(&mut self) -> Result<u32, Error> { R::read_u32(self) }
    fn read_u64(&mut self) -> Result<u64, Error> { R::read_u64(self) }
    fn read_u128(&mut self) -> Result<u128, Error> { R::read_u128(self) }
    fn read_u256(&mut self) -> Result<u256, Error> { R::read_u256(self) }
    fn read_u512(&mut self) -> Result<u512, Error> { R::read_u512(self) }
    fn read_u1024(&mut self) -> Result<u1024, Error> { R::read_u1024(self) }
    fn read_i8(&mut self) -> Result<i8, Error> { R::read_i8(self) }
    fn read_i16(&mut self) -> Result<i16, Error> { R::read_i16(self) }
    fn read_i32(&mut self) -> Result<i32, Error> { R::read_i32(self) }
    fn read_i64(&mut self) -> Result<i64, Error> { R::read_i64(self) }
    fn read_i128(&mut self) -> Result<i128, Error> { R::read_i128(self) }
    fn read_i256(&mut self) -> Result<i256, Error> { R::read_i256(self) }
    fn read_i512(&mut self) -> Result<i512, Error> { R::read_i512(self) }
    fn read_i1024(&mut self) -> Result<i1024, Error> { R::read_i1024(self) }
    fn read_f16b(&mut self) -> Result<bf16, Error> { R::read_f16b(self) }
    fn read_f16(&mut self) -> Result<Half, Error> { R::read_f16(self) }
    fn read_f32(&mut self) -> Result<Single, Error> { R::read_f32(self) }
    fn read_f64(&mut self) -> Result<Double, Error> { R::read_f64(self) }
    fn read_f80(&mut self) -> Result<X87DoubleExtended, Error> {
        R::read_f80(self)
    }
    fn read_f128(&mut self) -> Result<Quad, Error> { R::read_f128(self) }
    fn read_f256(&mut self) -> Result<Oct, Error> { R::read_f256(self) }

    fn read_enum(&mut self, name: &'static str, ty: Ty) -> Result<u8, Error> {
        R::read_enum(self, name, ty)
    }

    fn read_union(
        &mut self,
        name: &'static str,
        ty: Ty,
    ) -> Result<(&'static str, Alternative), Error> {
        R::read_union(self, name, ty)
    }

    fn read_option<T: ConfinedDecode>(&mut self) -> Result<Option<T>, Error> {
        R::read_option(self)
    }

    fn read_byte_array<const LEN: usize>(
        &mut self,
    ) -> Result<[u8; LEN], Error> {
        R::read_byte_array(self)
    }

    fn read_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<u8>, MIN, MAX>, Error> {
        R::read_bytes(self)
    }

    fn read_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<AsciiString, MIN, MAX>, Error> {
        R::read_ascii(self)
    }

    fn read_string<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<String, MIN, MAX>, Error> {
        R::read_string(self)
    }

    fn read_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode,
    {
        R::read_list(self)
    }

    fn read_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeSet<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode + Hash + Ord + Debug,
    {
        R::read_set(self)
    }

    fn read_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeMap<K, V>, MIN, MAX>, Error>
    where
        K: ConfinedDecode + Hash + Ord + Debug,
        V: ConfinedDecode,
    {
        R::read_map(self)
    }

    fn read_struct(self) -> StructReader<Self> { StructReader(self) }
}

pub struct Reader<R: io::Read>(R);

impl<R: io::Read> Reader<R> {
    pub fn unbox(self) -> R { self.0 }

    fn read_len(&mut self, max: usize) -> Result<usize, Error> {
        assert!(
            max <= u16::MAX as usize,
            "confinement size must be below u16::MAX"
        );
        if max <= u8::MAX as usize {
            Ok(self.read_u8()? as usize)
        } else {
            Ok(self.read_u16()? as usize)
        }
    }
}

impl<R: io::Read> From<R> for Reader<R> {
    fn from(reader: R) -> Self { Self(reader) }
}

macro_rules! read_num {
    ($ty:ty, $name:ident) => {
        fn $name(&mut self) -> Result<$ty, Error> {
            let mut buf = [0u8; <$ty>::BITS as usize / 8];
            self.0.read_exact(&mut buf)?;
            Ok(<$ty>::from_le_bytes(buf))
        }
    };
}

macro_rules! read_float {
    ($ty:ident, $name:ident) => {
        fn $name(&mut self) -> Result<$ty, Error> {
            let mut buf = [0u8; 32];
            self.0.read_exact(&mut buf[..($ty::BITS as usize / 8)])?;
            // Constructing inner representation
            let inner = u256::from_le_bytes(buf);
            Ok(<$ty>::from_bits(inner))
        }
    };
}

impl<R: io::Read> ConfinedRead for Reader<R> {
    fn step_in(&mut self, _step: Step) {}

    fn step_out(&mut self) {}

    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut buf = [0u8; 1];
        self.0.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    read_num!(u16, read_u16);
    read_num!(u24, read_u24);
    read_num!(u32, read_u32);
    read_num!(u64, read_u64);
    read_num!(u128, read_u128);
    read_num!(u256, read_u256);
    read_num!(u512, read_u512);
    read_num!(u1024, read_u1024);

    read_num!(i8, read_i8);
    read_num!(i16, read_i16);
    read_num!(i32, read_i32);
    read_num!(i64, read_i64);
    read_num!(i128, read_i128);
    read_num!(i256, read_i256);
    read_num!(i512, read_i512);
    read_num!(i1024, read_i1024);

    fn read_f16b(&mut self) -> Result<bf16, Error> {
        let mut buf = [0u8; 2];
        self.0.read_exact(&mut buf)?;
        Ok(bf16::from_le_bytes(buf))
    }

    read_float!(Half, read_f16);
    read_float!(Single, read_f32);
    read_float!(Double, read_f64);
    read_float!(X87DoubleExtended, read_f80);
    read_float!(Quad, read_f128);
    read_float!(Oct, read_f256);

    fn read_enum(&mut self, name: &'static str, ty: Ty) -> Result<u8, Error> {
        let Ty::Enum(variants) = ty else {
            panic!("write_enum requires Ty::Enum type")
        };
        let val = self.read_u8()?;
        if variants
            .iter()
            .find(|variant| variant.value == val)
            .is_none()
        {
            return Err(Error::EnumValueNotKnown(name, val, variants));
        }
        Ok(val)
    }

    fn read_union(
        &mut self,
        name: &'static str,
        ty: Ty,
    ) -> Result<(&'static str, Alternative), Error> {
        let Ty::Union(ref alts) = ty else {
            panic!("write_union requires Ty::Union type")
        };

        let id = self.read_u8()?;

        let Some((name, alt)) = alts.iter().find(|(_, alt)| alt.id == id) else {
            return Err(Error::UnionValueNotKnown(name, id, alts.clone()))
        };

        Ok((name, alt.clone()))
    }

    fn read_option<T: ConfinedDecode>(&mut self) -> Result<Option<T>, Error> {
        let ty = Option::<T>::confined_type();
        match self
            .read_union(stringify!("Option<", T::TYPE_NAME, ">"), ty)?
            .0
        {
            "Some" => T::confined_decode(self).map(Some),
            "None" => Ok(None),
            _ => unreachable!(),
        }
    }

    fn read_byte_array<const LEN: usize>(
        &mut self,
    ) -> Result<[u8; LEN], Error> {
        debug_assert!(
            LEN < u16::MAX as usize,
            "only arrays under u16::MAX are allowed"
        );
        let mut array = [0u8; LEN];
        self.0.read_exact(&mut array)?;
        Ok(array)
    }

    fn read_bytes<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<u8>, MIN, MAX>, Error> {
        let len = self.read_len(MAX)?;
        let mut buf = vec![0u8; len];
        self.0.read_exact(&mut buf)?;
        Confined::try_from(buf).map_err(Error::from)
    }

    fn read_ascii<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<AsciiString, MIN, MAX>, Error> {
        let len = self.read_len(MAX)?;
        let mut buf = vec![0u8; len];
        self.0.read_exact(&mut buf)?;
        let s = AsciiString::from_ascii(buf)?;
        Confined::try_from(s).map_err(Error::from)
    }

    fn read_string<const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<String, MIN, MAX>, Error> {
        let len = self.read_len(MAX)?;
        let mut buf = vec![0u8; len];
        self.0.read_exact(&mut buf)?;
        let s = String::from_utf8(buf)?;
        Confined::try_from(s).map_err(Error::from)
    }

    fn read_list<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<Vec<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode,
    {
        let len = self.read_len(MAX)?;
        let mut vec = Vec::<T>::with_capacity(len);
        for _ in 0..len {
            vec.push(T::confined_decode(&mut *self)?);
        }
        Confined::try_from(vec).map_err(Error::from)
    }

    fn read_set<T, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeSet<T>, MIN, MAX>, Error>
    where
        T: ConfinedDecode + Hash + Ord + Debug,
    {
        let len = self.read_len(MAX)?;
        let mut set = BTreeSet::<T>::new();
        for _ in 0..len {
            let val = T::confined_decode(&mut *self)?;
            if let Some(max) = set.iter().max() {
                if max > &val {
                    return Err(Error::BrokenOrder(
                        format!("{:?}", val),
                        format!("{:?}", max),
                    ));
                }
            }
            if set.contains(&val) {
                return Err(Error::RepeatedValue(format!("{:?}", val)));
            }
            set.insert(val);
        }
        Confined::try_from(set).map_err(Error::from)
    }

    fn read_map<K, V, const MIN: usize, const MAX: usize>(
        &mut self,
    ) -> Result<Confined<BTreeMap<K, V>, MIN, MAX>, Error>
    where
        K: ConfinedDecode + Hash + Ord + Debug,
        V: ConfinedDecode,
    {
        let len = self.read_len(MAX)?;
        let mut map = BTreeMap::<K, V>::new();
        for _ in 0..len {
            let key = K::confined_decode(&mut *self)?;
            let val = V::confined_decode(&mut *self)?;
            if let Some(max) = map.keys().max() {
                if max > &key {
                    return Err(Error::BrokenOrder(
                        format!("{:?}", key),
                        format!("{:?}", max),
                    ));
                }
            }
            if map.contains_key(&key) {
                return Err(Error::RepeatedValue(format!("{:?}", key)));
            }
            map.insert(key, val);
        }
        Confined::try_from(map).map_err(Error::from)
    }

    fn read_struct(self) -> StructReader<Self> { StructReader(self) }
}

pub struct StructReader<R: ConfinedRead>(R);

impl<R: ConfinedRead> StructReader<R> {
    pub fn start(reader: R) -> Self { StructReader(reader) }

    pub fn field<T: ConfinedDecode>(
        &mut self,
        name: &'static str,
    ) -> Result<T, Error> {
        self.0.step_in(Step::Field(name));
        let field = T::confined_decode(&mut self.0)?;
        self.0.step_out();
        Ok(field)
    }

    pub fn finish(self) -> R {
        // Do nothing
        self.0
    }
}
