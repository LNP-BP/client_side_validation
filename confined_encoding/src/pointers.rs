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

use std::borrow::Borrow;
use std::cell::RefCell;
use std::io;
use std::rc::Rc;
use std::sync::Arc;

use crate::{ConfinedDecode, ConfinedEncode, Error};

impl ConfinedEncode for &[u8] {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let mut len = self.len();
        // We handle oversize problems at the level of `usize` value
        // serializaton
        len += len.confined_encode(&mut e)?;
        e.write_all(self)?;
        Ok(len)
    }
}

impl<const LEN: usize> ConfinedEncode for [u8; LEN] {
    fn confined_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if LEN > u16::MAX as usize {
            return Err(Error::ExceedMaxItems(LEN));
        }
        e.write_all(self)?;
        Ok(self.len())
    }
}

impl<const LEN: usize> ConfinedDecode for [u8; LEN] {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        if LEN > u16::MAX as usize {
            return Err(Error::ExceedMaxItems(LEN));
        }
        let mut ret = [0u8; LEN];
        d.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl ConfinedEncode for Box<[u8]> {
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        <[u8]>::borrow(self).confined_encode(e)
    }
}

impl ConfinedDecode for Box<[u8]> {
    fn confined_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::confined_decode(&mut d)?;
        let mut ret = vec![0u8; len];
        d.read_exact(&mut ret)?;
        Ok(ret.into_boxed_slice())
    }
}

impl<T> ConfinedEncode for Rc<T>
where
    T: ConfinedEncode,
{
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        T::borrow(self).confined_encode(e)
    }
}

impl<T> ConfinedDecode for Rc<T>
where
    T: ConfinedDecode,
{
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Rc::new(T::confined_decode(d)?))
    }
}

impl<T> ConfinedEncode for RefCell<T>
where
    T: ConfinedEncode,
{
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.borrow().confined_encode(e)
    }
}

impl<T> ConfinedDecode for RefCell<T>
where
    T: ConfinedDecode,
{
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(RefCell::new(T::confined_decode(d)?))
    }
}

impl<T> ConfinedEncode for Arc<T>
where
    T: ConfinedEncode,
{
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        T::borrow(self).confined_encode(e)
    }
}

impl<T> ConfinedDecode for Arc<T>
where
    T: ConfinedDecode,
{
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Arc::new(T::confined_decode(d)?))
    }
}

impl ConfinedEncode for &str {
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().confined_encode(e)
    }
}

impl ConfinedEncode for String {
    fn confined_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().confined_encode(e)
    }
}

impl ConfinedDecode for String {
    fn confined_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::from_utf8(Vec::<u8>::confined_decode(d)?).map_err(Error::from)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{confined_deserialize, confined_serialize};

    fn gen_strings() -> Vec<&'static str> {
        vec![
            "",
            "0",
            " ",
            "A string slice (&str) is made of bytes (u8), and a byte slice \
             (&[u8]) is made of bytes, so this function converts between the \
             two.Not all byte slices are valid string slices, however: &str \
             requires that it is valid UTF-8. from_utf8() checks to ensure \
             that the bytes are valid UTF-8, and then does the conversion.",
        ]
    }

    #[test]
    fn test_encode_decode() {
        gen_strings().into_iter().for_each(|s| {
            let r = confined_serialize(&s).unwrap();
            let p: String = confined_deserialize(&r).unwrap();
            assert_eq!(s, p);
        })
    }

    #[test]
    #[should_panic(expected = "DataNotEntirelyConsumed")]
    fn test_consumation() {
        gen_strings().into_iter().for_each(|s| {
            let mut r = confined_serialize(&s).unwrap();
            r.extend_from_slice("data".as_ref());
            let _: String = confined_deserialize(&r).unwrap();
        })
    }

    #[test]
    fn test_error_propagation() {
        gen_strings().into_iter().for_each(|s| {
            let r = confined_serialize(&s).unwrap();
            let p: Result<String, _> = confined_deserialize(&r[..1]);
            assert!(p.is_err());
        })
    }
}
