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

use crate::{Error, StrictDecode, StrictEncode};

impl StrictEncode for &[u8] {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        let mut len = self.len();
        // We handle oversize problems at the level of `usize` value
        // serializaton
        len += len.strict_encode(&mut e)?;
        e.write_all(self)?;
        Ok(len)
    }
}

impl<const LEN: usize> StrictEncode for [u8; LEN] {
    fn strict_encode<E: io::Write>(&self, mut e: E) -> Result<usize, Error> {
        if LEN > u16::MAX as usize {
            return Err(Error::ExceedMaxItems(LEN));
        }
        e.write_all(self)?;
        Ok(self.len())
    }
}

impl<const LEN: usize> StrictDecode for [u8; LEN] {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        if LEN > u16::MAX as usize {
            return Err(Error::ExceedMaxItems(LEN));
        }
        let mut ret = [0u8; LEN];
        d.read_exact(&mut ret)?;
        Ok(ret)
    }
}

impl StrictEncode for Box<[u8]> {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        <[u8]>::borrow(self).strict_encode(e)
    }
}

impl StrictDecode for Box<[u8]> {
    fn strict_decode<D: io::Read>(mut d: D) -> Result<Self, Error> {
        let len = usize::strict_decode(&mut d)?;
        let mut ret = vec![0u8; len];
        d.read_exact(&mut ret)?;
        Ok(ret.into_boxed_slice())
    }
}

impl<T> StrictEncode for Rc<T>
where
    T: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        T::borrow(self).strict_encode(e)
    }
}

impl<T> StrictDecode for Rc<T>
where
    T: StrictDecode,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Rc::new(T::strict_decode(d)?))
    }
}

impl<T> StrictEncode for RefCell<T>
where
    T: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.borrow().strict_encode(e)
    }
}

impl<T> StrictDecode for RefCell<T>
where
    T: StrictDecode,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(RefCell::new(T::strict_decode(d)?))
    }
}

impl<T> StrictEncode for Arc<T>
where
    T: StrictEncode,
{
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        T::borrow(self).strict_encode(e)
    }
}

impl<T> StrictDecode for Arc<T>
where
    T: StrictDecode,
{
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        Ok(Arc::new(T::strict_decode(d)?))
    }
}

impl StrictEncode for &str {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().strict_encode(e)
    }
}

impl StrictEncode for String {
    fn strict_encode<E: io::Write>(&self, e: E) -> Result<usize, Error> {
        self.as_bytes().strict_encode(e)
    }
}

impl StrictDecode for String {
    fn strict_decode<D: io::Read>(d: D) -> Result<Self, Error> {
        String::from_utf8(Vec::<u8>::strict_decode(d)?).map_err(Error::from)
    }
}

#[cfg(test)]
pub mod test {
    use crate::{strict_deserialize, strict_serialize};

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
            let r = strict_serialize(&s).unwrap();
            let p: String = strict_deserialize(r).unwrap();
            assert_eq!(s, p);
        })
    }

    #[test]
    #[should_panic(expected = "DataNotEntirelyConsumed")]
    fn test_consumation() {
        gen_strings().into_iter().for_each(|s| {
            let mut r = strict_serialize(&s).unwrap();
            r.extend_from_slice("data".as_ref());
            let _: String = strict_deserialize(r).unwrap();
        })
    }

    #[test]
    fn test_error_propagation() {
        gen_strings().into_iter().for_each(|s| {
            let r = strict_serialize(&s).unwrap();
            let p: Result<String, _> = strict_deserialize(&r[..1]);
            assert!(p.is_err());
        })
    }
}
