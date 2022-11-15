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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate confined_encoding_derive;
#[macro_use]
extern crate confined_encoding_test;

mod common;
use std::collections::BTreeMap;

use common::{compile_test, Error, Result};
use confined_encoding::{strict_deserialize, StrictDecode};
use confined_encoding_test::test_encoding_roundtrip;

pub mod internet2 {
    pub mod tlv {
        use std::collections::BTreeMap;
        use std::io::{Read, Write};

        use amplify::Wrapper;
        use confined_encoding::Error;

        /// TLV type field value
        #[derive(
            Wrapper, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash,
            Default, Debug, Display, From
        )]
        #[derive(StrictEncode, StrictDecode)]
        #[display(inner)]
        #[wrapper(LowerHex, UpperHex, Octal, FromStr)]
        pub struct Type(u64);

        impl From<usize> for Type {
            fn from(val: usize) -> Self { Type(val as u64) }
        }

        /// Unknown TLV record represented by raw bytes
        #[derive(
            Wrapper, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default,
            Debug, From
        )]
        #[derive(StrictEncode, StrictDecode)]
        pub struct RawValue(Box<[u8]>);

        impl AsRef<[u8]> for RawValue {
            #[inline]
            fn as_ref(&self) -> &[u8] { self.0.as_ref() }
        }

        #[derive(
            Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug, Default, From
        )]
        pub struct Stream(#[from] BTreeMap<Type, RawValue>);

        impl confined_encoding::StrictEncode for Stream {
            fn strict_encode<E: Write>(&self, e: E) -> Result<usize, Error> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                self.0.strict_encode(e)
            }
        }

        impl confined_encoding::StrictDecode for Stream {
            fn strict_decode<D: Read>(d: D) -> Result<Self, Error> {
                match BTreeMap::strict_decode(d) {
                    Ok(data) => Ok(Self(data)),
                    Err(confined_encoding::Error::Io(_)) => Ok(Self::default()),
                    Err(err) => Err(err),
                }
            }
        }

        impl<'a> IntoIterator for &'a Stream {
            type Item = (&'a Type, &'a RawValue);
            type IntoIter =
                std::collections::btree_map::Iter<'a, Type, RawValue>;
            #[inline]
            fn into_iter(self) -> Self::IntoIter { self.0.iter() }
        }
        impl IntoIterator for Stream {
            type Item = (Type, RawValue);
            type IntoIter =
                std::collections::btree_map::IntoIter<Type, RawValue>;
            #[inline]
            fn into_iter(self) -> Self::IntoIter { self.0.into_iter() }
        }

        impl Stream {
            #[inline]
            pub fn new() -> Self { Self::default() }

            #[inline]
            pub fn get(&self, type_id: &Type) -> Option<&RawValue> {
                self.0.get(type_id)
            }

            #[inline]
            pub fn insert(
                &mut self,
                type_id: Type,
                value: impl AsRef<[u8]>,
            ) -> bool {
                self.0
                    .insert(type_id, RawValue::from(Box::from(value.as_ref())))
                    .is_none()
            }

            #[inline]
            pub fn contains_key(&self, type_id: &Type) -> bool {
                self.0.contains_key(type_id)
            }

            #[inline]
            pub fn len(&self) -> usize { self.0.len() }

            #[inline]
            pub fn is_empty(&self) -> bool { self.0.is_empty() }
        }
    }
}

#[test]
#[should_panic]
fn tlv_no_strict() { compile_test("tlv-failures/no_strict"); }

#[test]
#[should_panic]
fn tlv_no_enums() { compile_test("tlv-failures/no_enums"); }

#[test]
#[should_panic]
fn tlv_no_unions() { compile_test("tlv-failures/no_unions"); }

#[test]
#[should_panic]
fn tlv_non_u16_type() { compile_test("tlv-failures/tlv_non_u16_type"); }

#[test]
#[should_panic]
fn tlv_undeclared() { compile_test("tlv-failures/tlv_undeclared"); }

const TLV_U32: u32 = 0xDEADCAFE;
macro_rules! tlv_u32 {
    () => {
        [
            // Count of TLV elements:
            0x01, 0x00, //
            // Type field:
            0xEF, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            // Length:
            0x04, 0x00, //
            // Value field:
            0xFE, 0xCA, 0xAD, 0xDE,
        ]
    };
}

#[test]
fn tlv_optional() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct Tlv {
        fixed: u8,

        #[network_encoding(tlv = 0xBEEF)]
        tlv: Option<u32>,
    }

    test_encoding_roundtrip(
        &Tlv {
            fixed: 0xDD,
            tlv: None,
        },
        [0xDD],
    )?;
    test_encoding_roundtrip(
        &Tlv {
            fixed: 0xDD,
            tlv: Some(TLV_U32),
        },
        vec![0xDD]
            .iter()
            .chain(&tlv_u32!()[..])
            .cloned()
            .collect::<Vec<_>>(),
    )
    .map_err(Error::from)
}

#[test]
fn tlv_newtype() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct Tlv(#[network_encoding(tlv = 0xBEEF)] Option<u32>);

    test_encoding_roundtrip(&Tlv(None), [])?;
    //    println!("{:02x?}", Tlv::strict_deserialize(tlv_u32!())?);
    test_encoding_roundtrip(&Tlv(Some(TLV_U32)), tlv_u32!())
        .map_err(Error::from)
}

#[test]
fn tlv_default() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct TlvDefault {
        fixed: u8,

        #[network_encoding(tlv = 0xBEEF)]
        tlv: Vec<u8>,
    }

    test_encoding_roundtrip(&TlvDefault::default(), [0x00])?;

    test_encoding_roundtrip(
        &TlvDefault {
            fixed: 0xDD,
            tlv: TLV_U32.to_le_bytes().to_vec(),
        },
        vec![
            0xdd, // =fixed
            0x01, 0x00, // # of TLVs
            0xef, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TLV type
            0x06, 0x00, // TLV length
            0x04, 0x00, 0xfe, 0xca, 0xad, 0xde, // Value: length + vec
        ],
    )
    .map_err(Error::from)
}

#[test]
fn tlv_ordering() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct Tlv {
        #[network_encoding(tlv = 0xCAFE)]
        second: Option<u8>,

        #[network_encoding(tlv = 0xBAD)]
        first: Option<u8>,
    }

    let data = [
        // Count of TLV fields
        0x02, 0x00, //
        // First goes first
        0xAD, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
        0x01, 0x00, // length
        0xA1, // value
        // Second goes second
        0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
        0x01, 0x00, // length
        0xA2, // value
    ];
    let _: Tlv = strict_deserialize(data).unwrap();

    test_encoding_roundtrip(&Tlv::default(), [])?;
    test_encoding_roundtrip(
        &Tlv {
            second: Some(0xA2),
            first: Some(0xA1),
        },
        data,
    )?;

    // Now lets switch ordering
    Tlv::strict_deserialize([
        // Count of TLV fields
        0x02, 0x00, //
        // Second goes first
        0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
        0x01, 0x00, // length
        0xA1, // value
        // First goes second
        0xAD, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
        0x01, 0x00, // length
        0xA1, // value
    ])
    .expect_err("");

    Ok(())
}

#[test]
fn pseudo_tlv() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct Tlv {
        vec: Vec<u8>,
        unknown_tlvs: BTreeMap<usize, Box<[u8]>>,
    }

    let data1 = [0x00, 0x00, 0x00, 0x00];
    let data2 = [
        // vec:
        0x03, 0x00, 0xB1, 0xB2, 0xB3, // empty map:
        0x00, 0x00, // unknown_tlvs - auto added on top
    ];

    // Checking that the data are entirely consumed
    let _: Tlv = strict_deserialize(data1).unwrap();
    let _: Tlv = strict_deserialize(data2).unwrap();

    test_encoding_roundtrip(&Tlv::default(), data1)?;
    test_encoding_roundtrip(
        &Tlv {
            vec: vec![0xB1, 0xB2, 0xB3],
            unknown_tlvs: bmap! {},
        },
        data2,
    )
    .map_err(Error::from)
}

#[test]
fn tlv_collection() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct Tlv {
        #[network_encoding(tlv = 0xCAFE)]
        map: BTreeMap<u8, String>,

        #[network_encoding(tlv = 0xBAD)]
        vec: Vec<u8>,
    }

    test_encoding_roundtrip(&Tlv::default(), [])?;
    test_encoding_roundtrip(
        &Tlv {
            map: bmap! { 0xA1u8 => s!("First"), 0xA2u8 => s!("Second") },
            vec: vec![0xB1, 0xB2, 0xB3],
        },
        [
            // Count of TLV fields
            0x02, 0x00, //
            // First goes first
            0xAD, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
            0x05, 0x00, // length
            0x03, 0x00, 0xB1, 0xB2, 0xB3, // value
            // Second goes second
            0xFE, 0xCA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // type
            0x13, 0x00, // length
            0x02, 0x00, // value: # of map elements
            0xA1, 0x05, 0x00, b'F', b'i', b'r', b's', b't', // first entry
            0xA2, 0x06, 0x00, b'S', b'e', b'c', b'o', b'n', b'd',
        ],
    )
    .map_err(Error::from)
}

#[test]
fn tlv_unknown() -> Result {
    use internet2::tlv;

    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(NetworkEncode, NetworkDecode)]
    #[network_encoding(use_tlv)]
    struct TlvStream {
        field: Vec<u8>,

        #[network_encoding(tlv = 1)]
        tlv_int: Option<u16>,

        #[network_encoding(tlv = 2)]
        tlv_int2: Option<String>,

        #[network_encoding(unknown_tlvs)]
        rest_of_tlvs: tlv::Stream,
    }

    test_encoding_roundtrip(&TlvStream::default(), [0x00; 2])
        .map_err(Error::from)
}

// TODO: Complete TLV encoding derivation test cases:
//       - Failing on unknown even fields
//       - Failed lengths etc
