// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
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

#![allow(dead_code)]

#[macro_use]
extern crate strict_encoding_derive;

use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(by_value, repr = u16)]
enum Feature {
    #[strict_encoding(value = 0b0000_0000_0000_0001)]
    PermanentConnection,

    #[strict_encoding(value = 0b0000_0001_0000_0000)]
    ProtocolV2,
}

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Default)]
#[derive(NetworkEncode, NetworkDecode)]
struct Stamp {
    quality: u8,
}

impl Stamp {
    pub fn iter(&self) -> Stamp { *self }
}

// We need TLV type to implement iterator, such we know whether it has value or
// not
impl Iterator for Stamp {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if *self == Self::default() {
            None
        } else {
            Some(self.quality)
        }
    }
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(NetworkEncode, NetworkDecode)]
#[network_encoding(use_tlv)]
struct Document {
    pub name: String,

    pub description: String,

    #[network_encoding(tlv = 0x0101)]
    pub signature: Vec<u8>,

    #[network_encoding(tlv = 0x0201)]
    pub stamp: Stamp,

    #[network_encoding(unknown_tlvs)]
    pub extra_fields: BTreeMap<usize, Box<[u8]>>,

    #[network_encoding(skip)]
    pub internal_use: Vec<u8>,
}

#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[derive(NetworkEncode, NetworkDecode)]
enum ProtocolMessages {
    Init {
        source: String,
        destination: String,
        features: BTreeSet<Feature>,
    },

    Ping,

    Send(Document),
}

fn main() {
    /*
    impl strict_encoding::StrictDecode for TlvDefault {
        #[inline]
        fn strict_decode<D: ::std::io::Read>(
            mut d: D,
        ) -> ::core::result::Result<Self, strict_encoding::Error> {
            use strict_encoding::StrictDecode;
            let mut s = TlvDefault {
                fixed: strict_encoding::StrictDecode::strict_decode(&mut d)?,
                tlv: Default::default(),
            };
            let tlvs = BTreeMap::<usize, Box<[u8]>>::strict_decode(&mut d)?;
            for (type_no, bytes) in tlvs {
                match type_no {
                    48879usize => {
                        s.tlv =
                            strict_encoding::StrictDecode::strict_deserialize(
                                bytes,
                            )?
                    }
                    _ if type_no % 2 == 0 => {
                        return Err(strict_encoding::TlvError::UnknownEvenType(
                            type_no,
                        )
                        .into())
                    }
                    _ => {}
                }
            }
            Ok(s)
        }
    }
     */
}
