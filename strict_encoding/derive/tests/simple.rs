#![allow(dead_code)]

#[macro_use]
extern crate strict_encoding_derive;

use std::collections::BTreeMap;

#[derive(StrictEncode, StrictDecode)]
struct Me(u8);

#[derive(StrictEncode, StrictDecode)]
#[strict_encoding(use_tlv)]
struct One {
    field_a: Vec<u8>,

    #[strict_encoding(tlv = 1)]
    tlv_int: Option<u16>,

    #[strict_encoding(unknown_tlvs)]
    rest_of_tlvs: BTreeMap<u16, Box<[u8]>>,
}

#[derive(StrictEncode, StrictDecode)]
struct Heap(Box<[u8]>);

#[derive(StrictEncode, StrictDecode)]
struct You {
    //    a: (),
    b: Vec<u8>,
}

#[derive(StrictEncode, StrictDecode)]
struct Other {
    //    a: (),
    b: u8,
}

fn main() {}
