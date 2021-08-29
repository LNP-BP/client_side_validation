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

use std::collections::BTreeMap;

#[derive(StrictEncode, StrictDecode)]
struct Me(u8);

#[derive(NetworkEncode, NetworkDecode)]
#[network_encoding(use_tlv)]
struct One {
    field_a: Vec<u8>,

    #[network_encoding(tlv = 1)]
    tlv_int: Option<u16>,

    #[network_encoding(tlv = 2)]
    tlv_int2: Option<u16>,

    #[network_encoding(unknown_tlvs)]
    rest_of_tlvs: BTreeMap<usize, Box<[u8]>>,
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
