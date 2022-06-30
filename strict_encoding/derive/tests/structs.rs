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
extern crate strict_encoding_test;

mod common;

use common::Result;
use strict_encoding_test::test_encoding_roundtrip;

#[test]
fn struct_numbered_fields() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictEncode, StrictDecode)]
    struct NumberedFields(u8, String);

    let fields = NumberedFields(7, s!("some"));
    test_encoding_roundtrip(&fields, [
        0x07, 0x04, 0x00, b's', b'o', b'm', b'e',
    ])?;

    Ok(())
}
