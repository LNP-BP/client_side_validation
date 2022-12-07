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

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate confined_encoding_test;

mod common;

use amplify::confinement::TinyString;
use common::{compile_test, Error, Result};
use confined_encoding::{ConfinedDecode, ConfinedEncode};
use confined_encoding_test::test_encoding_roundtrip;

#[test]
#[should_panic]
fn no_confined_units() { compile_test("basics-failures/no_confined_units"); }

#[test]
#[should_panic]
fn no_networking_unions() {
    compile_test("basics-failures/no_networking_unions");
}

#[test]
#[should_panic]
fn confined_network_exclusivity() {
    compile_test("basics-failures/confined_network_exclusivity");
}

#[test]
#[should_panic]
fn no_unit_types() { compile_test("basics-failures/no_unit_types"); }

#[test]
#[should_panic]
fn no_empty_types() { compile_test("basics-failures/no_empty_types"); }

#[test]
fn unit_struct() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    struct Strict(u16);
    test_encoding_roundtrip(&Strict(0xcafe), [0xFE, 0xCA])?;

    Ok(())
}

#[test]
fn skipping() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    struct Skipping {
        pub data: TinyString,

        // This will initialize the field upon decoding with Option::default()
        // value
        #[confined_encoding(skip)]
        pub ephemeral: bool,
    }

    test_encoding_roundtrip(
        &Skipping {
            data: TinyString::try_from(s!("String")).unwrap(),
            ephemeral: false,
        },
        [0x06, 0x00, b'S', b't', b'r', b'i', b'n', b'g'],
    )
    .map_err(Error::from)
}

#[test]
fn custom_crate() {
    use confined_encoding as custom_crate;

    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(crate = custom_crate)]
    struct One {
        a: u8,
    }
}

#[test]
fn generics() {
    #[derive(ConfinedEncode, ConfinedDecode)]
    enum CustomErr1<Err>
    where
        Err: std::error::Error + ConfinedEncode + ConfinedDecode,
    {
        Other(Err),
    }
}
