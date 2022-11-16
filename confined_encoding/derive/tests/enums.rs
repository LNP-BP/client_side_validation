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
extern crate confined_encoding_test;

mod common;

use common::Result;
use confined_encoding_test::test_encoding_roundtrip;

#[test]
fn enum_associated_types() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    struct Heap(Box<[u8]>);

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    enum Hi {
        /// Docstring
        First(u8),
        Second(Heap),
        Third,
        Fourth {
            heap: Heap,
        },
        #[confined_encoding(value = 7)]
        Seventh,
    }

    let heap = Heap(Box::from([0xA1, 0xA2]));
    test_encoding_roundtrip(&Hi::First(0xC8), [0x00, 0xC8])?;
    test_encoding_roundtrip(&Hi::Second(heap.clone()), [
        0x01, 0x02, 0x00, 0xA1, 0xA2,
    ])?;
    test_encoding_roundtrip(&Hi::Third, [0x02])?;
    test_encoding_roundtrip(&Hi::Fourth { heap }, [
        0x03, 0x02, 0x00, 0xA1, 0xA2,
    ])?;
    test_encoding_roundtrip(&Hi::Seventh, [0x07])?;

    Ok(())
}

#[test]
fn enum_default_values() -> Result {
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, Display)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[repr(u16)]
    #[display(Debug)]
    enum ContractType {
        Bit8 = 1,
        Bit16 = 2,
        Bit32 = 4,
        Bit64 = 8,
    }

    test_encoding_roundtrip(&ContractType::Bit8, [0x00])?;
    test_encoding_roundtrip(&ContractType::Bit16, [0x01])?;
    test_encoding_roundtrip(&ContractType::Bit32, [0x02])?;
    test_encoding_roundtrip(&ContractType::Bit64, [0x03])?;

    Ok(())
}

#[test]
fn enum_repr() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(by_order, repr = u16)]
    #[repr(u16)]
    enum U16 {
        Bit8 = 1,
        Bit16 = 2,
        Bit32 = 4,
        Bit64 = 8,
    }

    test_encoding_roundtrip(&U16::Bit8, [0x00, 0x00])?;
    test_encoding_roundtrip(&U16::Bit16, [0x01, 0x00])?;
    test_encoding_roundtrip(&U16::Bit32, [0x02, 0x00])?;
    test_encoding_roundtrip(&U16::Bit64, [0x03, 0x00])?;

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(by_order, repr = u8)]
    #[repr(u16)]
    enum ByOrder {
        Bit8 = 1,
        Bit16 = 2,
        Bit32 = 4,
        Bit64 = 8,
    }

    test_encoding_roundtrip(&ByOrder::Bit8, [0x00])?;
    test_encoding_roundtrip(&ByOrder::Bit16, [0x01])?;
    test_encoding_roundtrip(&ByOrder::Bit32, [0x02])?;
    test_encoding_roundtrip(&ByOrder::Bit64, [0x03])?;

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(by_value)]
    #[repr(u8)]
    enum ByValue {
        Bit8 = 1,
        Bit16 = 2,
        Bit32 = 4,
        Bit64 = 8,
    }

    test_encoding_roundtrip(&ByValue::Bit8, [0x01])?;
    test_encoding_roundtrip(&ByValue::Bit16, [0x02])?;
    test_encoding_roundtrip(&ByValue::Bit32, [0x04])?;
    test_encoding_roundtrip(&ByValue::Bit64, [0x08])?;

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(by_value)]
    #[repr(u16)]
    enum ByValue16 {
        Bit8 = 1,
        Bit16 = 2,
        Bit32 = 4,
        Bit64 = 8,
    }

    test_encoding_roundtrip(&ByValue16::Bit8, [0x01])?;
    test_encoding_roundtrip(&ByValue16::Bit16, [0x02])?;
    test_encoding_roundtrip(&ByValue16::Bit32, [0x04])?;
    test_encoding_roundtrip(&ByValue16::Bit64, [0x08])?;

    Ok(())
}

#[test]
fn enum_custom_values() -> Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(ConfinedEncode, ConfinedDecode)]
    #[confined_encoding(by_value)]
    #[repr(u8)]
    enum CustomValues {
        Bit8 = 1,

        #[confined_encoding(value = 11)]
        Bit16 = 2,

        #[confined_encoding(value = 12)]
        Bit32 = 4,

        #[confined_encoding(value = 13)]
        Bit64 = 8,
    }

    test_encoding_roundtrip(&CustomValues::Bit8, [1])?;
    test_encoding_roundtrip(&CustomValues::Bit16, [11])?;
    test_encoding_roundtrip(&CustomValues::Bit32, [12])?;
    test_encoding_roundtrip(&CustomValues::Bit64, [13])?;

    Ok(())
}
