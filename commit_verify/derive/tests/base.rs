// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2023 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2023 LNP/BP Standards Association. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding_derive;

mod common;

use std::convert::Infallible;

use strict_encoding::{
    tn, StrictDecode, StrictDumb, StrictEncode, StrictSerialize, StrictSum, VariantError,
};

const TEST_LIB: &str = "TestLib";

#[test]
fn wrapper_base() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct ShortLen(u16);

    Ok(())
}

#[test]
fn tuple_base() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct TaggedInfo(u16, u64);

    Ok(())
}

#[test]
fn tuple_generics() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct Pair<
        A: StrictDumb + StrictEncode + StrictDecode,
        B: StrictDumb + StrictEncode + StrictDecode,
    >(A, B);

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct WhereConstraint<A: TryInto<u8>, B: From<String>>(A, B)
    where
        A: StrictDumb + StrictEncode + StrictDecode + From<u8>,
        <A as TryFrom<u8>>::Error: From<Infallible>,
        B: StrictDumb + StrictEncode + StrictDecode;

    Ok(())
}

#[test]
fn struct_generics() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct Field<V: StrictEncode + StrictDecode + StrictDumb> {
        tag: u8,
        value: V,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode)]
    #[strict_type(lib = TEST_LIB)]
    struct ComplexField<'a, V: StrictEncode + StrictDumb>
    where
        for<'b> V: From<&'b str>,
        &'a V: Default,
    {
        tag: u8,
        value: &'a V,
    }

    Ok(())
}

#[test]
fn enum_ord() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[repr(u8)]
    enum Variants {
        #[strict_type(dumb)]
        One = 5,
        Two = 6,
        Three = 7,
    }

    assert_eq!(Variants::Three as u8, 7);
    assert_eq!(u8::from(Variants::Three), 7);
    assert_eq!(Variants::try_from(6), Ok(Variants::Two));
    assert_eq!(Variants::try_from(3), Err(VariantError(Some(tn!("Variants")), 3)));

    Ok(())
}

#[test]
fn enum_repr() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[repr(u16)]
    enum Cls {
        One = 1,
        #[strict_type(dumb)]
        Two,
        Three,
    }

    assert_eq!(u8::from(Cls::Three), 3);
    assert_eq!(Cls::try_from(2), Ok(Cls::Two));
    assert_eq!(Cls::try_from(4), Err(VariantError(Some(tn!("Cls")), 4)));

    Ok(())
}

#[test]
fn enum_associated() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    enum Assoc {
        One {
            hash: [u8; 32],
            ord: u8,
        },
        Two(u8, u16, u32),
        #[strict_type(dumb)]
        Three,
        Four(),
        Five {},
    }

    assert_eq!(Assoc::ALL_VARIANTS, &[
        (0, "one"),
        (1, "two"),
        (2, "three"),
        (3, "four"),
        (4, "five")
    ]);

    Ok(())
}

#[test]
fn enum_custom_tags() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    enum Assoc {
        One {
            hash: [u8; 32],
            ord: u8,
        },
        #[strict_type(tag = 2)]
        Two(u8, u16, u32),
        #[strict_type(dumb, tag = 3)]
        Three,
        #[strict_type(tag = 4)]
        Four(),
        #[strict_type(tag = 5)]
        Five {},
    }

    impl StrictSerialize for Assoc {}

    assert_eq!(Assoc::ALL_VARIANTS, &[
        (0, "one"),
        (2, "two"),
        (3, "three"),
        (4, "four"),
        (5, "five")
    ]);

    let assoc = Assoc::Two(0, 1, 2);
    assert_eq!(assoc.to_strict_serialized::<256>().unwrap().as_slice(), &[2, 0, 1, 0, 2, 0, 0, 0]);

    let assoc = Assoc::One {
        hash: [0u8; 32],
        ord: 0,
    };
    assert_eq!(assoc.to_strict_serialized::<256>().unwrap().as_slice(), &[0u8; 34]);

    Ok(())
}
