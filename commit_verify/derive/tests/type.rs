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

// Caused by an imperfection of rust compiler in parsing proc macro args
#![allow(unused_braces)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding_derive;

mod common;

use strict_encoding::{
    tn, StrictDeserialize, StrictSerialize, StrictStruct, StrictSum, StrictType,
};

const TEST_LIB: &str = "TestLib";

#[test]
fn lib_name() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB)]
    struct OtherName(u16);

    assert_eq!(OtherName::STRICT_LIB_NAME, TEST_LIB);

    Ok(())
}

#[test]
fn rename_type() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB, rename = "ShortLen")]
    struct OtherName(u16);

    assert_eq!(OtherName::STRICT_LIB_NAME, TEST_LIB);
    assert_eq!(OtherName::strict_name().unwrap(), tn!("ShortLen"));

    Ok(())
}

#[test]
fn fields() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB)]
    struct Struct {
        must_camelize: u8,
    }

    assert_eq!(Struct::ALL_FIELDS, &["mustCamelize"]);

    Ok(())
}

#[test]
fn variants() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    enum Enum {
        #[default]
        MustCamelize,
    }

    #[allow(unused_braces)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = { Assoc::MustCamelize { field: 0 } })]
    enum Assoc {
        MustCamelize { field: u8 },
    }

    assert_eq!(Enum::ALL_VARIANTS, &[(0, "mustCamelize")]);
    assert_eq!(Assoc::ALL_VARIANTS, &[(0, "mustCamelize")]);

    Ok(())
}

#[test]
fn rename_field() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB)]
    struct Struct {
        must_camelize: u8,

        #[strict_type(rename = "correctName")]
        wrong_name: u8,
    }

    assert_eq!(Struct::ALL_FIELDS, &["mustCamelize", "correctName"]);

    Ok(())
}

#[test]
fn skip_field() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    struct Struct {
        must_camelize: u8,

        #[strict_type(skip)]
        wrong_name: u8,
    }
    impl StrictSerialize for Struct {}
    impl StrictDeserialize for Struct {}

    assert_eq!(Struct::ALL_FIELDS, &["mustCamelize"]);

    let val = Struct {
        must_camelize: 2,
        wrong_name: 3,
    };
    assert_eq!(
        val.to_strict_serialized::<{ usize::MAX }>()
            .unwrap()
            .as_slice(),
        &[2]
    );
    let val = Struct {
        must_camelize: 2,
        wrong_name: 0,
    };
    assert_eq!(Struct::from_strict_serialized(small_vec![2]).unwrap(), val);

    Ok(())
}

#[test]
fn rename_variant() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    enum Enum {
        #[default]
        MustCamelize,

        #[strict_type(rename = "correctName")]
        WrongName,
    }

    assert_eq!(Enum::ALL_VARIANTS, &[(0, "mustCamelize"), (1, "correctName")]);

    Ok(())
}
