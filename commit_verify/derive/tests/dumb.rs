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

mod common;

use amplify::confinement::Confined;
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode, StrictType};

const TEST_LIB: &str = "TestLib";

#[test]
fn struct_default() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB)]
    struct Field<V: StrictEncode + StrictDecode>
    where V: Default
    {
        name: u8,
        value: V,
    }

    assert_eq!(Field::<u8>::strict_dumb(), Field::<u8>::default());

    Ok(())
}

#[test]
fn enum_default() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
    #[derive(StrictType)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[repr(u8)]
    enum Variants {
        One,
        Two,
        #[default]
        Three,
    }

    assert_eq!(Variants::strict_dumb(), Variants::Three);

    Ok(())
}

#[test]
fn enum_explicit() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb)]
    #[strict_type(lib = TEST_LIB)]
    #[repr(u8)]
    enum Variants {
        One,
        Two,
        #[strict_type(dumb)]
        Three,
    }

    assert_eq!(Variants::strict_dumb(), Variants::Three);

    Ok(())
}

#[test]
fn dumb_wrapper_container() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb)]
    #[strict_type(lib = TEST_LIB, dumb = ShortLen(u16::MAX))]
    struct ShortLen(u16);

    assert_eq!(ShortLen::strict_dumb(), ShortLen(u16::MAX));
    Ok(())
}

#[test]
fn dumb_wrapper_field() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb)]
    #[strict_type(lib = TEST_LIB)]
    struct ShortLen(#[strict_type(dumb = 1)] u16);

    assert_eq!(ShortLen::strict_dumb(), ShortLen(1));
    Ok(())
}

#[test]
fn dumb_wrapper_precedence() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb)]
    #[strict_type(lib = TEST_LIB, dumb = ShortLen(u16::MAX))]
    struct ShortLen(#[strict_type(dumb = 1)] u16);

    assert_eq!(ShortLen::strict_dumb(), ShortLen(u16::MAX));
    Ok(())
}

#[test]
fn dumb_struct() -> common::Result {
    #[allow(unused_braces)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = Dumb::new())]
    struct Dumb {
        field1: u8,
        field2: u16,
    }

    impl Dumb {
        pub fn new() -> Self {
            Dumb {
                field1: 1,
                field2: 2,
            }
        }
    }

    assert_eq!(Dumb::strict_dumb(), Dumb {
        field1: 1,
        field2: 2
    });

    Ok(())
}

#[test]
fn dumb_enum_associated() -> common::Result {
    #[allow(unused_braces)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = { Assoc::Variant { field: 0 } })]
    enum Assoc {
        Variant { field: u8 },
    }

    assert_eq!(Assoc::strict_dumb(), Assoc::Variant { field: 0 });

    Ok(())
}

#[test]
fn dumb_ultra_complex() -> common::Result {
    #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, From)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, dumb = NamedFields(confined_vec!(T::strict_dumb())))]
    pub struct NamedFields<T: StrictDumb + StrictEncode + StrictDecode>(
        Confined<Vec<T>, 1, { u8::MAX as usize }>,
    );

    Ok(())
}
