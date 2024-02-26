// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

#![allow(unused_braces)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod common;

use std::fmt::Display;

use amplify::{Bytes32, Wrapper};
use commit_verify::{CommitEncode, CommitId, CommitmentId, Conceal, DigestExt, Sha256};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

const TEST_LIB: &str = "TestLib";

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug, From, Display)]
#[display(inner)]
#[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
#[strict_type(lib = TEST_LIB)]
struct DumbId(
    #[from]
    #[from([u8; 32])]
    Bytes32,
);

impl CommitmentId for DumbId {
    const TAG: &'static str = "";
}

impl From<Sha256> for DumbId {
    fn from(value: Sha256) -> Self { value.finish().into() }
}

fn verify_commit<T: CommitId>(value: T, expect: &'static str)
where T::CommitmentId: Display {
    assert_eq!(&value.commit_id().to_string(), expect, "invalid commitment");
}

#[test]
fn strategy_transparent() -> common::Result {
    #[derive(Wrapper, Clone, PartialEq, Eq, Debug, From)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = transparent, id = DumbId)]
    struct ShortLen(u16);

    verify_commit(ShortLen(0), "2bb00b2f346511235882255a898a224b6858e18ebec0a11967eb51f0ed1a2ff5");
    #[allow(clippy::mixed_case_hex_literals)]
    verify_commit(
        ShortLen(0xFFde),
        "0290490b549dfcb8a222d42abf53afbd9fadcef480bc61d7a9aeaf19288b394c",
    );

    Ok(())
}

#[test]
fn strategy_strict_enum() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    #[repr(u8)]
    enum Prim {
        #[strict_type(dumb)]
        A,
        B,
        C,
    }

    verify_commit(Prim::A, "82c0f0f259e8cffecead54325fadb48f15a4e761dae5ffaf31209993eacbb24d");
    verify_commit(Prim::B, "6db0981aac502e87a0498d169599ceace4c6480a182590d47e82d63b85cb3c72");
    verify_commit(Prim::C, "e4648d71abe10c0efd626b803ac86d57b1cdc8842f6baa9799ef95cf510784b6");

    Ok(())
}

#[test]
fn strategy_strict_tuple() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    struct TaggedInfo(u16, u64);

    verify_commit(
        TaggedInfo(0xdead, 0xbeefcafebaddafec),
        "8506078e6f47e4b75470cb45a18922785f1a54ba4501473b80ba7b0c363d7490",
    );

    Ok(())
}

#[test]
fn strategy_strict_struct() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    struct TaggedInfo {
        a: u16,
        b: u64,
    }

    verify_commit(
        TaggedInfo {
            a: 0xdead,
            b: 0xbeefcafebaddafec,
        },
        "8506078e6f47e4b75470cb45a18922785f1a54ba4501473b80ba7b0c363d7490",
    );

    Ok(())
}

#[test]
fn enum_associated() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
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

    verify_commit(
        Assoc::One {
            hash: default!(),
            ord: 1,
        },
        "18cc83e934de8ad385ce41c8c9b6a2ee3331817907d6ccf8c5ba4ca3570e65a3",
    );

    Ok(())
}

#[test]
fn enum_custom_tags() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict, id = DumbId)]
    enum Assoc {
        #[strict_type(tag = 8)]
        One { hash: [u8; 32], ord: u8 },
        #[strict_type(tag = 2)]
        Two(u8, u16, u32),
        #[strict_type(dumb, tag = 3)]
        Three,
        #[strict_type(tag = 4)]
        Four(),
        #[strict_type(tag = 5)]
        Five {},
    }

    let mut res = vec![8; 33];
    res.extend([1]);
    verify_commit(
        Assoc::One {
            hash: [8; 32],
            ord: 1,
        },
        "67e6cd9574e329906d28ce7143aef7124372e04d09bd46b130445fec2baf9fc6",
    );

    Ok(())
}

#[test]
fn conceal() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = { Self::Concealed(0) })]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = conceal, id = DumbId)]
    enum Data {
        Revealed(u128),
        Concealed(u8),
    }

    impl Conceal for Data {
        type Concealed = Self;
        fn conceal(&self) -> Self { Self::Concealed(0xde) }
    }

    verify_commit(
        Data::Revealed(0xcafe1234),
        "fd5ee38918347000fc3cbf31def233b226d14a47bbc6bac18fd6389c3fd16d2e",
    );

    Ok(())
}

/* TODO: Refactor
#[test]
fn merklize() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Tree {
        #[commit_encode(merklize = MERKLE_LNPBP4_TAG)]
        leaves: SmallVec<Leaf>,
    }

    #[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Debug)]
    #[derive(CommitEncode)]
    pub struct Leaf(u16);
    impl CommitmentId for Leaf {
        const TAG: [u8; 32] = [0u8; 32];
        type Id = MerkleHash;
    }

    let test_vec = small_vec!(Leaf(0), Leaf(1), Leaf(2), Leaf(3));
    verify_commit(
        Tree {
            leaves: test_vec.clone(),
        },
        MerkleHash::merklize(&test_vec).as_slice(),
    );

    Ok(())
}
 */
