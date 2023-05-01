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

#![allow(unused_braces)]

#[macro_use]
extern crate amplify;
#[macro_use]
extern crate strict_encoding;

mod common;

use std::convert::Infallible;

use amplify::confinement::SmallVec;
use amplify::Wrapper;
use commit_verify::merkle::MerkleNode;
use commit_verify::mpc::MERKLE_LNPBP4_TAG;
use commit_verify::{CommitEncode, Conceal};
use strict_encoding::{StrictDecode, StrictDumb, StrictEncode};

const TEST_LIB: &str = "TestLib";

fn verify_commit<T: CommitEncode>(t: T, c: impl AsRef<[u8]>) {
    let mut e = Vec::<u8>::new();
    t.commit_encode(&mut e);
    assert_eq!(e.as_slice(), c.as_ref(), "invalid commitment");
}

#[test]
fn strategy_transparent() -> common::Result {
    #[derive(Wrapper, Clone, PartialEq, Eq, Debug, From)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = transparent)]
    struct ShortLen(u16);

    verify_commit(ShortLen(0), [0, 0]);
    verify_commit(ShortLen(0xFFde), [0xde, 0xFF]);

    Ok(())
}

#[test]
fn strategy_into_u8() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = into_u8)]
    #[repr(u8)]
    enum Prim {
        A,
        B,
        C,
    }
    impl Into<u8> for Prim {
        fn into(self) -> u8 { self as u8 }
    }

    verify_commit(Prim::A, [0]);
    verify_commit(Prim::B, [1]);
    verify_commit(Prim::C, [2]);

    Ok(())
}

#[test]
fn strategy_default_tuple() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct TaggedInfo(u16, u64);

    verify_commit(TaggedInfo(0xdead, 0xbeefcafebaddafec), [
        0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe,
    ]);

    Ok(())
}

#[test]
fn strategy_commit_tuple() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = propagate)]
    struct TaggedInfo(u16, u64);

    verify_commit(TaggedInfo(0xdead, 0xbeefcafebaddafec), [
        0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe,
    ]);

    Ok(())
}

#[test]
fn strategy_strict_tuple() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict)]
    struct TaggedInfo(u16, u64);

    verify_commit(TaggedInfo(0xdead, 0xbeefcafebaddafec), [
        0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe,
    ]);

    Ok(())
}

#[test]
fn strategy_default_struct() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct TaggedInfo {
        a: u16,
        b: u64,
    }

    verify_commit(
        TaggedInfo {
            a: 0xdead,
            b: 0xbeefcafebaddafec,
        },
        [0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe],
    );

    Ok(())
}

#[test]
fn strategy_commit_struct() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = propagate)]
    struct TaggedInfo {
        a: u16,
        b: u64,
    }

    verify_commit(
        TaggedInfo {
            a: 0xdead,
            b: 0xbeefcafebaddafec,
        },
        [0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe],
    );

    Ok(())
}

#[test]
fn strategy_strict_struct() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict)]
    struct TaggedInfo {
        a: u16,
        b: u64,
    }

    verify_commit(
        TaggedInfo {
            a: 0xdead,
            b: 0xbeefcafebaddafec,
        },
        [0xad, 0xde, 0xec, 0xaf, 0xdd, 0xba, 0xfe, 0xca, 0xef, 0xbe],
    );

    Ok(())
}

#[test]
fn tuple_generics() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Pair<A: CommitEncode, B: CommitEncode + Default>(A, B);

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct WhereConstraint<A: TryInto<u8>, B: From<String>>(A, B)
    where
        A: CommitEncode + From<u8>,
        <A as TryFrom<u8>>::Error: From<Infallible>,
        B: CommitEncode + Default;

    Ok(())
}

#[test]
fn struct_generics() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Field<V: CommitEncode> {
        tag: u8,
        value: V,
    }

    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct ComplexField<'a, V: CommitEncode>
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
fn enum_repr() -> common::Result {
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = repr, into_u8, try_from_u8)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = into_u8)]
    #[repr(u16)]
    enum Cls {
        One = 1,
        #[strict_type(dumb)]
        Two,
        Three,
    }

    verify_commit(Cls::One, [1]);
    verify_commit(Cls::Two, [2]);
    verify_commit(Cls::Three, [3]);

    Ok(())
}

#[test]
fn enum_associated() -> common::Result {
    #[allow(dead_code)]
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order)]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = strict)]
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

    let mut res = vec![0; 33];
    res.extend([1]);
    verify_commit(
        Assoc::One {
            hash: default!(),
            ord: 1,
        },
        res,
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
    #[commit_encode(strategy = strict)]
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
        res,
    );

    Ok(())
}

#[test]
fn conceal() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(StrictDumb, StrictType, StrictEncode, StrictDecode)]
    #[strict_type(lib = TEST_LIB, tags = order, dumb = { Self::Concealed(0) })]
    #[derive(CommitEncode)]
    #[commit_encode(strategy = conceal_strict)]
    enum Data {
        Revealed(u128),
        Concealed(u8),
    }

    impl Conceal for Data {
        type Concealed = Self;
        fn conceal(&self) -> Self { Self::Concealed(0xde) }
    }

    verify_commit(Data::Revealed(0xcafe1234), [1, 0xde]);

    Ok(())
}

#[test]
fn skip() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Data {
        data: u8,
        #[commit_encode(skip)]
        bulletproof: Vec<u8>,
    }

    verify_commit(
        Data {
            data: 0xfe,
            bulletproof: vec![0xde, 0xad],
        },
        [0xfe],
    );

    Ok(())
}

#[test]
fn merklize() -> common::Result {
    #[derive(Clone, PartialEq, Eq, Debug)]
    #[derive(CommitEncode)]
    struct Tree {
        #[commit_encode(merklize = MERKLE_LNPBP4_TAG)]
        leaves: SmallVec<u16>,
    }

    let test_vec = small_vec!(0, 1, 2, 3);
    verify_commit(
        Tree {
            leaves: test_vec.clone(),
        },
        MerkleNode::merklize(MERKLE_LNPBP4_TAG.to_be_bytes(), &test_vec).as_slice(),
    );

    Ok(())
}
