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

use strict_types::{CompileError, LibBuilder, TypeLib};

use crate::{mpc, MerkleHash, MerkleNode, ReservedBytes, StrictHash, LIB_NAME_COMMIT_VERIFY};

pub const LIB_ID_COMMIT_VERIFY: &str =
    "stl:TGUWcCPX-99GBEi0-tlbMxUg-1SS_~Qh-_IdYDJt-zjJ3uMI#violet-panther-herbert";

fn _commit_verify_stl() -> Result<TypeLib, CompileError> {
    LibBuilder::with(libname!(LIB_NAME_COMMIT_VERIFY), [
        strict_types::stl::std_stl().to_dependency_types()
    ])
    .transpile::<ReservedBytes<1>>()
    .transpile::<ReservedBytes<2>>()
    .transpile::<ReservedBytes<4>>()
    .transpile::<mpc::MerkleConcealed>()
    .transpile::<mpc::MerkleTree>()
    .transpile::<mpc::MerkleBlock>()
    .transpile::<mpc::MerkleProof>()
    .transpile::<mpc::Leaf>()
    .transpile::<mpc::Commitment>()
    .transpile::<MerkleNode>()
    .transpile::<MerkleHash>()
    .transpile::<StrictHash>()
    .compile()
}

pub fn commit_verify_stl() -> TypeLib {
    _commit_verify_stl().expect("invalid strict type CommitVerify library")
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn lib_id() {
        let lib = commit_verify_stl();
        assert_eq!(lib.id().to_string(), LIB_ID_COMMIT_VERIFY);
    }
}
