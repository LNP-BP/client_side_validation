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

use strict_types::stl::std_stl;
use strict_types::{CompileError, LibBuilder, TranspileError, TypeLib, TypeObjects};

use crate::{mpc, LIB_NAME_COMMIT_VERIFY};

pub const LIB_ID_COMMIT_VERIFY: &str =
    "domino_desert_pixel_CNHdcRBXQnZULbdBJ9aCwvq4fRdFYXJJxAs7Zot4Bfcd";

fn _commit_verify_sym() -> Result<TypeObjects, TranspileError> {
    LibBuilder::new(libname!(LIB_NAME_COMMIT_VERIFY), [std_stl().to_dependency()])
        .transpile::<mpc::MerkleTree>()
        .transpile::<mpc::MerkleBlock>()
        .transpile::<mpc::MerkleProof>()
        .compile_symbols()
}
fn _commit_verify_stl() -> Result<TypeLib, CompileError> { _commit_verify_sym()?.compile() }

pub fn commit_verify_sym() -> TypeObjects {
    _commit_verify_sym().expect("invalid strict type CommitVerify library")
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
