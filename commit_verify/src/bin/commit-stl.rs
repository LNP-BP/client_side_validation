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
extern crate strict_types;

use commit_verify::{mpc, LIB_NAME_COMMIT_VERIFY};
use strict_types::typelib::LibBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let lib = LibBuilder::new(libname!(LIB_NAME_COMMIT_VERIFY))
        .process::<mpc::MerkleTree>()?
        .process::<mpc::MerkleBlock>()?
        .process::<mpc::MerkleProof>()?
        .compile(none!())?;
    let id = lib.id();

    println!(
        "{{-
  Id: {id:+}
  Name: CommitVerify
  Description: Types for client-side-validation commits and verification
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}
"
    );
    println!("{lib}");
    println!("{lib:X}");

    Ok(())
}
