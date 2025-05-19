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

#![cfg_attr(coverage_nightly, feature(coverage_attribute), coverage(off))]

use std::fs;
use std::io::Write;

use commit_verify::stl::commit_verify_stl;
use commit_verify::{mpc, CommitmentLayout, MerkleNode};
use strict_types::stl::{std_stl, strict_types_stl};
use strict_types::{parse_args, SystemBuilder};

fn main() {
    let lib = commit_verify_stl();
    let (format, dir) = parse_args();
    lib.serialize(
        format,
        dir.as_ref(),
        "0.1.0",
        Some(
            "
  Description: Client-side-validation deterministic commitments
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023-2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");

    let dir = dir.unwrap_or_else(|| ".".to_owned());

    let std = std_stl();
    let st = strict_types_stl();
    let cv = commit_verify_stl();

    let sys = SystemBuilder::new()
        .import(cv)
        .unwrap()
        .import(st)
        .unwrap()
        .import(std)
        .unwrap()
        .finalize()
        .expect("not all libraries present");

    let mut file = fs::File::create(format!("{dir}/Merkle.vesper")).unwrap();
    writeln!(
        file,
        "{{-
  Description: Merklization and MPC workflows
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2024 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0
-}}

Merklization vesper lexicon=types+commitments
"
    )
    .unwrap();
    writeln!(file, "\n-- General merklization workflows\n").unwrap();
    let layout = MerkleNode::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("CommitVerify.MerkleNode").unwrap();
    writeln!(file, "{tt}").unwrap();

    writeln!(file, "\n-- Multi-protocol commitment workflows\n").unwrap();
    let layout = mpc::Leaf::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("CommitVerify.Leaf").unwrap();
    writeln!(file, "{tt}").unwrap();

    let layout = mpc::MerkleConcealed::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("CommitVerify.MerkleConcealed").unwrap();
    writeln!(file, "{tt}").unwrap();

    let layout = mpc::MerkleBlock::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("CommitVerify.MerkleBlock").unwrap();
    writeln!(file, "{tt}").unwrap();

    let layout = mpc::MerkleTree::commitment_layout();
    writeln!(file, "{layout}").unwrap();
    let tt = sys.type_tree("CommitVerify.MerkleTree").unwrap();
    writeln!(file, "{tt}").unwrap();
}
