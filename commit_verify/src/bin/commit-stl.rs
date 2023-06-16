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

use commit_verify::stl;
use strict_types::parse_args;

fn main() {
    let lib = stl::commit_verify_stl();
    let (format, dir) = parse_args();
    lib.serialize(
        format,
        dir,
        "0.1.0",
        Some(
            "
  Description: Client-side-validation deterministic commitments
  Author: Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
  Copyright (C) 2023 LNP/BP Standards Association. All rights reserved.
  License: Apache-2.0",
        ),
    )
    .expect("unable to write to the file");
}
