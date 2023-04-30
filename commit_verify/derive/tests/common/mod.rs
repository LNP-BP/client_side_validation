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

extern crate compiletest_rs as compiletest;

use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;

use strict_encoding::{StrictDecode, StrictEncode};
use strict_encoding_test::DataEncodingTestFailure;

#[allow(dead_code)]
pub fn compile_test(mode: &'static str) {
    let mut config = compiletest::Config {
        mode: mode.parse().expect("Invalid mode"),
        src_base: PathBuf::from(format!("tests/{}", mode)),
        ..default!()
    };
    config.link_deps();
    config.clean_rmeta();
    compiletest::run_tests(&config);
}

#[derive(Display)]
#[display(inner)]
pub struct Error(pub Box<dyn std::error::Error>);

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result { Display::fmt(self, f) }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { Some(self.0.as_ref()) }
}

impl<T> From<DataEncodingTestFailure<T>> for Error
where T: StrictEncode + StrictDecode + PartialEq + Debug + Clone + 'static
{
    fn from(err: DataEncodingTestFailure<T>) -> Self { Self(Box::new(err)) }
}

/*
impl From<strict_encoding::Error> for Error {
    fn from(err: strict_encoding::Error) -> Self { Self(Box::new(err)) }
}
*/

pub type Result = std::result::Result<(), Error>;
