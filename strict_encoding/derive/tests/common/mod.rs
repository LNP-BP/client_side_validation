// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 42, 81)
//
// Written in 2019-2021 by
//     Dr. Maxim Orlovsky <orlovsky@pandoracore.com>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the Apache 2.0 License along with this
// software. If not, see <https://opensource.org/licenses/Apache-2.0>.

extern crate compiletest_rs as compiletest;

use std::fmt::{Debug, Display, Formatter};
use std::path::PathBuf;

use strict_encoding::{StrictDecode, StrictEncode};
use strict_encoding_test::DataEncodingTestFailure;

#[allow(dead_code)]
pub fn compile_test(mode: &'static str) {
    let mut config = compiletest::Config::default();

    config.mode = mode.parse().expect("Invalid mode");
    config.src_base = PathBuf::from(format!("tests/{}", mode));
    config.link_deps(); // Populate config.target_rustcflags with dependencies on the path
    config.clean_rmeta(); // If your tests import the parent crate, this helps with E0464

    compiletest::run_tests(&config);
}

#[derive(Display)]
#[display(inner)]
pub struct Error(pub Box<dyn std::error::Error>);

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

impl<T> From<strict_encoding_test::DataEncodingTestFailure<T>> for Error
where
    T: StrictEncode + StrictDecode + PartialEq + Debug + Clone + 'static,
{
    fn from(err: DataEncodingTestFailure<T>) -> Self { Self(Box::new(err)) }
}

impl From<strict_encoding::Error> for Error {
    fn from(err: strict_encoding::Error) -> Self { Self(Box::new(err)) }
}

pub type Result = std::result::Result<(), Error>;
