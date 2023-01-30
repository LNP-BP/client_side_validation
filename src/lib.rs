// LNP/BP client-side-validation foundation libraries implementing LNPBP
// specifications & standards (LNPBP-4, 7, 8, 9, 81)
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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs)]

//! The LNP/BP client-side-validation foundation libraries implementing LNPBP
//! specifications & standards (LNPBP-4, 7, 8, 9, 81).
//!
//! Defines core interfaces from LNPBP standards specifying secure and robust
//! practices via well-format APIs. Consists of the following main components:
//! * Client-side validation
//! * Cryptographic commitments and verification
//! * Single-use-seals
//! * Strict binary data serialization used by client-side validation
//!
//! The goal of this module is to maximally reduce the probability of errors and
//! mistakes within particular implementations of this paradigms by
//! standardizing typical workflow processes in a form of interfaces that
//! will be nearly impossible to use in a wrong way.

// pub extern crate commit_verify;
pub extern crate single_use_seals;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde_crate as serde;

mod api;

pub use api::{
    ClientData, ClientSideValidate, SealIssue, SealResolver, Status,
    ValidationFailure, ValidationLog, ValidationReport, Validity,
};
// pub use commit_verify::{commit_encode, lnpbp4, merkle, tagged_hash};
