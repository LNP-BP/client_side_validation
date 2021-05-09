// LNP/BP client-side-validation library implementing respective LNPBP
// specifications & standards (LNPBP-7, 8, 9, 42)
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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! Primitives module defines core strict interfaces from informational LNPBP
//! standards specifying secure and robust practices for function calls
//! used in main LNP/BP development paradigms:
//! * Cryptographic commitments and verification
//! * Single-use seals
//! * Client-side validation
//! * Strict binary data serialization used by client-side validation
//!
//! The goal of this module is to maximally reduce the probability of errors and
//! mistakes within particular implementations of this paradigms by
//! standartizing typical workflow processes in a form of interfaces that
//! will be nearly impossible to use in the wrong form.

pub extern crate commit_verify;
pub extern crate single_use_seals;
pub extern crate strict_encoding;

pub use commit_verify::commit_encode;
pub use commit_verify::multi_commit;
pub use commit_verify::tagged_hash;
pub use commit_verify::Slice32;
pub use strict_encoding::derive::{StrictDecode, StrictEncode};
