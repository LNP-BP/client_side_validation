// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed in 2019-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
// Written in 2024-2025 by Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association, Switzerland.
// Copyright (C) 2024-2025 LNP/BP Laboratories,
//                         Institute for Distributed and Cognitive Systems
// (InDCS), Switzerland. Copyright (C) 2019-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Coding conventions
#![deny(
    unsafe_code,
    dead_code,
    missing_docs,
    unused_variables,
    unused_mut,
    unused_imports,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

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
//! mistakes within particular implementations of this paradigm by
//! standardizing typical workflow processes in the form of interfaces that
//! will be nearly impossible to use in the wrong way.

/// Re-export of `commit_verify` crate.
pub extern crate commit_verify as commit;
/// Re-export of `single_use_seals` crate.
pub extern crate single_use_seals as seals;

#[cfg(feature = "serde")]
#[macro_use]
extern crate serde;

mod api;

pub use api::{
    ClientData, ClientSideValidate, SealIssue, SealResolver, Status, ValidationFailure,
    ValidationLog, ValidationReport, Validity,
};
