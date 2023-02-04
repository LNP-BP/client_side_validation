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

// Coding conventions
#![deny(
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    unused_mut,
    unused_imports,
    dead_code,
    missing_docs
)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

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
    ClientData, ClientSideValidate, SealIssue, SealResolver, Status, ValidationFailure,
    ValidationLog, ValidationReport, Validity,
};
// pub use commit_verify::{commit_encode, lnpbp4, merkle, tagged_hash};
