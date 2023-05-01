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
#![recursion_limit = "256"]

//! Derivation macros for strict encoding. To learn more about the strict
//! encoding please check `strict_encoding` crate.
//!
//! # Derivation macros
//!
//! Library exports derivation macros `#[derive(`[`StrictEncode`]`)]`,
//! `#[derive(`[`StrictDecode`]`)]`, which can be added on top of any structure
//! you'd like to support string encoding (see Example section below).
//!
//! Encoding/decoding implemented by both of these macros may be configured at
//! type and individual field level using `#[strict_type(...)]` attributes.
//!
//! # Attribute
//!
//! [`StrictEncode`] and [`StrictDecode`] behavior can be customized with
//! `#[strict_encoding(...)]` attribute, which accepts different arguments
//! depending to which part of the data type it is applied.
//!
//! ## Attribute arguments at type declaration level
//!
//! Derivation macros accept `#[strict_encoding()]` attribute with the following
//! arguments:

#[macro_use]
extern crate quote;
extern crate proc_macro;
#[macro_use]
extern crate syn;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate amplify_syn;

pub(crate) mod params;
mod derive;

use proc_macro::TokenStream;
use syn::DeriveInput;

use crate::params::CommitDerive;

/// Derives [`CommitEncode`] implementation for the type.
#[proc_macro_derive(CommitEncode, attributes(commit_encode))]
pub fn derive_commit_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    CommitDerive::try_from(derive_input)
        .and_then(|engine| engine.derive_encode())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
