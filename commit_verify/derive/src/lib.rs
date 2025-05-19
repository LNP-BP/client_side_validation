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
#![recursion_limit = "256"]

//! Derivation macros for commit encoding. To learn more about the strict
//! commit please check `commit_verify` crate.
//!
//! # Derivation macros
//!
//! Library exports derivation macros `#[derive(`[`CommitEncode`]`)]`,
//! which can be added on top of any structure you'd like to support commitment
//! encoding.
//!
//! Encoding/decoding implemented by both of these macros may be configured at
//! type and individual field level using `#[commit_encode(...)]` attributes.
//!
//! # Attribute
//!
//! [`CommitEncode`] behavior can be customized with `#[commit_encoding(...)]`
//! attribute, which accepts different arguments depending to which part of the
//! data type it is applied.
//!
//! ## Attribute arguments at type declaration level
//!
//! Derivation macros accept `#[commit_encoding()]` attribute with the following
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
