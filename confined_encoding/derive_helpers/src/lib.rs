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

// Coding conventions
#![recursion_limit = "256"]
#![deny(dead_code, missing_docs, warnings)]

//! Helper functions for creating encoding derive crates, like
//! `confined_encoding_derive` or `lightning_encoding_derive`.
//!
//! To create a derive crate, just use the following sample:
//!
//! ```ignore
//! extern crate proc_macro;
//! #[macro_use]
//! extern crate amplify;
//!
//! use encoding_derive_helpers::{decode_derive, encode_derive, TlvEncoding};
//! use proc_macro::TokenStream;
//! use syn::DeriveInput;
//!
//! #[proc_macro_derive(ConfinedEncode, attributes(confined_encoding))]
//! pub fn derive_confined_encode(input: TokenStream) -> TokenStream {
//!     let derive_input = parse_macro_input!(input as DeriveInput);
//!     encode_derive(
//!         "confined_encoding",
//!         ident!(confined_encoding),
//!         ident!(ConfinedEncode),
//!         ident!(confined_encode),
//!         ident!(confined_serialize),
//!         derive_input,
//!         TlvEncoding::Denied,
//!     )
//!     .unwrap_or_else(|e| e.to_compile_error())
//!     .into()
//! }
//! ```

extern crate proc_macro;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate quote;

mod decode;
mod encode;
mod param;

pub use decode::decode_derive;
pub use encode::encode_derive;
