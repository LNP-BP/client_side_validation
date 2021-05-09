// LNP/BP client-side-validation library implementig respective LNPBP
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

#![recursion_limit = "256"]
#![cfg_attr(test, deny(warnings))]

extern crate proc_macro;
#[macro_use]
extern crate amplify;
#[macro_use]
extern crate quote;
#[macro_use]
extern crate syn;

mod decode;
mod encode;
mod param;

use proc_macro::TokenStream;
use syn::DeriveInput;

pub(crate) const ATTR_NAME: &str = "strict_encoding";

#[proc_macro_derive(StrictEncode, attributes(strict_encoding))]
pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    encode::encode_derive(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

#[proc_macro_derive(StrictDecode, attributes(strict_encoding))]
pub fn derive_strict_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    decode::decode_derive(derive_input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
