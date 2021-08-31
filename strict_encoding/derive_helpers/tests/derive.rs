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

extern crate proc_macro;
#[macro_use]
extern crate amplify;

use encoding_derive_helpers::{decode_derive, encode_derive, TlvEncoding};
use proc_macro::TokenStream;
use syn::DeriveInput;

#[test]
fn test_custom_derivation() {
    #[proc_macro_derive(StrictEncode, attributes(strict_encoding))]
    pub fn derive_strict_encode(input: TokenStream) -> TokenStream {
        let derive_input = parse_macro_input!(input as DeriveInput);
        encode_derive(
            "strict_encoding",
            ident!(strict_encoding),
            ident!(StrictEncode),
            ident!(strict_encode),
            ident!(strict_serialize),
            derive_input,
            TlvEncoding::Denied,
        )
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
    }
}
