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

//! Derivation macros for strict encoding. To learn more about the strict
//! encoding please check `confined_encoding` crate.
//!
//! # Derivation macros
//!
//! Library exports derivation macros `#[derive(`[`ConfinedEncode`]`)]`,
//! `#[derive(`[`ConfinedDecode`]`)]`, which can be added on top of any
//! structure you'd like to support string encoding (see Example section below).
//!
//! Encoding/decoding implemented by both of these macros may be configured at
//! type and individual field level using `#[confined_encoding(...)]` and
//! `#[network_encoding(...)]` attributes.
//!
//! The difference between strict and network encoding is in the support of
//! TLV (type-length-value) extensions: strict encoding, used for pure
//! client-side-validation, does not allow use of TLVs, while in network
//! protocol context this requirement is relaxed and specially-designed TLV
//! encoding is allowed (see sections below on how to use TLV encoding). Network
//! encoding TLV is not strictly BOLT-1 compatible; if you are looking for
//! BOLT-1 TLV implementation, please check `lightning_encoding_derive` crate.
//!
//! # Attribute
//!
//! [`ConfinedEncode`] and [`ConfinedDecode`] behavior can be customized with
//! `#[confined_encoding(...)]` attribute, which accepts different arguments
//! depending to which part of the data type it is applied.
//!
//! ## Attribute arguments at type declaration level
//!
//! Derivation macros accept `#[confined_encoding()]` attribute with the
//! following arguments:
//!
//! ### `use_tlv`
//!
//! Applies TLV extension to the data type and allows use of `tlv` and
//! `unknown_tlvs` arguments on struct fields.
//!
//! NB: TLVs work only with structures and not enums.
//!
//! ### `crate = ::path::to::confined_encoding_crate`
//!
//! Allows to specify custom path to `confined_encoding` crate
//!
//! ### `repr = <uint>`
//!
//! Can be used with enum types only.
//!
//! Specifies which unsigned integer type must represent enum variants during
//! the encoding. Possible values are `u8`, `u16`, `u32` and `u64`.
//!
//! For enum veriants without associated values defaults to `u8`, independently
//! of rust enum `#[repr(...)]` attribute value or presence (see also NB below).
//!
//! NB: This argument is not equal to the rust `#[repr(...)]` attribute, which
//! defines C FFI representation of the enum type. For their combined usage
//! pls check examples below
//!
//! ### `bu_order`/`by_velue`
//!
//! Can be used with enum types only, where they define which encoding strategy
//! should be used for representation of enum variants:
//! - `by_value` - encodes enum variants using their value representation (see
//!   `repr` above)
//! - `by_order` - encodes enum variants by their ordinal position starting from
//!   zero. Can't be combined with `by_value`.
//!
//! If neither of these two arguments is provided, the macro defaults to
//! `by_order` encoding.
//!
//!
//! ## Attribute arguments at field and enum variant level
//!
//! Derivation macros accept `#[confined_encoding()]` attribute with the
//! following arguments
//!
//! ### `skip`
//!
//! Skips field during serialization and initialize field value with
//! `Default::default()` on type deserialization.
//!
//! Allowed only for named and unnamed (tuple) structure fields and enum variant
//! associated value fields.
//!
//! ### `value = <unsigned integer>`
//!
//! Allowed only for enum variants.
//!
//! Assigns custom value for a given enum variant, overriding `by_value` and
//! `by_order` directives defined at type level and the actual variant value, if
//! any.
//!
//! NB: If the value conflicts with the values of other enum variants, taken
//! from either their assigned value (for `by_value`-encoded enums), order
//! index (for `by_order`-encoded enums) or other variant's value from with
//! explicit `value` argument the compiler will error.
//!
//! ### `tlv = <unsigned 16-bit int>`
//!
//! Sets the TLV type id for the field. The field type MUST be `Option` and
//! it must implement `Default`.
//!
//! ### `unknown_tlvs`
//!
//! Specifies structure field which will be "capture all" for unknown odd TLV
//! ids. The argument can be used only for a single field within a structure and
//! the field type must be `BTreeMap<usize, Box<[u8]>]`.
//!
//! NB: if an unknown even TLV type id is met, error is raised and the value
//! does not get into the field.
//!
//! # Examples
//!
//! ```
//! # #[macro_use] extern crate confined_encoding_derive;
//! use confined_encoding::ConfinedEncode;
//!
//! // All variants have custom values apart from the first one, which should has
//! // value = 1
//! #[derive(ConfinedEncode, ConfinedDecode)]
//! #[confined_encoding(by_value, repr = u32)]
//! #[repr(u8)]
//! enum CustomValues {
//!     Bit8 = 1,
//!
//!     #[confined_encoding(value = 0x10)]
//!     Bit16 = 2,
//!
//!     #[confined_encoding(value = 0x1000)]
//!     Bit32 = 4,
//!
//!     #[confined_encoding(value = 0x100000)]
//!     Bit64 = 8,
//! }
//!
//! assert_eq!(CustomValues::Bit8.confined_serialize(), Ok(vec![0x01, 0x00, 0x00, 0x00]));
//! assert_eq!(CustomValues::Bit16.confined_serialize(), Ok(vec![0x10, 0x00, 0x00, 0x00]));
//! assert_eq!(CustomValues::Bit32.confined_serialize(), Ok(vec![0x00, 0x10, 0x00, 0x00]));
//! assert_eq!(CustomValues::Bit64.confined_serialize(), Ok(vec![0x00, 0x00, 0x10, 0x00]));
//! ```
//!
//! ```
//! # #[macro_use] extern crate confined_encoding_derive;
//! use confined_encoding::ConfinedEncode;
//!
//! #[derive(ConfinedEncode, ConfinedDecode)]
//! #[confined_encoding(by_order, repr = u16)]
//! #[repr(u8)]
//! enum U16 {
//!     Bit8 = 1, // this will be encoded as 0x0000, since we use `by_order` here
//!     Bit16 = 2,
//!     Bit32 = 4,
//!     Bit64 = 8,
//! }
//!
//! assert_eq!(U16::Bit8.confined_serialize(), Ok(vec![0x00, 0x00]));
//! assert_eq!(U16::Bit16.confined_serialize(), Ok(vec![0x01, 0x00]));
//! assert_eq!(U16::Bit32.confined_serialize(), Ok(vec![0x02, 0x00]));
//! assert_eq!(U16::Bit64.confined_serialize(), Ok(vec![0x03, 0x00]));
//! ```
//!
//! ```
//! # #[macro_use] extern crate confined_encoding_derive;
//! use confined_encoding::{ConfinedDecode, ConfinedEncode};
//!
//! #[derive(ConfinedEncode, ConfinedDecode)]
//! struct Skipping {
//!     pub data: Vec<u8>,
//!
//!     // This will initialize the field upon decoding with Option::default()
//!     // value (i.e. `None`)
//!     #[confined_encoding(skip)]
//!     pub ephemeral: Option<bool>,
//! }
//!
//! let obj = Skipping {
//!     data: b"abc".to_vec(),
//!     ephemeral: Some(true),
//! };
//! let ser = obj.confined_serialize().unwrap();
//!
//! assert_eq!(ser, vec![0x03, 0x00, b'a', b'b', b'c']);
//! let de = Skipping::confined_deserialize(&ser).unwrap();
//! assert_eq!(de.ephemeral, None);
//! assert_eq!(obj.data, de.data);
//! ```

extern crate proc_macro;
#[macro_use]
extern crate syn;
#[macro_use]
extern crate amplify_syn;

use encoding_derive_helpers::{decode_derive, encode_derive};
use proc_macro::TokenStream;
use syn::DeriveInput;

/// Derives [`ConfinedEncode`] implementation for the type.
#[proc_macro_derive(ConfinedEncode, attributes(confined_encoding))]
pub fn derive_confined_encode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    encode_derive(
        "confined_encoding",
        ident!(confined_encoding),
        ident!(ConfinedEncode),
        ident!(confined_encode),
        ident!(confined_serialize),
        derive_input,
        false,
    )
    .unwrap_or_else(|e| e.to_compile_error())
    .into()
}

/// Derives [`ConfinedDecode`] implementation for the type.
#[proc_macro_derive(ConfinedDecode, attributes(confined_encoding))]
pub fn derive_confined_decode(input: TokenStream) -> TokenStream {
    let derive_input = parse_macro_input!(input as DeriveInput);
    decode_derive(
        "confined_encoding",
        ident!(confined_encoding),
        ident!(ConfinedDecode),
        ident!(confined_decode),
        ident!(confined_deserialize),
        derive_input,
        false,
    )
    .unwrap_or_else(|e| e.to_compile_error())
    .into()
}
