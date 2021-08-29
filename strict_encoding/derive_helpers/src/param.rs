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

use core::convert::{TryFrom, TryInto};

use amplify::proc_attr::{
    ArgValue, ArgValueReq, AttrReq, LiteralClass, ParametrizedAttr, ValueClass,
};
use proc_macro2::Span;
use syn::{Error, Ident, LitInt, Path, Result};

pub const CRATE: &str = "crate";
pub const SKIP: &str = "skip";
pub const REPR: &str = "repr";
pub const VALUE: &str = "value";
pub const BY_ORDER: &str = "by_order";
pub const BY_VALUE: &str = "by_value";
pub const USE_TLV: &str = "use_tlv";
pub const TLV: &str = "tlv";
pub const UNKNOWN_TLVS: &str = "unknown_tlvs";

const EXPECT: &str =
    "amplify_syn is broken: requirements for crate arg are not satisfied";

#[derive(Clone)]
pub struct EncodingDerive {
    pub use_crate: Path,
    pub skip: bool,
    pub by_order: bool,
    pub value: Option<LitInt>,
    pub repr: Ident,
    /// `None` if TLVs are not allowed at the struct level with
    /// `#[strict_encoding(use_tlv)]` attribute
    pub tlv: Option<TlvDerive>,
}

#[derive(Clone, Copy)]
pub enum TlvDerive {
    None,
    Typed(u16),
    Unknown,
}

impl EncodingDerive {
    pub fn with(
        attr: &mut ParametrizedAttr,
        is_global: bool,
        is_enum: bool,
        use_tlv: bool,
    ) -> Result<EncodingDerive> {
        let mut map = if is_global {
            map! {
                CRATE => ArgValueReq::with_default(ident!(strict_encoding)),
                USE_TLV => ArgValueReq::with_default(true)
            }
        } else {
            map! {
                SKIP => ArgValueReq::Prohibited,
                TLV => ArgValueReq::Optional(ValueClass::Literal(LiteralClass::Int)),
                UNKNOWN_TLVS => ArgValueReq::with_default(true)
            }
        };

        if is_enum {
            map.insert(BY_ORDER, ArgValueReq::Prohibited);
            map.insert(BY_VALUE, ArgValueReq::Prohibited);
            map.insert(USE_TLV, ArgValueReq::Prohibited);
            map.insert(TLV, ArgValueReq::Prohibited);
            map.insert(UNKNOWN_TLVS, ArgValueReq::Prohibited);
            if is_global {
                map.insert(REPR, ArgValueReq::with_default(ident!(u8)));
            } else {
                map.insert(
                    VALUE,
                    ArgValueReq::Optional(ValueClass::Literal(
                        LiteralClass::Int,
                    )),
                );
            }
        }

        attr.check(AttrReq::with(map))?;

        if attr.args.contains_key(BY_VALUE) && attr.args.contains_key(BY_ORDER)
        {
            return Err(Error::new(
                Span::call_site(),
                "`by_value` and `by_order` attributes can't be present \
                 together",
            ));
        }

        let repr: Ident = attr
            .args
            .get(REPR)
            .cloned()
            .map(TryInto::try_into)
            .transpose()
            .expect(EXPECT)
            .unwrap_or_else(|| ident!(u8));

        match repr.to_string().as_str() {
            "u8" | "u16" | "u32" | "u64" => {}
            _ => {
                return Err(Error::new(
                    Span::call_site(),
                    "`repr` requires integer type identifier",
                ))
            }
        }

        let use_crate = attr
            .args
            .get(CRATE)
            .cloned()
            .unwrap_or_else(|| ArgValue::from(ident!(strict_encoding)))
            .try_into()
            .expect(EXPECT);

        let value = attr
            .args
            .get(VALUE)
            .cloned()
            .map(LitInt::try_from)
            .transpose()
            .expect(EXPECT);

        let skip = attr.args.get("skip").is_some();

        let by_order = !attr.args.contains_key("by_value");

        let tlv = TlvDerive::with(attr, use_tlv)?;

        Ok(EncodingDerive {
            use_crate,
            skip,
            by_order,
            value,
            repr,
            tlv,
        })
    }
}

impl TlvDerive {
    pub fn with(
        attr: &mut ParametrizedAttr,
        use_tlv: bool,
    ) -> Result<Option<TlvDerive>> {
        if !use_tlv
            && !attr
                .args
                .get(USE_TLV)
                .cloned()
                .map(bool::try_from)
                .transpose()
                .expect(EXPECT)
                .unwrap_or_default()
        {
            if attr.args.contains_key(TLV)
                || attr.args.contains_key(UNKNOWN_TLVS)
            {
                return Err(Error::new(
                    Span::call_site(),
                    "TLV-related attributes are allowed only when global \
                     `use_tlv` attribute is set",
                ));
            }
            return Ok(None);
        }

        if attr.args.contains_key(TLV) && attr.args.contains_key(UNKNOWN_TLVS) {
            return Err(Error::new(
                Span::call_site(),
                "`tlv` and `unknown_tlvs` attributes are mutually exclusive",
            ));
        }

        let tlv = if let Some(tlv) = attr
            .args
            .get(TLV)
            .cloned()
            .map(LitInt::try_from)
            .transpose()
            .expect(EXPECT)
        {
            Some(TlvDerive::Typed(tlv.base10_parse()?))
        } else if attr.args.contains_key(UNKNOWN_TLVS) {
            Some(TlvDerive::Unknown)
        } else {
            None
        };

        Ok(tlv)
    }
}
