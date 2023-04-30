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

use std::collections::HashMap;

use amplify_syn::{
    ArgValueReq, AttrReq, DataType, EnumKind, FieldKind, ListReq, ParametrizedAttr, TypeClass,
    ValueClass,
};
use heck::ToLowerCamelCase;
use proc_macro2::{Ident, Span};
use quote::ToTokens;
use syn::{DeriveInput, Error, Expr, LitInt, LitStr, Path, Result};

const ATTR: &str = "commit_encode";
const ATTR_CRATE: &str = "crate";
const ATTR_LIB: &str = "lib";
const ATTR_RENAME: &str = "rename";
const ATTR_WITH: &str = "with";
const ATTR_ENCODE_WITH: &str = "encode_with";
const ATTR_DECODE_WITH: &str = "decode_with";
const ATTR_DUMB: &str = "dumb";
const ATTR_TAGS: &str = "tags";
const ATTR_TAGS_ORDER: &str = "order";
const ATTR_TAGS_REPR: &str = "repr";
const ATTR_TAGS_CUSTOM: &str = "custom";
const ATTR_TAG: &str = "tag";
const ATTR_SKIP: &str = "skip";
const ATTR_INTO_U8: &str = "into_u8";
const ATTR_TRY_FROM_U8: &str = "try_from_u8";

pub struct ContainerAttr {
    pub strict_crate: Path,
    pub lib: Expr,
    pub rename: Option<LitStr>,
    pub dumb: Option<Expr>,
    pub encode_with: Option<Path>,
    pub decode_with: Option<Path>,
}

pub struct EnumAttr {
    pub tags: VariantTags,
    pub try_from_u8: bool,
    pub into_u8: bool,
}

pub struct FieldAttr {
    pub dumb: Option<Expr>,
    pub rename: Option<LitStr>,
    pub skip: bool,
}

pub struct VariantAttr {
    pub dumb: bool,
    pub rename: Option<LitStr>,
    pub tag: Option<LitInt>,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum VariantTags {
    Repr,
    Order,
    Custom,
}

impl ContainerAttr {
    fn shared_attrs() -> Vec<(&'static str, ArgValueReq)> {
        vec![
            (ATTR_CRATE, ArgValueReq::optional(TypeClass::Path)),
            (ATTR_LIB, ArgValueReq::required(ValueClass::Expr)),
            (ATTR_RENAME, ArgValueReq::optional(ValueClass::str())),
            (ATTR_DUMB, ArgValueReq::optional(ValueClass::Expr)),
            (ATTR_ENCODE_WITH, ArgValueReq::optional(TypeClass::Path)),
            (ATTR_DECODE_WITH, ArgValueReq::optional(TypeClass::Path)),
        ]
    }
}

impl EnumAttr {
    fn attr_req(map: HashMap<&str, ArgValueReq>, kind: EnumKind) -> AttrReq {
        let mut req = AttrReq::with(map);
        if kind == EnumKind::Primitive {
            req.path_req = ListReq::any_of(vec![path!(try_from_u8), path!(into_u8)], false);
        }
        req
    }
}

impl TryFrom<ParametrizedAttr> for ContainerAttr {
    type Error = Error;

    fn try_from(mut params: ParametrizedAttr) -> Result<Self> {
        let mut attrs = ContainerAttr::shared_attrs();
        attrs.extend([(ATTR_TAGS, ArgValueReq::optional(TypeClass::Path))]);
        let map = HashMap::from_iter(attrs);

        params.check(EnumAttr::attr_req(map, EnumKind::Primitive))?;

        Ok(ContainerAttr {
            strict_crate: params
                .arg_value(ATTR_CRATE)
                .unwrap_or_else(|_| path!(strict_encoding)),
            lib: params.unwrap_arg_value(ATTR_LIB),
            rename: params.arg_value(ATTR_RENAME).ok(),
            dumb: params.arg_value(ATTR_DUMB).ok(),
            encode_with: params
                .arg_value(ATTR_ENCODE_WITH)
                .or_else(|_| params.arg_value(ATTR_WITH))
                .ok(),
            decode_with: params
                .arg_value(ATTR_DECODE_WITH)
                .or_else(|_| params.arg_value(ATTR_WITH))
                .ok(),
        })
    }
}

impl EnumAttr {
    pub fn with(mut params: ParametrizedAttr, kind: EnumKind) -> Result<Self> {
        let mut attrs = ContainerAttr::shared_attrs();
        attrs.extend([(ATTR_TAGS, ArgValueReq::required(TypeClass::Path))]);
        let map = HashMap::from_iter(attrs);

        params.check(EnumAttr::attr_req(map, kind))?;

        let tags = match params
            .arg_value(ATTR_TAGS)
            .unwrap_or_else(|_| path!(custom))
            .to_token_stream()
            .to_string()
            .as_str()
        {
            ATTR_TAGS_REPR => VariantTags::Repr,
            ATTR_TAGS_ORDER => VariantTags::Order,
            ATTR_TAGS_CUSTOM => VariantTags::Custom,
            unknown => {
                return Err(Error::new(
                    Span::call_site(),
                    format!(
                        "invalid enum strict encoding value for `tags` attribute `{unknown}`; \
                         only `repr`, `order` or `custom` are allowed"
                    ),
                ));
            }
        };

        let try_from_u8 = params.has_verbatim(ATTR_TRY_FROM_U8);
        let into_u8 = params.has_verbatim(ATTR_INTO_U8);

        if tags != VariantTags::Repr && kind == EnumKind::Primitive {
            return Err(Error::new(
                Span::call_site(),
                "primitive enum types must always use `tags = repr`",
            ));
        }

        Ok(EnumAttr {
            tags,
            try_from_u8,
            into_u8,
        })
    }
}

impl FieldAttr {
    pub fn with(mut params: ParametrizedAttr, kind: FieldKind) -> Result<Self> {
        let mut map =
            HashMap::from_iter(vec![(ATTR_DUMB, ArgValueReq::optional(ValueClass::Expr))]);

        if kind == FieldKind::Named {
            map.insert(ATTR_RENAME, ArgValueReq::optional(ValueClass::str()));
        }

        let mut attr_req = AttrReq::with(map);
        attr_req.path_req = ListReq::maybe_one(path!(skip));
        params.check(attr_req)?;

        Ok(FieldAttr {
            rename: params.arg_value(ATTR_RENAME).ok(),
            dumb: params.arg_value(ATTR_DUMB).ok(),
            skip: params.has_verbatim(ATTR_SKIP),
        })
    }

    pub fn field_name(&self, name: &Ident) -> LitStr {
        match self.rename {
            None => LitStr::new(&name.to_string().to_lower_camel_case(), name.span()),
            Some(ref name) => name.clone(),
        }
    }
}

impl TryFrom<ParametrizedAttr> for VariantAttr {
    type Error = Error;

    fn try_from(mut params: ParametrizedAttr) -> Result<Self> {
        let map = HashMap::from_iter(vec![
            (ATTR_RENAME, ArgValueReq::optional(ValueClass::str())),
            (ATTR_TAG, ArgValueReq::optional(ValueClass::int())),
        ]);

        let mut req = AttrReq::with(map);
        req.path_req = ListReq::maybe_one(path!(dumb));
        params.check(req)?;

        Ok(VariantAttr {
            rename: params.arg_value(ATTR_RENAME).ok(),
            tag: params.arg_value(ATTR_TAG).ok(),
            dumb: params.has_verbatim("dumb"),
        })
    }
}

impl VariantAttr {
    pub fn variant_name(&self, name: &Ident) -> LitStr {
        match self.rename {
            None => LitStr::new(&name.to_string().to_lower_camel_case(), name.span()),
            Some(ref name) => name.clone(),
        }
    }
}

pub struct CommitDerive {
    pub data: DataType,
    pub conf: ContainerAttr,
}

impl TryFrom<DeriveInput> for CommitDerive {
    type Error = Error;

    fn try_from(input: DeriveInput) -> Result<Self> {
        let params = ParametrizedAttr::with(ATTR, &input.attrs)?;
        let conf = ContainerAttr::try_from(params)?;
        let data = DataType::with(input, ident!(strict_type))?;
        Ok(Self { data, conf })
    }
}
