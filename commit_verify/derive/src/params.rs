// Client-side-validation foundation libraries.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr. Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
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

use amplify_syn::{ArgValueReq, AttrReq, DataType, ParametrizedAttr, TypeClass};
use proc_macro2::Span;
use quote::ToTokens;
use syn::{DeriveInput, Error, Path, Result};

const ATTR: &str = "commit_encode";
const ATTR_CRATE: &str = "crate";
const ATTR_ID: &str = "id";
const ATTR_STRATEGY: &str = "strategy";
const ATTR_STRATEGY_STRICT: &str = "strict";
const ATTR_STRATEGY_CONCEAL: &str = "conceal";
const ATTR_STRATEGY_TRANSPARENT: &str = "transparent";
const ATTR_STRATEGY_MERKLIZE: &str = "merklize";

pub struct ContainerAttr {
    pub commit_crate: Path,
    pub strategy: StrategyAttr,
    pub id: Path,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum StrategyAttr {
    Strict,
    ConcealStrict,
    Transparent,
    Merklize,
    // TODO: Add Hash strategy
}

impl TryFrom<&Path> for StrategyAttr {
    type Error = Error;

    fn try_from(path: &Path) -> Result<Self> {
        match path.to_token_stream().to_string().as_str() {
            ATTR_STRATEGY_STRICT => Ok(StrategyAttr::Strict),
            ATTR_STRATEGY_CONCEAL => Ok(StrategyAttr::ConcealStrict),
            ATTR_STRATEGY_TRANSPARENT => Ok(StrategyAttr::Transparent),
            ATTR_STRATEGY_MERKLIZE => Ok(StrategyAttr::Merklize),
            unknown => Err(Error::new(
                Span::call_site(),
                format!(
                    "invalid commitment encoding value for `strategy` attribute `{unknown}`; only \
                     `{ATTR_STRATEGY_TRANSPARENT}`, `{ATTR_STRATEGY_STRICT}`, \
                     `{ATTR_STRATEGY_CONCEAL}`, or `{ATTR_STRATEGY_MERKLIZE}`  are allowed"
                ),
            )),
        }
    }
}

impl TryFrom<ParametrizedAttr> for ContainerAttr {
    type Error = Error;

    fn try_from(mut params: ParametrizedAttr) -> Result<Self> {
        let req = AttrReq::with(map![
            ATTR_CRATE => ArgValueReq::optional(TypeClass::Path),
            ATTR_ID => ArgValueReq::required(TypeClass::Path),
            ATTR_STRATEGY => ArgValueReq::required(TypeClass::Path),
        ]);
        params.check(req)?;

        let path = params.arg_value(ATTR_STRATEGY).expect("must be present");
        let strategy = StrategyAttr::try_from(&path)?;
        let id = params.arg_value(ATTR_ID).expect("must be present");

        Ok(ContainerAttr {
            commit_crate: params
                .arg_value(ATTR_CRATE)
                .unwrap_or_else(|_| path!(commit_verify)),
            strategy,
            id,
        })
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
        let data = DataType::with(input, ident!(commit_encode))?;
        Ok(Self { data, conf })
    }
}
