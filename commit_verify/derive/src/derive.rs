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

use proc_macro2::TokenStream as TokenStream2;
use syn::Result;

use crate::params::{CommitDerive, StrategyAttr};

impl CommitDerive {
    pub fn derive_encode(&self) -> Result<TokenStream2> {
        let (impl_generics, ty_generics, where_clause) = self.data.generics.split_for_impl();
        let trait_crate = &self.conf.commit_crate;
        let commitment_id = &self.conf.id;
        let ident_name = &self.data.name;

        let inner = match self.conf.strategy {
            StrategyAttr::Strict => quote! {
                engine.commit_to_serialized(self);
            },
            StrategyAttr::ConcealStrict => quote! {
                use #trait_crate::Conceal;
                engine.commit_to_concealed(&self.conceal());
            },
            StrategyAttr::Transparent => quote! {
                use amplify::Wrapper;
                engine.commit_to_serialized(self.as_inner());
            },
            StrategyAttr::Merklize => quote! {
                engine.commit_to_merkle(self);
            },
        };

        Ok(quote! {
            #[automatically_derived]
            impl #impl_generics #trait_crate::CommitEncode for #ident_name #ty_generics #where_clause {
                type CommitmentId = #commitment_id;

                fn commit_encode(&self, engine: &mut #trait_crate::CommitEngine) {
                    #inner
                }
            }
        })
    }
}
