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

use amplify_syn::{DeriveInner, EnumKind, Field, FieldKind, Fields, Items, NamedField, Variant};
use proc_macro2::{Ident, Span, TokenStream as TokenStream2};
use quote::ToTokens;
use syn::{Error, Index, Result};

use crate::params::{CommitDerive, FieldAttr, StrategyAttr};

struct DeriveCommit<'a>(&'a CommitDerive);

impl CommitDerive {
    pub fn derive_encode(&self) -> Result<TokenStream2> {
        match self.conf.strategy {
            StrategyAttr::CommitEncoding => self.data.derive(
                &self.conf.commit_crate,
                &ident!(CommitEncode),
                &DeriveCommit(self),
            ),
            other => self.derive_strategy(other),
        }
    }

    fn derive_strategy(&self, strategy: StrategyAttr) -> Result<TokenStream2> {
        let (impl_generics, ty_generics, where_clause) = self.data.generics.split_for_impl();
        let trait_crate = &self.conf.commit_crate;
        let ident_name = &self.data.name;
        let strategy_name = strategy.to_ident();

        Ok(quote! {
            #[automatically_derived]
            impl #impl_generics #trait_crate::CommitStrategy for #ident_name #ty_generics #where_clause {
                type Strategy = #trait_crate::strategies::#strategy_name;
            }
        })
    }

    fn derive_fields<'a>(
        &self,
        fields: impl Iterator<Item = (Option<&'a Ident>, &'a Field)>,
    ) -> Result<TokenStream2> {
        let crate_name = &self.conf.commit_crate;

        let conceal_code = if self.conf.conceal {
            quote! {
                let me = self.conceal();
            }
        } else {
            quote! {
                let me = self;
            }
        };

        let mut field_encoding = Vec::new();
        for (no, (field_name, unnamed_field)) in fields.enumerate() {
            let kind = match field_name {
                Some(_) => FieldKind::Named,
                None => FieldKind::Unnamed,
            };
            let attr = FieldAttr::with(unnamed_field.attr.clone(), kind)?;
            if attr.skip {
                continue;
            }
            let field_name = field_name
                .map(Ident::to_token_stream)
                .unwrap_or_else(|| Index::from(no).to_token_stream());
            let field = if let Some(tag) = attr.merklize {
                quote! {
                    {
                        use #crate_name::merkle::MerkleLeaves;
                        #crate_name::merkle::MerkleNode::merklize(#tag.to_be_bytes(), &me.#field_name).commit_encode(e);
                    }
                }
            } else {
                quote! {
                    me.#field_name.commit_encode(e);
                }
            };
            field_encoding.push(field)
        }

        Ok(quote! {
            fn commit_encode(&self, e: &mut impl ::std::io::Write) {
                use #crate_name::CommitEncode;
                #conceal_code
                #( #field_encoding )*
            }
        })
    }
}

impl DeriveInner for DeriveCommit<'_> {
    fn derive_unit_inner(&self) -> Result<TokenStream2> {
        Err(Error::new(
            Span::call_site(),
            "CommitEncode must not be derived on a unit types. Use just a unit type instead when \
             encoding parent structure.",
        ))
    }

    fn derive_struct_inner(&self, fields: &Items<NamedField>) -> Result<TokenStream2> {
        self.0
            .derive_fields(fields.iter().map(|f| (Some(&f.name), &f.field)))
    }

    fn derive_tuple_inner(&self, fields: &Items<Field>) -> Result<TokenStream2> {
        self.0.derive_fields(fields.iter().map(|f| (None, f)))
    }

    fn derive_enum_inner(&self, variants: &Items<Variant>) -> Result<TokenStream2> {
        let crate_name = &self.0.conf.commit_crate;

        if variants.enum_kind() == EnumKind::Primitive {
            return Err(Error::new(
                Span::call_site(),
                "primitive enums can't use `propagate` strategy",
            ));
        }

        let conceal_code = if self.0.conf.conceal {
            quote! {
                let me = self.conceal();
            }
        } else {
            quote! {
                let me = self;
            }
        };

        let mut write_variants = Vec::with_capacity(variants.len());
        for var in variants {
            let var_name = &var.name;
            match &var.fields {
                Fields::Unit => {
                    write_variants.push(quote! {
                        Self::#var_name => {},
                    });
                }
                Fields::Unnamed(fields) if fields.is_empty() => {
                    write_variants.push(quote! {
                        Self::#var_name() => {},
                    });
                }
                Fields::Named(fields) if fields.is_empty() => {
                    write_variants.push(quote! {
                        Self::#var_name {} => {},
                    });
                }
                Fields::Unnamed(fields) => {
                    let mut field_idx = Vec::with_capacity(fields.len());
                    let mut field_fragments = Vec::with_capacity(fields.len());
                    for (no, field) in fields.iter().enumerate() {
                        let index = Ident::new(&format!("_{no}"), Span::call_site());
                        let attr = FieldAttr::with(field.attr.clone(), FieldKind::Unnamed)?;
                        field_idx.push(index.clone());
                        if attr.skip {
                            continue;
                        }

                        if let Some(tag) = attr.merklize {
                            field_fragments.push(quote! {
                                MerkleNode::merklize(#tag.to_be_bytes(), #index).commit_encode(e);
                            })
                        } else {
                            field_fragments.push(quote! {
                                #index.commit_encode(e);
                            })
                        }
                    }
                    write_variants.push(quote! {
                        Self::#var_name( #( #field_idx ),* ) => {
                            #( #field_fragments )*
                        },
                    });
                }
                Fields::Named(fields) => {
                    let mut field_name = Vec::with_capacity(fields.len());
                    let mut field_fragments = Vec::with_capacity(fields.len());
                    for named_field in fields {
                        let attr =
                            FieldAttr::with(named_field.field.attr.clone(), FieldKind::Named)?;
                        let name = &named_field.name;
                        field_name.push(name.clone());
                        if attr.skip {
                            continue;
                        }

                        if let Some(tag) = attr.merklize {
                            field_fragments.push(quote! {
                                MerkleNode::merklize(#tag.to_be_bytes(), #name).commit_encode(e);
                            })
                        } else {
                            field_fragments.push(quote! {
                                #name.commit_encode(e);
                            })
                        }
                    }

                    write_variants.push(quote! {
                        Self::#var_name { #( #field_name ),* } => {
                            #( #field_fragments )*
                        },
                    });
                }
            }
        }

        Ok(quote! {
            #[allow(unused_imports, unused_variables)]
            fn commit_encode(&self, e: &mut impl ::std::io::Write) {
                use #crate_name::CommitEncode;
                use #crate_name::merkle::{MerkleLeaves, MerkleNode};
                use ::strict_encoding::StrictSum;

                #conceal_code
                me.variant_ord().commit_encode(e);

                match self {
                    #( #write_variants )*
                }
            }
        })
    }
}
