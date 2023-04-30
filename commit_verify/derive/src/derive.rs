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
use syn::{Error, Index, Result};

use crate::params::{CommitDerive, FieldAttr, VariantAttr};

struct DeriveEncode<'a>(&'a CommitDerive);

impl CommitDerive {
    pub fn derive_encode(&self) -> Result<TokenStream2> {
        self.data
            .derive(&self.conf.strict_crate, &ident!(StrictEncode), &DeriveEncode(self))
    }
}

impl DeriveInner for DeriveEncode<'_> {
    fn derive_unit_inner(&self) -> Result<TokenStream2> {
        Err(Error::new(
            Span::call_site(),
            "StrictEncode must not be derived on a unit types. Use just a unit type instead when \
             encoding parent structure.",
        ))
    }

    fn derive_struct_inner(&self, fields: &Items<NamedField>) -> Result<TokenStream2> {
        let crate_name = &self.0.conf.strict_crate;

        let mut orig_name = Vec::with_capacity(fields.len());
        let mut field_name = Vec::with_capacity(fields.len());
        for named_field in fields {
            let attr = FieldAttr::with(named_field.field.attr.clone(), FieldKind::Named)?;
            if !attr.skip {
                orig_name.push(&named_field.name);
                field_name.push(attr.field_name(&named_field.name));
            }
        }

        Ok(quote! {
            fn strict_encode<W: #crate_name::TypedWrite>(&self, writer: W) -> ::std::io::Result<W> {
                use #crate_name::{TypedWrite, WriteStruct, fname};
                writer.write_struct::<Self>(|w| {
                    Ok(w
                        #( .write_field(fname!(#field_name), &self.#orig_name)? )*
                        .complete())
                })
            }
        })
    }

    fn derive_tuple_inner(&self, fields: &Items<Field>) -> Result<TokenStream2> {
        let crate_name = &self.0.conf.strict_crate;

        let no = fields.iter().enumerate().filter_map(|(index, field)| {
            let attr = FieldAttr::with(field.attr.clone(), FieldKind::Unnamed).ok()?;
            if attr.skip {
                None
            } else {
                Some(Index::from(index))
            }
        });

        Ok(quote! {
            fn strict_encode<W: #crate_name::TypedWrite>(&self, writer: W) -> ::std::io::Result<W> {
                use #crate_name::{TypedWrite, WriteTuple};
                writer.write_tuple::<Self>(|w| {
                    Ok(w
                        #( .write_field(&self.#no)? )*
                        .complete())
                })
            }
        })
    }

    fn derive_enum_inner(&self, variants: &Items<Variant>) -> Result<TokenStream2> {
        let crate_name = &self.0.conf.strict_crate;

        let inner = if variants.enum_kind() == EnumKind::Primitive {
            quote! {
                writer.write_enum(*self)
            }
        } else {
            let mut define_variants = Vec::with_capacity(variants.len());
            let mut write_variants = Vec::with_capacity(variants.len());
            for var in variants {
                let attr = VariantAttr::try_from(var.attr.clone())?;
                let var_name = &var.name;
                let name = attr.variant_name(var_name);
                match &var.fields {
                    Fields::Unit => {
                        define_variants.push(quote! {
                            .define_unit(vname!(#name))
                        });
                        write_variants.push(quote! {
                            Self::#var_name => writer.write_unit(vname!(#name))?,
                        });
                    }
                    Fields::Unnamed(fields) if fields.is_empty() => {
                        define_variants.push(quote! {
                            .define_unit(vname!(#name))
                        });
                        write_variants.push(quote! {
                            Self::#var_name() => writer.write_unit(vname!(#name))?,
                        });
                    }
                    Fields::Named(fields) if fields.is_empty() => {
                        define_variants.push(quote! {
                            .define_unit(vname!(#name))
                        });
                        write_variants.push(quote! {
                            Self::#var_name {} => writer.write_unit(vname!(#name))?,
                        });
                    }
                    Fields::Unnamed(fields) => {
                        let mut field_ty = Vec::with_capacity(fields.len());
                        let mut field_idx = Vec::with_capacity(fields.len());
                        for (index, field) in fields.iter().enumerate() {
                            let attr = FieldAttr::with(field.attr.clone(), FieldKind::Unnamed)?;

                            if !attr.skip {
                                let ty = &field.ty;
                                let index = Ident::new(&format!("_{index}"), Span::call_site());
                                field_ty.push(quote! { #ty });
                                field_idx.push(quote! { #index });
                            }
                        }
                        define_variants.push(quote! {
                            .define_tuple(vname!(#name), |d| {
                                d #( .define_field::<#field_ty>() )* .complete()
                            })
                        });
                        write_variants.push(quote! {
                            Self::#var_name( #( #field_idx ),* ) => writer.write_tuple(vname!(#name), |w| {
                                Ok(w #( .write_field(#field_idx)? )* .complete())
                            })?,
                        });
                    }
                    Fields::Named(fields) => {
                        let mut field_ty = Vec::with_capacity(fields.len());
                        let mut field_name = Vec::with_capacity(fields.len());
                        let mut field_rename = Vec::with_capacity(fields.len());
                        for named_field in fields {
                            let attr =
                                FieldAttr::with(named_field.field.attr.clone(), FieldKind::Named)?;

                            let ty = &named_field.field.ty;
                            let name = &named_field.name;
                            let rename = attr.field_name(name);

                            if !attr.skip {
                                field_ty.push(quote! { #ty });
                                field_name.push(quote! { #name });
                                field_rename.push(quote! { fname!(#rename) });
                            }
                        }

                        define_variants.push(quote! {
                            .define_struct(vname!(#name), |d| {
                                d #( .define_field::<#field_ty>(#field_rename) )* .complete()
                            })
                        });
                        write_variants.push(quote! {
                            Self::#var_name { #( #field_name ),* } => writer.write_struct(vname!(#name), |w| {
                                Ok(w #( .write_field(#field_rename, #field_name)? )* .complete())
                            })?,
                        });
                    }
                }
            }

            quote! {
                #[allow(unused_imports)]
                use #crate_name::{DefineUnion, WriteUnion, DefineTuple, DefineStruct, WriteTuple, WriteStruct, fname, vname};
                writer.write_union::<Self>(|definer| {
                    let writer = definer
                        #( #define_variants )*
                        .complete();

                    Ok(match self {
                        #( #write_variants )*
                    }.complete())
                })
            }
        };

        Ok(quote! {
            fn strict_encode<W: #crate_name::TypedWrite>(&self, writer: W) -> ::std::io::Result<W> {
                use #crate_name::TypedWrite;
                #inner
            }
        })
    }
}
