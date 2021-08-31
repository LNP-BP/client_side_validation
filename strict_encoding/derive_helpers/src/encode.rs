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

use amplify::proc_attr::ParametrizedAttr;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{ToTokens, TokenStreamExt};
use syn::spanned::Spanned;
use syn::{
    Data, DataEnum, DataStruct, DeriveInput, Error, Field, Fields, Ident,
    ImplGenerics, Index, Result, TypeGenerics, WhereClause,
};

use crate::param::{EncodingDerive, TlvDerive, CRATE, REPR, USE_TLV};
use crate::TlvEncoding;

/// Performs actual derivation of the encode trait using the provided
/// information about trait parameters and requirements for TLV support (see
/// [`TlvEncoding`] description).
///
/// You will find example of the function use in the
/// [crate top-level documentation][crate].
pub fn encode_derive(
    attr_name: &'static str,
    crate_name: Ident,
    trait_name: Ident,
    encode_name: Ident,
    serialize_name: Ident,
    input: DeriveInput,
    tlv_encoding: TlvEncoding,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let global_param = ParametrizedAttr::with(attr_name, &input.attrs)?;

    match input.data {
        Data::Struct(data) => encode_struct_impl(
            attr_name,
            &crate_name,
            &trait_name,
            &encode_name,
            &serialize_name,
            data,
            ident_name,
            global_param,
            impl_generics,
            ty_generics,
            where_clause,
            tlv_encoding,
        ),
        Data::Enum(data) => encode_enum_impl(
            attr_name,
            &crate_name,
            &trait_name,
            &encode_name,
            &serialize_name,
            data,
            ident_name,
            global_param,
            impl_generics,
            ty_generics,
            where_clause,
        ),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            format!("Deriving `{}` is not supported in unions", trait_name),
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn encode_struct_impl(
    attr_name: &'static str,
    crate_name: &Ident,
    trait_name: &Ident,
    encode_name: &Ident,
    serialize_name: &Ident,
    data: DataStruct,
    ident_name: &Ident,
    mut global_param: ParametrizedAttr,
    impl_generics: ImplGenerics,
    ty_generics: TypeGenerics,
    where_clause: Option<&WhereClause>,
    tlv_encoding: TlvEncoding,
) -> Result<TokenStream2> {
    let encoding = EncodingDerive::with(
        &mut global_param,
        crate_name,
        true,
        false,
        false,
    )?;

    if tlv_encoding == TlvEncoding::Denied && encoding.tlv.is_some() {
        return Err(Error::new(
            ident_name.span(),
            format!("TLV extensions are not allowed in `{}`", attr_name),
        ));
    }

    let inner_impl = match data.fields {
        Fields::Named(ref fields) => encode_fields_impl(
            attr_name,
            crate_name,
            trait_name,
            encode_name,
            serialize_name,
            &fields.named,
            global_param,
            false,
            tlv_encoding,
        )?,
        Fields::Unnamed(ref fields) => encode_fields_impl(
            attr_name,
            crate_name,
            trait_name,
            encode_name,
            serialize_name,
            &fields.unnamed,
            global_param,
            false,
            tlv_encoding,
        )?,
        Fields::Unit => quote! { Ok(0) },
    };

    let import = encoding.use_crate;

    Ok(quote! {
        impl #impl_generics #import::#trait_name for #ident_name #ty_generics #where_clause {
            fn #encode_name<E: ::std::io::Write>(&self, mut e: E) -> ::core::result::Result<usize, #import::Error> {
                use #import::#trait_name;
                let mut len = 0;
                let data = self;
                #inner_impl
                Ok(len)
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_enum_impl(
    attr_name: &'static str,
    crate_name: &Ident,
    trait_name: &Ident,
    encode_name: &Ident,
    serialize_name: &Ident,
    data: DataEnum,
    ident_name: &Ident,
    mut global_param: ParametrizedAttr,
    impl_generics: ImplGenerics,
    ty_generics: TypeGenerics,
    where_clause: Option<&WhereClause>,
) -> Result<TokenStream2> {
    let encoding =
        EncodingDerive::with(&mut global_param, crate_name, true, true, false)?;
    let repr = encoding.repr;

    let mut inner_impl = TokenStream2::new();

    for (order, variant) in data.variants.iter().enumerate() {
        let mut local_param =
            ParametrizedAttr::with(attr_name, &variant.attrs)?;

        // First, test individual attribute
        let _ = EncodingDerive::with(
            &mut local_param,
            crate_name,
            false,
            true,
            false,
        )?;
        // Second, combine global and local together
        let mut combined = global_param.clone().merged(local_param.clone())?;
        combined.args.remove(REPR);
        combined.args.remove(CRATE);
        let encoding = EncodingDerive::with(
            &mut combined,
            crate_name,
            false,
            true,
            false,
        )?;

        if encoding.skip {
            continue;
        }

        let captures = variant
            .fields
            .iter()
            .enumerate()
            .map(|(i, f)| {
                f.ident.as_ref().map(Ident::to_token_stream).unwrap_or_else(
                    || {
                        Ident::new(&format!("_{}", i), Span::call_site())
                            .to_token_stream()
                    },
                )
            })
            .collect::<Vec<_>>();

        let (field_impl, bra_captures_ket) = match variant.fields {
            Fields::Named(ref fields) => (
                encode_fields_impl(
                    attr_name,
                    crate_name,
                    trait_name,
                    encode_name,
                    serialize_name,
                    &fields.named,
                    local_param,
                    true,
                    TlvEncoding::Denied,
                )?,
                quote! { { #( #captures ),* } },
            ),
            Fields::Unnamed(ref fields) => (
                encode_fields_impl(
                    attr_name,
                    crate_name,
                    trait_name,
                    encode_name,
                    serialize_name,
                    &fields.unnamed,
                    local_param,
                    true,
                    TlvEncoding::Denied,
                )?,
                quote! { ( #( #captures ),* ) },
            ),
            Fields::Unit => (TokenStream2::new(), TokenStream2::new()),
        };

        let captures = match captures.len() {
            0 => quote! {},
            _ => quote! { let data = ( #( #captures ),* , ); },
        };

        let ident = &variant.ident;
        let value = match (encoding.value, encoding.by_order) {
            (Some(val), _) => val.to_token_stream(),
            (None, true) => Index::from(order as usize).to_token_stream(),
            (None, false) => quote! { Self::#ident },
        };

        inner_impl.append_all(quote_spanned! { variant.span() =>
            Self::#ident #bra_captures_ket => {
                len += (#value as #repr).#encode_name(&mut e)?;
                #captures
                #field_impl
            }
        });
    }

    let import = encoding.use_crate;

    Ok(quote! {
        impl #impl_generics #import::#trait_name for #ident_name #ty_generics #where_clause {
            #[inline]
            fn #encode_name<E: ::std::io::Write>(&self, mut e: E) -> ::core::result::Result<usize, #import::Error> {
                use #import::#trait_name;
                let mut len = 0;
                match self {
                    #inner_impl
                }
                Ok(len)
            }
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn encode_fields_impl<'a>(
    attr_name: &'static str,
    crate_name: &Ident,
    _trait_name: &Ident,
    encode_name: &Ident,
    serialize_name: &Ident,
    fields: impl IntoIterator<Item = &'a Field>,
    mut parent_param: ParametrizedAttr,
    is_enum: bool,
    tlv_encoding: TlvEncoding,
) -> Result<TokenStream2> {
    let mut stream = TokenStream2::new();

    let use_tlv = parent_param.args.contains_key(USE_TLV);
    parent_param.args.remove(CRATE);
    parent_param.args.remove(USE_TLV);

    let mut strict_fields = vec![];
    let mut tlv_fields = bmap! {};
    let mut tlv_aggregator = None;

    for (index, field) in fields.into_iter().enumerate() {
        let mut local_param = ParametrizedAttr::with(attr_name, &field.attrs)?;

        // First, test individual attribute
        let _ = EncodingDerive::with(
            &mut local_param,
            crate_name,
            false,
            is_enum,
            use_tlv,
        )?;
        // Second, combine global and local together
        let mut combined = parent_param.clone().merged(local_param)?;
        let encoding = EncodingDerive::with(
            &mut combined,
            crate_name,
            false,
            is_enum,
            use_tlv,
        )?;

        if encoding.skip {
            continue;
        }

        let index = Index::from(index).to_token_stream();
        let name = if is_enum {
            index
        } else {
            field
                .ident
                .as_ref()
                .map(Ident::to_token_stream)
                .unwrap_or(index)
        };

        encoding.tlv.unwrap_or(TlvDerive::None).process(
            field,
            name,
            &mut strict_fields,
            &mut tlv_fields,
            &mut tlv_aggregator,
        )?;
    }

    for name in strict_fields {
        stream.append_all(quote_spanned! { Span::call_site() =>
            len += data.#name.#encode_name(&mut e)?;
        })
    }

    if use_tlv {
        stream.append_all(quote_spanned! { Span::call_site() =>
            let mut tlvs = ::std::collections::BTreeMap::<usize, Vec<u8>>::default();
        });
        for (type_no, (name, optional)) in tlv_fields {
            if optional {
                stream.append_all(quote_spanned! { Span::call_site() =>
                    if let Some(val) = &data.#name {
                        tlvs.insert(#type_no, val.#serialize_name()?);
                    }
                });
            } else {
                stream.append_all(quote_spanned! { Span::call_site() =>
                    if data.#name.iter().count() > 0 {
                        tlvs.insert(#type_no, data.#name.#serialize_name()?);
                    }
                });
            }
        }
        if let Some(name) = tlv_aggregator {
            stream.append_all(quote_spanned! { Span::call_site() =>
                for (type_no, val) in &data.#name {
                    tlvs.insert(*type_no, val.#serialize_name()?);
                }
            });
        }

        match tlv_encoding {
            TlvEncoding::Count => {
                stream.append_all(quote_spanned! { Span::call_site() =>
                    len += tlvs.#encode_name(&mut e)?;
                })
            }
            TlvEncoding::Length => {
                stream.append_all(quote_spanned! { Span::call_site() =>
                    let tlv_len: usize = tlvs.values().map(Vec::len).sum();
                    len += tlv_len.#encode_name(&mut e)?;
                    for (type_no, bytes) in tlvs {
                        len += type_no.#encode_name(&mut e)?;
                        len += bytes.#encode_name(&mut e)?;
                    }
                })
            }
            TlvEncoding::Denied => unreachable!(
                "denied TLV encoding is already checked in the caller method"
            ),
        }
    }

    Ok(stream)
}
