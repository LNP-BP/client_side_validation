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

pub fn encode_derive(
    attr_name: &'static str,
    input: DeriveInput,
    allow_tlv: bool,
) -> Result<TokenStream2> {
    let (impl_generics, ty_generics, where_clause) =
        input.generics.split_for_impl();
    let ident_name = &input.ident;

    let global_param = ParametrizedAttr::with(attr_name, &input.attrs)?;

    match input.data {
        Data::Struct(data) => encode_struct_impl(
            attr_name,
            data,
            ident_name,
            global_param,
            impl_generics,
            ty_generics,
            where_clause,
            allow_tlv,
        ),
        Data::Enum(data) => encode_enum_impl(
            attr_name,
            data,
            ident_name,
            global_param,
            impl_generics,
            ty_generics,
            where_clause,
        ),
        //strict_encode_inner_enum(&input, &data),
        Data::Union(_) => Err(Error::new_spanned(
            &input,
            "Deriving StrictEncode is not supported in unions",
        )),
    }
}

fn encode_struct_impl(
    attr_name: &'static str,
    data: DataStruct,
    ident_name: &Ident,
    mut global_param: ParametrizedAttr,
    impl_generics: ImplGenerics,
    ty_generics: TypeGenerics,
    where_clause: Option<&WhereClause>,
    allow_tlv: bool,
) -> Result<TokenStream2> {
    let encoding = EncodingDerive::with(&mut global_param, true, false, false)?;

    if !allow_tlv && encoding.tlv.is_some() {
        return Err(Error::new(
            ident_name.span(),
            format!("TLV extensions are not allowed in `{}`", attr_name),
        ));
    }

    let inner_impl = match data.fields {
        Fields::Named(ref fields) => {
            encode_fields_impl(attr_name, &fields.named, global_param, false)?
        }
        Fields::Unnamed(ref fields) => {
            encode_fields_impl(attr_name, &fields.unnamed, global_param, false)?
        }
        Fields::Unit => quote! { Ok(0) },
    };

    let import = encoding.use_crate;

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics #import::StrictEncode for #ident_name #ty_generics #where_clause {
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, #import::Error> {
                use #import::StrictEncode;
                let mut len = 0;
                let data = self;
                #inner_impl
                Ok(len)
            }
        }
    })
}

fn encode_enum_impl(
    attr_name: &'static str,
    data: DataEnum,
    ident_name: &Ident,
    mut global_param: ParametrizedAttr,
    impl_generics: ImplGenerics,
    ty_generics: TypeGenerics,
    where_clause: Option<&WhereClause>,
) -> Result<TokenStream2> {
    let encoding = EncodingDerive::with(&mut global_param, true, true, false)?;
    let repr = encoding.repr;

    let mut inner_impl = TokenStream2::new();

    for (order, variant) in data.variants.iter().enumerate() {
        let mut local_param =
            ParametrizedAttr::with(attr_name, &variant.attrs)?;

        // First, test individual attribute
        let _ = EncodingDerive::with(&mut local_param, false, true, false)?;
        // Second, combine global and local together
        let mut combined = global_param.clone().merged(local_param.clone())?;
        combined.args.remove(REPR);
        combined.args.remove(CRATE);
        let encoding = EncodingDerive::with(&mut combined, false, true, false)?;

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
                    &fields.named,
                    local_param,
                    true,
                )?,
                quote! { { #( #captures ),* } },
            ),
            Fields::Unnamed(ref fields) => (
                encode_fields_impl(
                    attr_name,
                    &fields.unnamed,
                    local_param,
                    true,
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
                len += (#value as #repr).strict_encode(&mut e)?;
                #captures
                #field_impl
            }
        });
    }

    let import = encoding.use_crate;

    Ok(quote! {
        #[allow(unused_qualifications)]
        impl #impl_generics #import::StrictEncode for #ident_name #ty_generics #where_clause {
            #[inline]
            fn strict_encode<E: ::std::io::Write>(&self, mut e: E) -> Result<usize, #import::Error> {
                use #import::StrictEncode;
                let mut len = 0;
                match self {
                    #inner_impl
                }
                Ok(len)
            }
        }
    })
}

fn encode_fields_impl<'a>(
    attr_name: &'static str,
    fields: impl IntoIterator<Item = &'a Field>,
    mut parent_param: ParametrizedAttr,
    is_enum: bool,
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
        let _ =
            EncodingDerive::with(&mut local_param, false, is_enum, use_tlv)?;
        // Second, combine global and local together
        let mut combined = parent_param.clone().merged(local_param)?;
        let encoding =
            EncodingDerive::with(&mut combined, false, is_enum, use_tlv)?;

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
            &field,
            name,
            &mut strict_fields,
            &mut tlv_fields,
            &mut tlv_aggregator,
        )?;
    }

    for name in strict_fields {
        stream.append_all(quote_spanned! { Span::call_site() =>
            len += data.#name.strict_encode(&mut e)?;
        })
    }

    if use_tlv {
        stream.append_all(quote_spanned! { Span::call_site() =>
            let mut tlvs = ::std::collections::BTreeMap::<u16, Vec<u8>>::default();
        });
        for (type_no, name) in tlv_fields {
            stream.append_all(quote_spanned! { Span::call_site() =>
                tlvs.insert(#type_no, data.#name.strict_serialize()?);
            });
        }
        if let Some(name) = tlv_aggregator {
            stream.append_all(quote_spanned! { Span::call_site() =>
                for (type_no, val) in &data.#name {
                    tlvs.insert(*type_no, val.strict_serialize()?);
                }
            });
        }
        stream.append_all(quote_spanned! { Span::call_site() =>
            tlvs.strict_encode(&mut e)?;
        });

        /* Use this for lightning encode
        // TODO: Replace with new error type on strict_encoding 1.7 release
        stream.append_all(quote_spanned! { Span::call_site() =>
            let tlv_len = tlvs.values().map(Vec::len).sum();
            if tlv_len > ::core::u16::MAX {
                return Err(Error::ExceedMaxItems(tlv_len));
            }
            len += (tlv_len as u16).strict_encode(&mut e)?;
            for (type_no, bytes) in tlvs {
                len += type_no.strict_encode(&mut e)?;
                len += bytes.strict_encode(&mut e)?;
            }
        });
         */
    }

    Ok(stream)
}
