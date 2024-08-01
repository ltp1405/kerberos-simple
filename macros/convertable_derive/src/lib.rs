extern crate proc_macro;
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, DeriveInput, Data, Meta, NestedMeta};

#[proc_macro_derive(Convertable, attributes(convert))]
pub fn convertable_derive(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    let name = &input.ident;

    let mut from_bytes_match_arms = vec![];
    let mut from_enum_match_arms = vec![];

    if let Data::Enum(data_enum) = &input.data {
        for variant in &data_enum.variants {
            let variant_name = &variant.ident;
            if let Some(attr) = variant.attrs.iter().find(|a| a.path.is_ident("convert")) {
                if let Ok(Meta::List(meta_list)) = attr.parse_meta() {
                    if let Some(NestedMeta::Lit(syn::Lit::Int(lit_int))) = meta_list.nested.first() {
                        let byte_value = lit_int.base10_parse::<u8>().unwrap();

                        from_bytes_match_arms.push(quote! {
                            #byte_value => #name::#variant_name,
                        });

                        from_enum_match_arms.push(quote! {
                            #name::#variant_name => [#byte_value],
                        });
                    }
                }
            }
        }
    }

    let gen = quote! {
        impl From<&[u8]> for #name {
            fn from(bytes: &[u8]) -> Self {
                if bytes.len() != 1 {
                    panic!("invalid bytes format");
                }
                match bytes[0] {
                    #(#from_bytes_match_arms)*
                    _ => panic!("invalid bytes format"),
                }
            }
        }

        impl From<#name> for Int32 {
            fn from(adtype: #name) -> Self {
                let bytes = match adtype {
                    #(#from_enum_match_arms)*
                };
                Int32::new(&bytes).expect("Cannot initialize Int32 from &Vec<u8>")
            }
        }
    };
    gen.into()
}
