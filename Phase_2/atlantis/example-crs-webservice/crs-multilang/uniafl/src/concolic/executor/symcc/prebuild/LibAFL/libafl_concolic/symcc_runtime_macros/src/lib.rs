use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    Ident, Result, ReturnType, Token, Type,
};

#[allow(unused)]
struct MacroInput {
    vis: syn::Visibility,
    fn_token: Token![fn],
    name: Ident,
    paren_token: syn::token::Paren,
    args: Punctuated<syn::FnArg, Token![,]>,
    return_type: Option<ReturnType>,
    rt_cb: Option<Ident>,
}

impl Parse for MacroInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let vis: syn::Visibility = input.parse()?;
        let fn_token: Token![fn] = input.parse()?;
        let name: Ident = input.parse()?;
        let content;
        let paren_token = syn::parenthesized!(content in input);
        let args = content.parse_terminated(syn::FnArg::parse, Token![,])?;
        let return_type: Option<ReturnType> = if input.peek(Token![->]) {
            let arrow: Token![->] = input.parse()?;
            let ty: Type = input.parse()?;
            Some(ReturnType::Type(arrow, Box::new(ty)))
        } else {
            None
        };
        let _: Token![,] = input.parse()?;
        let _: Ident = input.parse()?;
        let _: Token![;] = input.parse()?;
        let rt_cb: Option<Ident> = if input.peek(Ident) {
            input.parse()?
        } else {
            None
        };

        // consume tokens after the comma_token
        Ok(Self {
            vis,
            fn_token,
            name,
            paren_token,
            args,
            return_type,
            rt_cb,
        })
    }
}

fn process_args(
    args: &Punctuated<syn::FnArg, Token![,]>,
    for_rust_runtime: bool,
) -> Vec<syn::FnArg> {
    args.iter()
        .map(|arg| {
            if let syn::FnArg::Typed(arg) = arg {
                if let syn::Pat::Ident(pat_ident) = &*arg.pat {
                    if arg.ty.to_token_stream().to_string() == "RSymExpr" {
                        if !for_rust_runtime {
                            return syn::FnArg::Typed(
                                syn::parse_quote!(#pat_ident: Option<RSymExpr>),
                            );
                        } else {
                            if pat_ident.ident.to_string().starts_with("optional_") {
                                // optional_ case: pass through without ?
                                return syn::FnArg::Typed(
                                    syn::parse_quote!(#pat_ident: Option<RSymExpr>),
                                );
                            } else {
                                // non-optional case: pass through with ?
                                return syn::FnArg::Typed(syn::parse_quote!(#pat_ident: RSymExpr));
                            }
                        }
                    }
                }
            }
            arg.clone()
        })
        .collect()
}

fn process_return_type(return_type: &Option<ReturnType>) -> ReturnType {
    if let Some(return_type) = return_type {
        match return_type {
            ReturnType::Default => ReturnType::Default,
            ReturnType::Type(_, ty) => {
                if ty.to_token_stream().to_string() == "RSymExpr" {
                    ReturnType::Type(
                        Token![->](proc_macro2::Span::call_site()),
                        Box::new(syn::parse_quote!(Option<RSymExpr>)),
                    )
                } else {
                    return_type.clone()
                }
            }
        }
    } else {
        ReturnType::Default
    }
}

#[proc_macro]
pub fn rust_runtime_function_declaration(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
            fn expression_unreachable(&mut self, expressions: &[RSymExpr]);
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
            fn hook_function_call(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr>;
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
            fn hook_intrinsic_call(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr>;
        });
    }
    let processed_args = process_args(&args, true);
    let processed_ret = process_return_type(&return_type);
    let output = quote! {
        fn #name(
            &mut self,
            #(#processed_args),*
        ) #processed_ret;
    };
    TokenStream::from(output)
}

#[proc_macro]
pub fn rust_runtime_export(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        rt_cb,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _rsym_expression_unreachable(expressions: *mut RSymExpr, num_elements: usize) {
            let slice = unsafe { core::slice::from_raw_parts(expressions, num_elements) };
            #rt_cb(|rt| {
                rt.expression_unreachable(slice);
            })
        }
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _rsym_hook_function_call(function_addr: u64, loc_id: u64, is_concrete_return_value_valid: bool, concrete_return_value: u64, args: *mut RSymExpr, concrete_args_valid: *mut bool, concrete_args: *mut u64, arg_count: u64) -> Option<RSymExpr> {
            let args_slice = unsafe { core::slice::from_raw_parts(args, arg_count as usize) };
            let concrete_args_values = unsafe { core::slice::from_raw_parts(concrete_args, arg_count as usize) };
            let concrete_args_validity = unsafe { core::slice::from_raw_parts(concrete_args_valid, arg_count as usize) };
            let concrete_args_slice: Vec<Option<u64>> = concrete_args_validity.iter().zip(concrete_args_values.iter()).map(|(&valid, &val)| if valid { Some(val) } else { None }).collect();
            #rt_cb(|rt| {
                rt.hook_function_call(function_addr, loc_id, if is_concrete_return_value_valid { Some(concrete_return_value) } else { None }, args_slice, &concrete_args_slice)
            })
        }
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _rsym_hook_intrinsic_call(intrinsic_id: u64, loc_id: u64, is_concrete_return_value_valid: bool, concrete_return_value: u64, args: *mut RSymExpr, concrete_args_valid: *mut bool, concrete_args: *mut u64, arg_count: u64) -> Option<RSymExpr> {
            let args_slice = unsafe { core::slice::from_raw_parts(args, arg_count as usize) };
            let concrete_args_values = unsafe { core::slice::from_raw_parts(concrete_args, arg_count as usize) };
            let concrete_args_validity = unsafe { core::slice::from_raw_parts(concrete_args_valid, arg_count as usize) };
            let concrete_args_slice: Vec<Option<u64>> = concrete_args_validity.iter().zip(concrete_args_values.iter()).map(|(&valid, &val)| if valid { Some(val) } else { None }).collect();
            #rt_cb(|rt| {
                rt.hook_intrinsic_call(intrinsic_id, loc_id, if is_concrete_return_value_valid { Some(concrete_return_value) } else { None }, args_slice, &concrete_args_slice)
            })
        }
        });
    }
    if name.to_string().as_str() == "push_path_constraint" {
        return TokenStream::from(quote! {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn _rsym_push_path_constraint(constraint: Option<RSymExpr>, taken: bool, site_id: usize) {
            if let Some(constraint) = constraint {
                #rt_cb(|rt| {
                    rt.push_path_constraint(constraint, taken, site_id);
                })
            }
        }
        });
    }

    let rt_cb = rt_cb.unwrap();
    let processed_args = process_args(&args, false);
    let processed_args_names_only = processed_args
        .iter()
        .map(|arg| {
            if let syn::FnArg::Typed(arg) = arg {
                if arg.ty.to_token_stream().to_string() == "Option < RSymExpr >" {
                    if let syn::Pat::Ident(pat_ident) = &*arg.pat {
                        if pat_ident.ident.to_string().starts_with("optional_") {
                            // optional_ case: pass through without ?
                            return quote! {
                                #pat_ident
                            };
                        } else {
                            // non-optional case: pass through with ?
                            return quote! {
                                #pat_ident?
                            };
                        }
                    }
                } else {
                    if let syn::Pat::Ident(pat_ident) = &*arg.pat {
                        return quote! {
                            #pat_ident
                        };
                    }
                }
            }
            panic!("Expected a named argument");
        })
        .collect::<Vec<_>>();
    // let rust infer the return type
    let rust_fn_name = Ident::new(&format!("_rsym_{}", name), proc_macro2::Span::call_site());
    let processed_ret = process_return_type(&return_type);
    let output = quote! {
        #[allow(clippy::missing_safety_doc)]
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn #rust_fn_name(#(#processed_args),*) #processed_ret {
            #rt_cb(|rt| {
                rt.#name(#(#processed_args_names_only),*)
            })
        }
    };
    TokenStream::from(output)
}

#[proc_macro]
pub fn rust_nop_runtime_function_definition(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
            fn #name(&mut self, expressions: &[RSymExpr]) { todo!() }
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
            fn #name(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> { todo!() }
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
            fn #name(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> { todo!() }
        });
    }

    let processed_args = process_args(&args, true);
    let processed_ret = process_return_type(&return_type);
    let output = quote! {
        #[allow(unused_variables)]
        fn #name(
            &mut self,
            #(#processed_args),*
        ) #processed_ret {
            std::default::Default::default()
        }
    };
    TokenStream::from(output)
}

fn is_rsym_expr_option(ty: &ReturnType) -> bool {
    match ty {
        ReturnType::Default => false,
        ReturnType::Type(_, ty) => {
            let ty_str = ty.to_token_stream().to_string();
            ty_str.as_str() == "Option < RSymExpr >"
        }
    }
}

#[proc_macro]
pub fn rust_optional_runtime_function_definition(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
        fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
            if let Some(inner) = &mut self.inner {
                inner.expression_unreachable(exprs);
            }
        }
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
        fn hook_function_call(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> {
            if let Some(inner) = &mut self.inner {
                inner.hook_function_call(function_addr, loc_id, concrete_return_value, args, concrete_args)
            } else {
                None
            }
        }
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
        fn hook_intrinsic_call(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> {
            if let Some(inner) = &mut self.inner {
                inner.hook_intrinsic_call(intrinsic_id, loc_id, concrete_return_value, args, concrete_args)
            } else {
                None
            }
        }
        });
    }

    let processed_args = process_args(&args, true);
    let arg_names = processed_args
        .iter()
        .map(|arg| {
            if let syn::FnArg::Typed(arg) = arg {
                if let syn::Pat::Ident(pat_ident) = &*arg.pat {
                    return pat_ident.ident.clone();
                }
            }
            panic!("Expected a named argument");
        })
        .collect::<Vec<_>>();
    let processed_ret = process_return_type(&return_type);

    // check if processed_ret is an option
    let output = if is_rsym_expr_option(&processed_ret) {
        quote! {
            #[allow(unused_variables)]
            fn #name(
                &mut self,
                #(#processed_args),*
            ) #processed_ret {
                if let Some(inner) = &mut self.inner {
                    inner.#name(#(#arg_names),*)
                } else {
                    None
                }
            }
        }
    } else {
        quote! {
            #[allow(unused_variables)]
            fn #name(
                &mut self,
                #(#processed_args),*
            ) #processed_ret {
                if let Some(inner) = &mut self.inner {
                    inner.#name(#(#arg_names),*)
                }
            }
        }
    };

    TokenStream::from(output)
}

#[proc_macro]
pub fn rust_filter_function_declaration(input: TokenStream) -> TokenStream {
    let MacroInput { name, args, .. } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
        fn expression_unreachable(&mut self, exprs: &[RSymExpr]) -> bool {
            true
        }
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
        fn hook_function_call(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> bool {
            true
        }
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
        fn hook_intrinsic_call(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> bool {
            true
        }
        });
    }

    let processed_args = process_args(&args, true);
    let output = quote! {
        #[allow(unused_variables)]
        fn #name(
            &mut self,
            #(#processed_args),*
        ) -> bool {
            true
        }
    };
    TokenStream::from(output)
}

#[proc_macro]
pub fn rust_filter_runtime_function_definition(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    if name.to_string().as_str() == "expression_unreachable" {
        return TokenStream::from(quote! {
        fn expression_unreachable(&mut self, exprs: &[RSymExpr]) {
            if !self.filter.expression_unreachable(exprs) {
                return;
            }
            self.runtime.expression_unreachable(exprs);
        }
        });
    }

    if name.to_string().as_str() == "hook_function_call" {
        return TokenStream::from(quote! {
        fn hook_function_call(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> {
            if !self.filter.hook_function_call(function_addr, loc_id, concrete_return_value, args, concrete_args) {
                return None;
            }
            self.runtime.hook_function_call(function_addr, loc_id, concrete_return_value, args, concrete_args)
        }
        });
    }

    if name.to_string().as_str() == "hook_intrinsic_call" {
        return TokenStream::from(quote! {
        fn hook_intrinsic_call(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> Option<RSymExpr> {
            if !self.filter.hook_intrinsic_call(intrinsic_id, loc_id, concrete_return_value, args, concrete_args) {
                return None;
            }
            self.runtime.hook_intrinsic_call(intrinsic_id, loc_id, concrete_return_value, args, concrete_args)
        }
        });
    }

    let processed_args = process_args(&args, true);
    let arg_names = processed_args
        .iter()
        .map(|arg| {
            if let syn::FnArg::Typed(arg) = arg {
                if let syn::Pat::Ident(pat_ident) = &*arg.pat {
                    return pat_ident.ident.clone();
                }
            }
            panic!("Expected a named argument");
        })
        .collect::<Vec<_>>();
    let processed_ret = process_return_type(&return_type);
    let output = quote! {
        #[allow(unused_variables)]
        fn #name(
            &mut self,
            #(#processed_args),*
        ) #processed_ret {
            if !self.filter.#name(#(#arg_names),*) {
                return std::default::Default::default();
            }
            self.runtime.#name(#(#arg_names),*)
        }
    };
    TokenStream::from(output)
}

#[proc_macro]
pub fn rust_coverage_filter_function_definition(input: TokenStream) -> TokenStream {
    let MacroInput {
        name,
        args,
        return_type,
        ..
    } = parse_macro_input!(input as MacroInput);

    let processed_args = process_args(&args, true);

    // now mimic each arm of your macro_rules!
    let output = match name.to_string().as_str() {
        // 1) skip expression_unreachable
        "expression_unreachable" => quote! {
            #[allow(unused_variables)]
            fn expression_unreachable(&mut self, expressions: &[RSymExpr]) -> bool {
                true
            }
        },
        "hook_function_call" => quote! {
            #[allow(unused_variables)]
            fn hook_function_call(&mut self, function_addr: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> bool {
                true
            }
        },
        "hook_intrinsic_call" => quote! {
            #[allow(unused_variables)]
            fn hook_intrinsic_call(&mut self, intrinsic_id: u64, loc_id: u64, concrete_return_value: Option<u64>, args: &[RSymExpr], concrete_args: &[Option<u64>]) -> bool {
                true
            }
        }, // 2) the three notifies
        "notify_basic_block" => quote! {
            #[allow(unused_variables)]
            fn notify_basic_block(&mut self, #(#processed_args),*) -> bool {
                self.visit_basic_block(site_id);
                true
            }
        },
        "notify_call" => quote! {
            #[allow(unused_variables)]
            fn notify_call(&mut self, #(#processed_args),*) -> bool {
                self.visit_call(site_id);
                true
            }
        },
        "notify_ret" => quote! {
            #[allow(unused_variables)]
            fn notify_ret(&mut self, #(#processed_args),*) -> bool {
                self.visit_ret(site_id);
                true
            }
        },

        // 3) push_path_constraint (no `->` in signature)
        "push_path_constraint" => quote! {
            #[allow(unused_variables)]
            fn push_path_constraint(&mut self, #(#processed_args),*) -> bool {
                self.update_bitmap();
                self.is_interesting()
            }
        },

        // 4) any other `-> Type` method
        _ if !matches!(return_type, Some(ReturnType::Default)) => quote! {
            #[allow(unused_variables)]
            fn #name(&mut self, #(#processed_args),*) -> bool {
                self.update_bitmap();
                self.is_interesting()
            }
        },

        // 5) any other no-return‐type method
        _ => quote! {
            #[allow(unused_variables)]
            fn #name(&mut self, #(#processed_args),*) -> bool {
                true
            }
        },
    };

    TokenStream::from(output)
}
