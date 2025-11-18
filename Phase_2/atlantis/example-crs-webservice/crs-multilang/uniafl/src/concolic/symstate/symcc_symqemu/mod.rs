use crate::common::{Error, InputID};
use crate::concolic::symstate::common::expr_optimizer::{ConcatOptimizer, ExprOptimizer};
use crate::concolic::symstate::common::solver::{AnnotatedSolution, PathConstraintExpr, Solver};
use crate::concolic::symstate::{
    PathConstraint, SolutionCache, SolutionToInput, SymState, SymStateProfileData, TraceManager,
};
use indexmap::IndexMap;
use rand::Rng;
use serde::{ser::SerializeStruct, Serialize};
use std::collections::{HashMap, HashSet};
use std::hash::{DefaultHasher, Hasher};
pub use sym_expr::{SymExpr, SymExprRef};
#[allow(unused_imports)]
pub use symcc::{new_symcc_symstate, SymCCSymState, SymCCSymStateConfig, SymCCTraceManager};
pub use symcc_map_parser::{parse_symcc_map, SrcLocation, SymCCMap};
#[allow(unused)]
pub use symqemu::{
    new_symqemu_symstate, SymQEMUSymState, SymQEMUSymStateConfig, SymQEMUTraceManager,
};
pub use translation_entry::{ArrayInfo, TranslationEntry};
use z3::ast::{Array, Ast, Bool, Dynamic, Float, BV};
use z3::{Context, SortKind, Symbol};

mod sym_expr;
mod symcc;
mod symcc_map_parser;
mod symqemu;
mod translation_entry;

#[derive(Debug, Clone)]
pub struct SymCCPathConstraintMetadata {
    pub is_interesting: bool,
    pub src_location: Option<SrcLocation>,
}

impl Into<Option<SrcLocation>> for SymCCPathConstraintMetadata {
    fn into(self) -> Option<SrcLocation> {
        self.src_location
    }
}

pub type SymCCTR = (Vec<u8>, HashMap<u64, bool>);

#[allow(unused)]
#[derive(Debug, Clone)]
pub struct SymCCCoercedValue<'ctx> {
    pub variable: Dynamic<'ctx>,
    pub concrete_value: Dynamic<'ctx>,
    pub src_location: Option<SrcLocation>,
    // end exclusive!
    pub max_failed_hook_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub enum SymCCFailedHookCall {
    Function {
        function_addr: u64,
        reason: String,
        src_location: Option<SrcLocation>,
    },
    Intrinsic {
        intrinsic_id: u64,
        reason: String,
        src_location: Option<SrcLocation>,
    },
}

impl Serialize for SymCCCoercedValue<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SymCCCoercedValue", 2)?;
        state.serialize_field("concrete_value", &self.concrete_value.to_string())?;
        state.serialize_field("src_location", &self.src_location)?;
        state.end()
    }
}

#[allow(unused)]
pub trait IsSymCCAux<'ctx> {
    fn messages(&self) -> &Vec<(SymExprRef, SymExpr)>;
    fn translations(&self) -> &HashMap<SymExprRef, TranslationEntry<'ctx, Dynamic<'ctx>>>;
    fn coerced_values(&self) -> &HashMap<String, SymCCCoercedValue<'ctx>>;
    fn unidentified_sites(&self) -> &Vec<u64>;
    fn failed_function_hook_calls(&self) -> &Vec<SymCCFailedHookCall>;
}

#[allow(unused)]
#[derive(Default)]
pub struct SymCCAux<'ctx> {
    /// A list of site IDs which were not identifiable via symcc_map (SymCC) or llvm-symbolizer (SymQEMU)
    pub messages: Vec<(SymExprRef, SymExpr)>,
    pub translations: HashMap<SymExprRef, TranslationEntry<'ctx, Dynamic<'ctx>>>,
    pub coerced_values: HashMap<String, SymCCCoercedValue<'ctx>>,
    pub unidentified_sites: Vec<u64>,
    pub failed_hook_calls: Vec<SymCCFailedHookCall>,
}

impl<'ctx> IsSymCCAux<'ctx> for SymCCAux<'ctx> {
    fn messages(&self) -> &Vec<(SymExprRef, SymExpr)> {
        &self.messages
    }

    fn translations(&self) -> &HashMap<SymExprRef, TranslationEntry<'ctx, Dynamic<'ctx>>> {
        &self.translations
    }

    fn coerced_values(&self) -> &HashMap<String, SymCCCoercedValue<'ctx>> {
        &self.coerced_values
    }

    fn unidentified_sites(&self) -> &Vec<u64> {
        &self.unidentified_sites
    }

    fn failed_function_hook_calls(&self) -> &Vec<SymCCFailedHookCall> {
        &self.failed_hook_calls
    }
}

impl Serialize for SymCCAux<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut state = serializer.serialize_struct("SymCCAux", 2)?;
        state.serialize_field("unidentified_sites", &self.unidentified_sites)?;
        state.serialize_field("coerced_values", &self.coerced_values)?;
        state.end()
    }
}

pub struct SymCCSymQEMULoadedTrace<'ctx> {
    pub messages: Vec<(SymExprRef, SymExpr)>,
    pub path_constraints: Vec<PathConstraint<'ctx, SymCCPathConstraintMetadata>>,
    pub translations: HashMap<SymExprRef, TranslationEntry<'ctx, Dynamic<'ctx>>>,
    pub coerced_values: HashMap<String, SymCCCoercedValue<'ctx>>,
    pub failed_hook_calls: Vec<SymCCFailedHookCall>,
}
fn build_extract<'ctx>(
    te: &TranslationEntry<'ctx, BV<'ctx>>,
    offset: u64,
    length: u64,
    little_endian: bool,
) -> TranslationEntry<'ctx, BV<'ctx>> {
    let size = u64::from(te.get_size());
    assert_eq!(
        size % 8,
        0,
        "can't extract on byte-boundary on BV that is not byte-sized"
    );
    let bv = te.expr().clone();

    let final_bv = if little_endian {
        (0..length)
            .map(|i| {
                bv.extract(
                    (size - (offset + i) * 8 - 1).try_into().unwrap(),
                    (size - (offset + i + 1) * 8).try_into().unwrap(),
                )
            })
            .reduce(|acc, next| next.concat(&acc))
            .unwrap()
    } else {
        bv.extract(
            (size - offset * 8 - 1).try_into().unwrap(),
            (size - (offset + length) * 8).try_into().unwrap(),
        )
    };
    TranslationEntry::new_scalar(final_bv, te.depth() + 1, te.coerced_values().clone())
}

pub fn offset_to_symbol(offset: usize) -> String {
    format!("k!{}", offset)
}

fn load_trace_common<'ctx>(
    ctx: &'ctx Context,
    trace: SymCCTR,
    mut src_location_fn: impl FnMut(u64) -> Option<SrcLocation>,
    max_path_constraints: Option<usize>,
    capture_constant_path_constraints: bool,
    previous_aux: Option<&SymCCAux<'ctx>>,
) -> Result<SymCCSymQEMULoadedTrace<'ctx>, Error> {
    let (trace, metadata) = trace;
    let (messages, start_index, mut translations, mut failed_hook_calls, mut coerced_values): (
        Vec<(SymExprRef, SymExpr)>,
        usize,
        HashMap<SymExprRef, TranslationEntry<Dynamic<'ctx>>>,
        Vec<SymCCFailedHookCall>,
        HashMap<String, SymCCCoercedValue<'ctx>>,
    ) = if let Some(previous_aux) = previous_aux {
        let all_messages: Vec<(SymExprRef, SymExpr)> = postcard::from_bytes(&trace)?;
        let start_index = previous_aux.messages.len();
        let (previous_messages, _) = all_messages.as_slice().split_at(start_index);
        if previous_messages != &previous_aux.messages {
            return Err(Error::invalid_trace_generation());
        }
        (
            all_messages,
            start_index,
            previous_aux.translations.clone(),
            previous_aux.failed_hook_calls.clone(),
            previous_aux.coerced_values.clone(),
        )
    } else {
        (
            postcard::from_bytes(&trace)?,
            0,
            HashMap::new(),
            vec![],
            HashMap::new(),
        )
    };

    macro_rules! bool {
        ($op:ident) => {
            translations[&$op].as_bool().unwrap()
        };
    }

    macro_rules! bv {
        ($op:ident) => {
            translations[&$op].as_bv().unwrap()
        };
    }

    macro_rules! bv_binop {
        ($a:ident $op:tt $b:ident) => {{
            let a = bv!($a);
            let b = bv!($b);
            Some(a.$op(&b).into())
        }};
    }

    macro_rules! float {
        ($op:ident) => {
            translations[&$op].as_float().unwrap()
        };
    }

    macro_rules! array {
        ($op:ident) => {{
            let tr = &translations[&$op];
            (tr.as_array().unwrap(), tr.array_info().unwrap())
        }};
    }

    macro_rules! float_binop {
        ($a:ident $op:tt $b:ident) => {{
            let a = float!($a);
            let b = float!($b);
            Some(a.$op(&b).into())
        }};
    }

    macro_rules! float_unorderd_comparison {
        ($a:ident $op:tt $b:ident) => {{
            let a = float!($a);
            let b = float!($b);
            let unordered = a.unordered(&b);
            let $op = a.$op(&b);
            Some(unordered.or(&$op).into())
        }};
    }

    macro_rules! float_ordered_comparison {
        ($a:ident $op:tt $b:ident) => {{
            let a = float!($a);
            let b = float!($b);
            let ordered = a.ordered(&b);
            let $op = a.$op(&b);
            Some(ordered.and(&$op).into())
        }};
    }

    let mut path_constraints = vec![];
    let mut optimizer = ConcatOptimizer::new(ctx);

    for (id, msg) in messages.iter().skip(start_index) {
        let msg = msg.clone();
        let tr: Option<TranslationEntry<'ctx, Dynamic<'ctx>>> = match msg {
            SymExpr::InputByte { offset, .. } => {
                let symbol = offset_to_symbol(offset);
                let bv = BV::new_const(ctx, Symbol::String(symbol.clone()), 8);
                Some(bv.into())
            }
            SymExpr::DataLength { value: _ } => {
                let symbol = "data_length".to_string();
                let bv = BV::new_const(ctx, Symbol::String(symbol.clone()), 64);
                Some(bv.into())
            }
            SymExpr::ScanfExtract {
                format_string: _,
                input_begin: _,
                input_end: _,
                arg_idx,
                arg_size,
                nonce,
                success: _,
            } => {
                let bv = BV::new_const(
                    ctx,
                    Symbol::String(format!("Scanf({},{})", nonce, arg_idx)),
                    (arg_size as u32) * 8,
                );
                Some(bv.into())
            }
            SymExpr::Integer { value, bits } => {
                Some(BV::from_u64(ctx, value, u32::from(bits)).into())
            }
            SymExpr::Integer128 { high, low, bits } => {
                let high_bv = BV::from_u64(ctx, high, (bits - 64).into());
                let low_bv = BV::from_u64(ctx, low, 64);
                Some(high_bv.concat(&low_bv).into())
            }
            // ─────────────────────────────── float ─────────────────────────────────
            SymExpr::Float { value, is_double } => {
                let float = if is_double {
                    Float::from_f64(ctx, value)
                } else {
                    Float::from_f32(ctx, value as f32)
                };
                Some(float.into())
            }
            // ──────────────────────────────── unary ─────────────────────────────────
            SymExpr::FloatNeg { op } => {
                let f = float!(op);
                Some(f.unary_neg().into())
            }
            // ────────────────────────────── arithmetic ─────────────────────────────────
            SymExpr::FloatAdd { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.add(&fb).into())
            }
            SymExpr::FloatSub { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.sub(&fb).into())
            }
            SymExpr::FloatMul { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.mul(&fb).into())
            }
            SymExpr::FloatDiv { a, b } => float_binop!(a div b),
            SymExpr::FloatRem { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.rem(&fb).into())
            }
            SymExpr::FloatToBits { op } => {
                let float = float!(op);
                Some(float.to_ieee_bv().into())
            }
            SymExpr::BitsToFloat { op, to_double } => {
                let bv = bv!(op);
                if to_double {
                    if bv.get_size() != 64 {
                        return Err(Error::invalid_data(format!(
                            "expected 64 bits for double, got {}",
                            bv.get_size()
                        )));
                    }
                } else {
                    if bv.get_size() != 32 {
                        return Err(Error::invalid_data(format!(
                            "expected 32 bits for float, got {}",
                            bv.get_size()
                        )));
                    }
                }
                let dynamic: TranslationEntry<'ctx, Dynamic<'ctx>> = bv.into();
                Some(dynamic.bv_to_float().into())
            }
            SymExpr::IntToFloat {
                op,
                is_double,
                is_signed,
            } => {
                let bv = bv!(op);
                let float = bv.to_float(is_double, is_signed);
                Some(float.into())
            }
            SymExpr::FloatToFloat { op, to_double } => {
                let float = float!(op);
                let new_float = float.to_other_float(to_double);
                Some(new_float.into())
            }
            SymExpr::FloatToSignedInteger { op, bits } => {
                let float = float!(op);
                let bv = float.to_int(bits as u32, true)?;
                Some(bv.into())
            }
            SymExpr::FloatToUnsignedInteger { op, bits } => {
                let float = float!(op);
                let bv = float.to_int(bits as u32, false)?;
                Some(bv.into())
            }

            // ───────────────────────────── ordered comparisons ────────────────────────
            SymExpr::FloatOrdered { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.ordered(&fb).into())
            }
            SymExpr::FloatOrderedGreaterThan { a, b } => float_ordered_comparison!(a gt b),
            SymExpr::FloatOrderedGreaterEqual { a, b } => float_ordered_comparison!(a ge b),
            SymExpr::FloatOrderedLessThan { a, b } => float_ordered_comparison!(a lt b),
            SymExpr::FloatOrderedLessEqual { a, b } => float_ordered_comparison!(a le b),
            SymExpr::FloatOrderedEqual { a, b } => float_ordered_comparison!(a _eq b),
            SymExpr::FloatOrderedNotEqual { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa._eq(&fb).not().into())
            }

            // ──────────────────────────── unordered comparisons ───────────────────────
            SymExpr::FloatUnordered { a, b } => {
                let fa = float!(a);
                let fb = float!(b);
                Some(fa.unordered(&fb).into())
            }
            SymExpr::FloatUnorderedGreaterThan { a, b } => float_unorderd_comparison!(a gt b),
            SymExpr::FloatUnorderedGreaterEqual { a, b } => float_unorderd_comparison!(a ge b),
            SymExpr::FloatUnorderedLessThan { a, b } => float_unorderd_comparison!(a lt b),
            SymExpr::FloatUnorderedLessEqual { a, b } => float_unorderd_comparison!(a le b),
            SymExpr::FloatUnorderedEqual { a, b } => float_unorderd_comparison!(a _eq b),
            SymExpr::FloatUnorderedNotEqual { a, b } => {
                let a = float!(a);
                let b = float!(b);
                let unordered = a.unordered(&b);
                let neq = a._eq(&b).not();
                Some(unordered.or(&neq).into())
            }
            SymExpr::FloatAbs { op } => {
                let float = float!(op);
                Some(float.unary_abs().into())
            }
            // --─────────────────────────────── other ─────────────────────────────────
            SymExpr::IntegerFromBuffer {} => todo!(),
            SymExpr::NullPointer => Some(BV::from_u64(ctx, 0, usize::BITS).into()),
            SymExpr::True => Some(Bool::from_bool(ctx, true).into()),
            SymExpr::False => Some(Bool::from_bool(ctx, false).into()),
            SymExpr::Bool { value } => Some(Bool::from_bool(ctx, value).into()),
            SymExpr::Neg { op } => Some(bv!(op).bvneg().into()),
            SymExpr::Add { a, b } => bv_binop!(a bvadd b),
            SymExpr::Sub { a, b } => bv_binop!(a bvsub b),
            SymExpr::Mul { a, b } => bv_binop!(a bvmul b),
            SymExpr::UnsignedDiv { a, b } => bv_binop!(a bvudiv b),
            SymExpr::SignedDiv { a, b } => bv_binop!(a bvsdiv b),
            SymExpr::UnsignedRem { a, b } => bv_binop!(a bvurem b),
            SymExpr::SignedRem { a, b } => bv_binop!(a bvsrem b),
            SymExpr::ShiftLeft { a, b } => bv_binop!(a bvshl b),
            SymExpr::LogicalShiftRight { a, b } => bv_binop!(a bvlshr b),
            SymExpr::ArithmeticShiftRight { a, b } => bv_binop!(a bvashr b),
            SymExpr::SignedLessThan { a, b } => bv_binop!(a bvslt b),
            SymExpr::SignedLessEqual { a, b } => bv_binop!(a bvsle b),
            SymExpr::SignedGreaterThan { a, b } => bv_binop!(a bvsgt b),
            SymExpr::SignedGreaterEqual { a, b } => bv_binop!(a bvsge b),
            SymExpr::UnsignedLessThan { a, b } => bv_binop!(a bvult b),
            SymExpr::UnsignedLessEqual { a, b } => bv_binop!(a bvule b),
            SymExpr::UnsignedGreaterThan { a, b } => bv_binop!(a bvugt b),
            SymExpr::UnsignedGreaterEqual { a, b } => bv_binop!(a bvuge b),
            SymExpr::Not { op } => {
                let translated = &translations[&op];
                Some(if let Some(bv) = translated.as_bv() {
                    bv.bvnot().expr().into()
                } else if let Some(bool) = translated.as_bool() {
                    bool.not().expr().into()
                } else {
                    panic!(
                        "unexpected z3 expr of type {:?} when applying not operation",
                        translated.kind()
                    )
                })
            }
            SymExpr::Equal { a, b } => Some(translations[&a]._eq(&translations[&b]).into()),
            SymExpr::NotEqual { a, b } => {
                Some(translations[&a]._eq(&translations[&b]).not().into())
            }
            SymExpr::BoolAnd { a, b } => Some(bool!(a).and(&bool!(b)).into()),
            SymExpr::BoolOr { a, b } => Some(bool!(a).or(&bool!(b)).into()),
            SymExpr::BoolXor { a, b } => Some(bool!(a).xor(&bool!(b)).into()),
            SymExpr::And { a, b } => bv_binop!(a bvand b),
            SymExpr::Or { a, b } => bv_binop!(a bvor b),
            SymExpr::Xor { a, b } => bv_binop!(a bvxor b),
            SymExpr::Sext { op, bits } => Some(bv!(op).sign_ext(u32::from(bits)).into()),
            SymExpr::Zext { op, bits } => Some(bv!(op).zero_ext(u32::from(bits)).into()),
            SymExpr::Trunc { op, bits } => Some(bv!(op).extract(u32::from(bits - 1), 0).into()),
            SymExpr::BoolToBit { op } => Some(
                bool!(op)
                    .ite(
                        &BV::from_u64(ctx, 1, 1).into(),
                        &BV::from_u64(ctx, 0, 1).into(),
                    )
                    .into(),
            ),
            SymExpr::Concat { a, b } => {
                if let Some(out) = bv_binop!(a concat b) {
                    let out = optimizer.optimize(out)?;
                    Some(out)
                } else {
                    None
                }
            }
            SymExpr::Extract {
                op,
                first_bit,
                last_bit,
            } => Some(bv!(op).extract(first_bit as u32, last_bit as u32).into()),
            SymExpr::Insert {
                target,
                to_insert,
                offset,
                little_endian,
            } => {
                let target = bv!(target);
                let to_insert = bv!(to_insert);
                let bits_to_insert = u64::from(to_insert.get_size());
                assert_eq!(bits_to_insert % 8, 0, "can only insert full bytes");
                let after_len = (u64::from(target.get_size()) / 8) - offset - (bits_to_insert / 8);
                Some(
                    [
                        if offset == 0 {
                            None
                        } else {
                            Some(build_extract(&target, 0, offset, false))
                        },
                        Some(if little_endian {
                            build_extract(&to_insert, 0, bits_to_insert / 8, true)
                        } else {
                            to_insert
                        }),
                        if after_len == 0 {
                            None
                        } else {
                            Some(build_extract(
                                &target,
                                offset + (bits_to_insert / 8),
                                after_len,
                                false,
                            ))
                        },
                    ]
                    .into_iter()
                    .reduce(
                        |acc: Option<TranslationEntry<'ctx, BV<'ctx>>>,
                         val: Option<TranslationEntry<'ctx, BV<'ctx>>>| {
                            match (acc, val) {
                                (Some(prev), Some(next)) => Some(prev.concat(&next)),
                                (Some(prev), None) => Some(prev),
                                (None, next) => next,
                            }
                        },
                    )
                    .unwrap()
                    .unwrap()
                    .into(),
                )
            }
            SymExpr::Ite { cond, a, b } => {
                let cond = bool!(cond);
                let a = bv!(a);
                let b = bv!(b);
                Some(cond.ite(&a, &b).into())
            }
            SymExpr::PathConstraint { .. }
            | SymExpr::Function { .. }
            | SymExpr::BasicBlock { .. }
            | SymExpr::Call { .. }
            | SymExpr::Return { .. }
            | SymExpr::SymbolicComputationInput { .. }
            | SymExpr::WriteMemory { .. }
            | SymExpr::ReadMemory { .. } => None,
            SymExpr::FailedFunctionHook {
                function_addr,
                ref reason,
                loc_id,
            } => {
                failed_hook_calls.push(SymCCFailedHookCall::Function {
                    function_addr,
                    reason: format!("{:?}", reason),
                    src_location: src_location_fn(loc_id),
                });
                None
            }
            SymExpr::FailedIntrinsicHook {
                intrinsic_id,
                ref reason,
                loc_id,
            } => {
                failed_hook_calls.push(SymCCFailedHookCall::Intrinsic {
                    intrinsic_id,
                    reason: format!("{:?}", reason),
                    src_location: src_location_fn(loc_id),
                });
                None
            }
            SymExpr::ExpressionsUnreachable { .. } => panic!(
                "unexpected z3 expr of type {:?} when processing message",
                msg
            ),
            SymExpr::SymbolicArrayInt {
                elem_cnt,
                elem_size,
            } => {
                let array_name = format!("sym_array_int_{}", id);
                Some(TranslationEntry::new_array_int(ctx, &array_name, elem_cnt, elem_size).into())
            }
            SymExpr::SymbolicArrayFP {
                elem_cnt,
                is_double,
            } => {
                let array_name = format!("sym_array_fp_{}", id);
                Some(TranslationEntry::new_array_fp(ctx, &array_name, elem_cnt, is_double).into())
            }
            SymExpr::InsertElement {
                vector,
                element,
                index,
            } => {
                let (vector, array_info) = array!(vector);
                match array_info {
                    ArrayInfo::Int { .. } => {
                        let index = u64::from(index);
                        // TODO: check if index is in bounds + element size matches size of
                        // bv!(element)
                        Some(vector.store(index, &bv!(element)).into())
                    }
                    ArrayInfo::FP { .. } => {
                        let index = u64::from(index);
                        Some(vector.store(index, &float!(element)).into())
                    }
                }
            }
            SymExpr::ExtractElement { vector, index } => {
                let (vector, array_info) = array!(vector);
                let index = u64::from(index);
                match array_info {
                    ArrayInfo::Int { .. } => Some(vector.select(index).into()),
                    ArrayInfo::FP { .. } => Some(vector.select(index).into()),
                }
            }
        };
        if let Some(tr) = tr {
            translations.insert(*id, tr.simplify());
        } else if let SymExpr::PathConstraint {
            constraint,
            taken,
            location,
        } = msg
        {
            if let Some(max_path_constraints) = max_path_constraints {
                if path_constraints.len() >= max_path_constraints {
                    break;
                }
            }
            let op = translations[&constraint].as_bool().unwrap();
            let location_u64 = location.0 as u64;
            let src_location = src_location_fn(location_u64);
            if op.expr().as_bool().is_none() || capture_constant_path_constraints {
                let path_constraint = PathConstraint::new(
                    location.0 as u64,
                    None,
                    taken,
                    PathConstraintExpr::new(
                        op.expr().simplify(),
                        op.depth(),
                        op.coerced_values().clone(),
                    ),
                    SymCCPathConstraintMetadata {
                        is_interesting: metadata.get(&(location.0 as u64)).cloned().unwrap_or(true),
                        src_location,
                    },
                );
                path_constraints.push(path_constraint);
            } else {
                // useless
            }
        } else if let SymExpr::SymbolicComputationInput {
            input,
            is_symbolic,
            loc_id,
        } = msg
        {
            if !is_symbolic {
                let concrete_value = translations[&input].clone();
                let variable_name = format!("coerced_{}", input);
                let variable: Dynamic<'ctx> = match concrete_value.expr().sort_kind() {
                    SortKind::BV => BV::new_const(
                        ctx,
                        Symbol::String(variable_name.clone()),
                        concrete_value.expr().as_bv().unwrap().get_size(),
                    )
                    .into(),
                    SortKind::Bool => {
                        Bool::new_const(ctx, Symbol::String(variable_name.clone())).into()
                    }
                    SortKind::FloatingPoint => {
                        let sort = concrete_value.expr().get_sort();
                        let ebits = sort.float_exponent_size().unwrap();
                        let sbits = sort.float_significand_size().unwrap();
                        Float::new_const(ctx, Symbol::String(variable_name.clone()), ebits, sbits)
                            .into()
                    }
                    SortKind::Array => {
                        let sort = concrete_value.expr().get_sort();
                        let array_domain = sort.array_domain().unwrap();
                        let array_range = sort.array_range().unwrap();
                        Array::new_const(
                            ctx,
                            Symbol::String(variable_name.clone()),
                            &array_domain,
                            &array_range,
                        )
                        .into()
                    }
                    _ => unreachable!(),
                };
                let coerced_values_for_tr: HashSet<Dynamic<'ctx>> =
                    vec![variable.clone()].into_iter().collect();
                if concrete_value.expr().sort_kind() == SortKind::Array {
                    let array_info = concrete_value.array_info().unwrap();
                    translations.insert(
                        input,
                        TranslationEntry::new_array(
                            variable.clone(),
                            0,
                            coerced_values_for_tr,
                            array_info.clone(),
                        ),
                    );
                } else {
                    translations.insert(
                        input,
                        TranslationEntry::new_scalar(variable.clone(), 0, coerced_values_for_tr),
                    );
                }
                coerced_values.insert(
                    variable_name,
                    SymCCCoercedValue {
                        variable,
                        concrete_value: concrete_value.expr().clone(),
                        src_location: src_location_fn(loc_id),
                        max_failed_hook_index: failed_hook_calls.len(),
                    },
                );
            }
        }
    }

    Ok(SymCCSymQEMULoadedTrace {
        messages,
        path_constraints,
        translations,
        coerced_values,
        failed_hook_calls,
    })
}

pub struct SymCCSolutionToInput {
    max_len: usize,
}

impl SymCCSolutionToInput {
    pub fn new(max_len: usize) -> Self {
        SymCCSolutionToInput { max_len }
    }
}

impl SolutionToInput for SymCCSolutionToInput {
    fn solution_to_input(
        &self,
        input: &[u8],
        solution: &AnnotatedSolution,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let mut new_inputs = vec![];
        let mut input_copy = input.to_vec();
        let mut new_length = None;
        for (symbol, value) in solution.sol.iter() {
            if let Some(offset_str) = symbol.strip_prefix("k!") {
                let byte_offset = usize::from_str_radix(offset_str, 10).map_err(|_| {
                    Error::invalid_data(format!(
                        "Invalid symbol name in solution to input {}",
                        symbol
                    ))
                })?;
                if byte_offset >= input_copy.len() {
                    // TODO: how to deal with this? This implies invalid instrumentation
                    // Think about why this happend in nginx
                    continue;
                } else {
                    input_copy[byte_offset] = (*value).try_into().map_err(|_| {
                        Error::invalid_data(format!(
                            "Byte replacement value exceeds 8-bits ({})",
                            value
                        ))
                    })?;
                }
            } else if symbol == "data_length" {
                new_length = Some(std::cmp::min(*value as usize, self.max_len));
            }
        }
        if input_copy != input {
            new_inputs.push(input_copy.clone());
        }
        if let Some(new_length) = new_length {
            if new_length > input.len() {
                let mut orig_input = input.to_vec();
                orig_input.extend(vec![0; new_length - input.len()]);
                new_inputs.push(orig_input);
                if input_copy != input {
                    input_copy.extend(vec![0; new_length - input.len()]);
                    new_inputs.push(input_copy);
                }
            } else if new_length < input.len() {
                let mut orig_input = input.to_vec();
                orig_input.truncate(new_length);
                new_inputs.push(orig_input);
                if input_copy != input {
                    input_copy.truncate(new_length);
                    new_inputs.push(input_copy);
                }
            }
        }
        Ok(new_inputs)
    }
}

pub const SYMCC_SOLUTION_CACHE_MAX_SIZE: usize = 0x10000;

pub struct SymCCSolutionCache<'ctxs> {
    observed_paths: HashSet<CompressedPath>,
    cached_solutions: IndexMap<InputID, AnnotatedSolution>,
    #[allow(unused)]
    ctx: &'ctxs z3::Context,
}

impl<'ctxs> SymCCSolutionCache<'ctxs> {
    pub fn new(ctx: &'ctxs z3::Context) -> Self {
        let mut cached_solutions = IndexMap::new();
        cached_solutions.reserve(SYMCC_SOLUTION_CACHE_MAX_SIZE);
        SymCCSolutionCache {
            observed_paths: HashSet::new(),
            cached_solutions,
            ctx,
        }
    }
}

type CompressedPath = u64;

impl<'ctx> SymCCSolutionCache<'ctx> {
    fn compress_path<'ctxp>(
        path_constraints: &[PathConstraint<'ctxp, SymCCPathConstraintMetadata>],
    ) -> CompressedPath {
        path_constraints
            .iter()
            .fold(DefaultHasher::new(), |mut acc, pc| {
                acc.write_u64(pc.site_id);
                acc.write_u8(pc.taken.into());
                acc
            })
            .finish()
    }
}

impl<'ctxp, 'ctxs> SolutionCache<'ctxp, 'ctxs, SymCCPathConstraintMetadata, SymCCAux<'ctxp>>
    for SymCCSolutionCache<'ctxs>
// This is unncessary but we need to specify it to make the compiler happy
// due to a notation bug in z3 (Z3_ast.translate)
where
    'ctxp: 'ctxs,
{
    fn add_solution(
        &mut self,
        input_id: InputID,
        solution: AnnotatedSolution,
        path_constraints: &[PathConstraint<'ctxp, SymCCPathConstraintMetadata>],
    ) -> Result<(), Error> {
        let compressed_path = Self::compress_path(path_constraints);
        self.observed_paths.insert(compressed_path);
        self.cached_solutions.insert(input_id, solution);
        if self.cached_solutions.len() > SYMCC_SOLUTION_CACHE_MAX_SIZE {
            self.cached_solutions
                .truncate(SYMCC_SOLUTION_CACHE_MAX_SIZE);
        }
        Ok(())
    }

    fn is_interesting(
        &self,
        path_constraints: &[PathConstraint<'ctxp, SymCCPathConstraintMetadata>],
    ) -> bool {
        if !path_constraints.last().unwrap().metadata.is_interesting {
            return false;
        } else {
            let compressed_path = Self::compress_path(path_constraints);
            return !self.observed_paths.contains(&compressed_path);
        }
    }

    fn get_random_cached_solution(
        &self,
        exclude: &[InputID],
    ) -> Option<(InputID, AnnotatedSolution)> {
        if self.cached_solutions.len() == 0 {
            return None;
        } else if self.cached_solutions.len() <= exclude.len() {
            let all_keys: HashSet<InputID> = self.cached_solutions.keys().cloned().collect();
            if all_keys.is_subset(&exclude.iter().cloned().collect()) {
                return None;
            }
        }
        let mut rng = rand::thread_rng();
        loop {
            let random_idx = rng.gen::<usize>() % self.cached_solutions.len();
            let (input_id, solution) = self.cached_solutions.get_index(random_idx).unwrap();
            if !exclude.contains(input_id) {
                return Some((*input_id, solution.clone()));
            }
        }
    }

    fn get_cached_solution(&self, input_id: InputID) -> Option<AnnotatedSolution> {
        self.cached_solutions.get(&input_id).cloned()
    }

    fn process_aux(&mut self, _aux: SymCCAux) -> Result<(), Error> {
        Ok(())
    }
}
