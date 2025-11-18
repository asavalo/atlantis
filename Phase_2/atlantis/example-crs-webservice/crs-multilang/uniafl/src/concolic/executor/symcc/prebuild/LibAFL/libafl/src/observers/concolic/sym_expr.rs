use std::vec::Vec;

use core::{
    fmt::{Debug, Display, Error, Formatter},
    num::NonZeroUsize,
};
use std::string::String;

use serde::{Deserialize, Serialize};

/// A `SymExprRef` identifies a [`SymExpr`] in a trace. Reading a `SymExpr` from a trace will always also yield its
/// `SymExprRef`, which can be used later in the trace to identify the `SymExpr`.
/// It is also never zero, which allows for efficient use of `Option<SymExprRef>`.
///
/// In a trace, `SymExprRef`s are monotonically increasing and start at 1.
/// `SymExprRef`s are not valid across traces.
pub type SymExprRef = NonZeroUsize;

#[allow(missing_docs)]
pub const INVALID_SYM_EXPR_REF: usize = 0x1337_1337;

/// [`Location`]s are code locations encountered during concolic tracing, that are constructed from pointers, but not always in a meaningful way.
/// Therefore, a location is an opaque value that can only be compared against itself.
///
/// It is possible to get at the underlying value using [`Into::into`], should this restriction be too inflexible for your usecase.
#[derive(Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(transparent)]
pub struct Location(pub usize);

impl Debug for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        Debug::fmt(&self.0, f)
    }
}

impl Display for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), Error> {
        Display::fmt(&self.0, f)
    }
}

impl From<Location> for usize {
    fn from(l: Location) -> Self {
        l.0
    }
}

impl From<usize> for Location {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

/// `SymExpr` represents a message in the serialization format.
/// The messages in the format are a perfect mirror of the methods that are called on the runtime during execution.
#[derive(Serialize, Clone, Deserialize, Debug, PartialEq)]
#[allow(missing_docs)]
pub enum SymExpr {
    InputByte {
        offset: usize,
        value: u8,
    },
    Integer {
        value: u64,
        bits: u8,
    },
    Integer128 {
        high: u64,
        low: u64,
        bits: u8,
    },
    IntegerFromBuffer {},
    Float {
        value: f64,
        is_double: bool,
    },
    NullPointer,
    True,
    False,
    Bool {
        value: bool,
    },

    Neg {
        op: SymExprRef,
    },
    Add {
        a: SymExprRef,
        b: SymExprRef,
    },
    Sub {
        a: SymExprRef,
        b: SymExprRef,
    },
    Mul {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedRem {
        a: SymExprRef,
        b: SymExprRef,
    },
    ShiftLeft {
        a: SymExprRef,
        b: SymExprRef,
    },
    LogicalShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },
    ArithmeticShiftRight {
        a: SymExprRef,
        b: SymExprRef,
    },

    SignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    SignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    UnsignedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    Not {
        op: SymExprRef,
    },
    Equal {
        a: SymExprRef,
        b: SymExprRef,
    },
    NotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    BoolAnd {
        a: SymExprRef,
        b: SymExprRef,
    },
    BoolOr {
        a: SymExprRef,
        b: SymExprRef,
    },
    BoolXor {
        a: SymExprRef,
        b: SymExprRef,
    },

    And {
        a: SymExprRef,
        b: SymExprRef,
    },
    Or {
        a: SymExprRef,
        b: SymExprRef,
    },
    Xor {
        a: SymExprRef,
        b: SymExprRef,
    },

    FloatOrdered {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatOrderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },

    FloatUnordered {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedGreaterThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedGreaterEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedLessThan {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedLessEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatUnorderedNotEqual {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatNeg {
        op: SymExprRef,
    },
    FloatAbs {
        op: SymExprRef,
    },
    FloatAdd {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatSub {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatMul {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatDiv {
        a: SymExprRef,
        b: SymExprRef,
    },
    FloatRem {
        a: SymExprRef,
        b: SymExprRef,
    },

    Ite {
        cond: SymExprRef,
        a: SymExprRef,
        b: SymExprRef,
    },
    Sext {
        op: SymExprRef,
        bits: u8,
    },
    Zext {
        op: SymExprRef,
        bits: u8,
    },
    Trunc {
        op: SymExprRef,
        bits: u8,
    },
    IntToFloat {
        op: SymExprRef,
        is_double: bool,
        is_signed: bool,
    },
    FloatToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    BitsToFloat {
        op: SymExprRef,
        to_double: bool,
    },
    FloatToBits {
        op: SymExprRef,
    },
    FloatToSignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    FloatToUnsignedInteger {
        op: SymExprRef,
        bits: u8,
    },
    BoolToBit {
        op: SymExprRef,
    },

    Concat {
        a: SymExprRef,
        b: SymExprRef,
    },
    Extract {
        op: SymExprRef,
        first_bit: usize,
        last_bit: usize,
    },
    Insert {
        target: SymExprRef,
        to_insert: SymExprRef,
        offset: u64,
        little_endian: bool,
    },

    PathConstraint {
        constraint: SymExprRef,
        taken: bool,
        location: Location,
    },

    /// These expressions won't be referenced again
    ExpressionsUnreachable {
        exprs: Vec<SymExprRef>,
    },

    /// Location information regarding a call. Tracing this information is optional.
    Call {
        location: Location,
    },
    /// Location information regarding a return. Tracing this information is optional.
    Return {
        location: Location,
    },
    /// Location information regarding a basic block. Tracing this information is optional.
    BasicBlock {
        location: Location,
    },
    /// Location information regarding a function. Tracing this information is optional.
    Function {
        location: Location,
    },
    /// Scanf and string related
    ScanfExtract {
        format_string: String,
        input_begin: u64,
        input_end: u64,
        arg_size: u64,
        arg_idx: u64,
        nonce: u64,
        success: bool,
    },
    /// Data length
    DataLength {
        value: u64,
    },
    SymbolicComputationInput {
        input: SymExprRef,
        loc_id: u64,
        is_symbolic: bool,
    },
    FailedFunctionHook {
        function_addr: u64,
        loc_id: u64,
        reason: FailedFunctionHookReason,
    },
    FailedIntrinsicHook {
        intrinsic_id: u64,
        loc_id: u64,
        reason: FailedIntrinsicHookReason,
    },
    ReadMemory {
        address: u64,
        size: u64,
        output: SymExprRef,
    },
    WriteMemory {
        address: u64,
        size: u64,
        input: SymExprRef,
    },
    InsertElement {
        vector: SymExprRef,
        element: SymExprRef,
        index: u64,
    },
    ExtractElement {
        vector: SymExprRef,
        index: u64,
    },
    SymbolicArrayInt {
        elem_cnt: u64,
        elem_size: u64,
    },
    SymbolicArrayFP {
        elem_cnt: u64,
        is_double: bool,
    },
}

#[derive(Serialize, Clone, Deserialize, Debug, PartialEq)]
pub enum FailedIntrinsicHookReason {
    MissingFunction,
    PythonException(String),
    Other(String),
}

#[derive(Serialize, Clone, Deserialize, Debug, PartialEq)]
pub enum FailedFunctionHookReason {
    MissingFunction,
    PythonException(String),
    Other(String),
}

impl SymExpr {
    /// Returns `true` if this variant “counts” as its own expression (i.e. increments the expression‐ID counter),
    /// or `false` otherwise.
    pub fn is_expr(&self) -> bool {
        match self {
            // ─────────────────────────────────────────────────────────────────────
            // “Leaf” expressions (always increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::InputByte { .. }
            | SymExpr::Integer { .. }
            | SymExpr::Integer128 { .. }
            | SymExpr::IntegerFromBuffer { .. }
            | SymExpr::Float { .. }
            | SymExpr::NullPointer
            | SymExpr::True
            | SymExpr::False
            | SymExpr::Bool { .. } => {
                // In both `transform_message` and `write_message`, these arms do `id_counter += 1`.
                true
            }

            // ─────────────────────────────────────────────────────────────────────
            // Unary‐op expressions (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::Neg { .. }
            | SymExpr::FloatAbs { .. }
            | SymExpr::FloatNeg { .. }
            | SymExpr::Not { .. }
            | SymExpr::Sext { .. }
            | SymExpr::Zext { .. }
            | SymExpr::Trunc { .. }
            | SymExpr::IntToFloat { .. }
            | SymExpr::FloatToFloat { .. }
            | SymExpr::BitsToFloat { .. }
            | SymExpr::FloatToBits { .. }
            | SymExpr::FloatToSignedInteger { .. }
            | SymExpr::FloatToUnsignedInteger { .. }
            | SymExpr::BoolToBit { .. }
            | SymExpr::Extract { .. } => {
                // `transform_message` and `write_message` do `id_counter += 1` here
                true
            }

            // ─────────────────────────────────────────────────────────────────────
            // Binary‐op expressions (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::Add { .. }
            | SymExpr::Sub { .. }
            | SymExpr::Mul { .. }
            | SymExpr::UnsignedDiv { .. }
            | SymExpr::SignedDiv { .. }
            | SymExpr::UnsignedRem { .. }
            | SymExpr::SignedRem { .. }
            | SymExpr::ShiftLeft { .. }
            | SymExpr::LogicalShiftRight { .. }
            | SymExpr::ArithmeticShiftRight { .. }
            | SymExpr::SignedLessThan { .. }
            | SymExpr::SignedLessEqual { .. }
            | SymExpr::SignedGreaterThan { .. }
            | SymExpr::SignedGreaterEqual { .. }
            | SymExpr::UnsignedLessThan { .. }
            | SymExpr::UnsignedLessEqual { .. }
            | SymExpr::UnsignedGreaterThan { .. }
            | SymExpr::UnsignedGreaterEqual { .. }
            | SymExpr::Equal { .. }
            | SymExpr::NotEqual { .. }
            | SymExpr::BoolAnd { .. }
            | SymExpr::BoolOr { .. }
            | SymExpr::BoolXor { .. }
            | SymExpr::And { .. }
            | SymExpr::Or { .. }
            | SymExpr::Xor { .. }
            | SymExpr::FloatOrdered { .. }
            | SymExpr::FloatOrderedGreaterThan { .. }
            | SymExpr::FloatOrderedGreaterEqual { .. }
            | SymExpr::FloatOrderedLessThan { .. }
            | SymExpr::FloatOrderedLessEqual { .. }
            | SymExpr::FloatOrderedEqual { .. }
            | SymExpr::FloatOrderedNotEqual { .. }
            | SymExpr::FloatUnordered { .. }
            | SymExpr::FloatUnorderedGreaterThan { .. }
            | SymExpr::FloatUnorderedGreaterEqual { .. }
            | SymExpr::FloatUnorderedLessThan { .. }
            | SymExpr::FloatUnorderedLessEqual { .. }
            | SymExpr::FloatUnorderedEqual { .. }
            | SymExpr::FloatUnorderedNotEqual { .. }
            | SymExpr::FloatAdd { .. }
            | SymExpr::FloatSub { .. }
            | SymExpr::FloatMul { .. }
            | SymExpr::FloatDiv { .. }
            | SymExpr::FloatRem { .. }
            | SymExpr::Concat { .. }
            | SymExpr::Insert { .. } => {
                // In `transform_message` / `write_message`, these do `id_counter += 1`
                true
            }

            // ─────────────────────────────────────────────────────────────────────
            // Ternary “if‐then‐else” (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::Ite { .. } => {
                // Both code paths show `id_counter += 1` here
                true
            }

            // ─────────────────────────────────────────────────────────────────────
            // ScanfExtract (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::ScanfExtract { .. } => {
                // `write_message` increments for ScanfExtract
                true
            }

            // ─────────────────────────────────────────────────────────────────────
            // DataLength (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::DataLength { .. } => true,

            // ─────────────────────────────────────────────────────────────────────
            // Vector operations (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::InsertElement { .. } => true,
            SymExpr::ExtractElement { .. } => true,

            // ─────────────────────────────────────────────────────────────────────
            // Symbolic‐array creations (increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::SymbolicArrayInt { .. } => true,
            SymExpr::SymbolicArrayFP { .. } => true,

            // ─────────────────────────────────────────────────────────────────────
            // PathConstraint (does NOT increment)
            // ─────────────────────────────────────────────────────────────────────
            SymExpr::PathConstraint { .. } => false,

            // ExpressionsUnreachable (does NOT increment)
            SymExpr::ExpressionsUnreachable { .. } => false,

            // Call, Return, BasicBlock, Function, ReadMemory, WriteMemory (all do NOT increment)
            SymExpr::Call { .. } => false,
            SymExpr::Return { .. } => false,
            SymExpr::BasicBlock { .. } => false,
            SymExpr::Function { .. } => false,
            SymExpr::ReadMemory { .. } => false,
            SymExpr::WriteMemory { .. } => false,

            // SymbolicComputationInput (does NOT increment)
            SymExpr::SymbolicComputationInput { .. } => false,

            // FailedFunctionHook (does NOT increment)
            SymExpr::FailedFunctionHook { .. } => false,
            SymExpr::FailedIntrinsicHook { .. } => false,
        }
    }
}
