// This file is part of the SymCC runtime.
//
// The SymCC runtime is free software: you can redistribute it and/or modify it
// under the terms of the GNU Lesser General Public License as published by the
// Free Software Foundation, either version 3 of the License, or (at your
// option) any later version.
//
// The SymCC runtime is distributed in the hope that it will be useful, but
// WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License
// for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with SymCC. If not, see <https://www.gnu.org/licenses/>.

//
// Definitions that we need for the QSYM backend
//

#include "Runtime.h"
#include "GarbageCollection.h"

// C++
#if __has_include(<filesystem>)
#define HAVE_FILESYSTEM 1
#elif __has_include(<experimental/filesystem>)
#define HAVE_FILESYSTEM 0
#else
#error "We need either <filesystem> or the older <experimental/filesystem>."
#endif

#include <atomic>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <unordered_set>
#include <variant>

#ifdef DEBUG_RUNTIME
#include <chrono>
#endif

// C
#include <cstdint>
#include <cstdio>

// Runtime
#include <Config.h>
#include <LibcWrappers.h>
#include <Shadow.h>

namespace qsym {} // namespace qsym

/// Indicate whether the runtime has been initialized.
std::atomic_flag g_initialized = ATOMIC_FLAG_INIT;

/// A mapping of all expressions that we have ever received from QSYM to the
/// corresponding shared pointers on the heap.
///
/// We can't expect C clients to handle std::shared_ptr, so we maintain a single
/// copy per expression in order to keep the expression alive. The garbage
/// collector decides when to release our shared pointer.
///
/// std::map seems to perform slightly better than std::unordered_map on our
/// workload.

/// The user-provided test case handler, if any.
///
/// If the user doesn't register a handler, we use QSYM's default behavior of
/// writing the test case to a file in the output directory.
using namespace qsym;

void _sym_flush(void) {}

void _sym_initialize(void) {}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits) { return NULL; }

SymExpr _sym_build_integer128(uint64_t high, uint64_t low) { return NULL; }

SymExpr _sym_build_integer_from_buffer(void *buffer, unsigned num_bits) {
  return NULL;
}

SymExpr _sym_build_null_pointer() { return NULL; }

SymExpr _sym_build_true() { return NULL; }

SymExpr _sym_build_false() { return NULL; }

SymExpr _sym_build_bool(bool value) { return NULL; }

#define DEF_BINARY_EXPR_BUILDER(name, qsymName)                                \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) { return NULL; }

DEF_BINARY_EXPR_BUILDER(add, Add)
DEF_BINARY_EXPR_BUILDER(sub, Sub)
DEF_BINARY_EXPR_BUILDER(mul, Mul)
DEF_BINARY_EXPR_BUILDER(unsigned_div, UDiv)
DEF_BINARY_EXPR_BUILDER(signed_div, SDiv)
DEF_BINARY_EXPR_BUILDER(unsigned_rem, URem)
DEF_BINARY_EXPR_BUILDER(signed_rem, SRem)

DEF_BINARY_EXPR_BUILDER(shift_left, Shl)
DEF_BINARY_EXPR_BUILDER(logical_shift_right, LShr)
DEF_BINARY_EXPR_BUILDER(arithmetic_shift_right, AShr)

DEF_BINARY_EXPR_BUILDER(signed_less_than, Slt)
DEF_BINARY_EXPR_BUILDER(signed_less_equal, Sle)
DEF_BINARY_EXPR_BUILDER(signed_greater_than, Sgt)
DEF_BINARY_EXPR_BUILDER(signed_greater_equal, Sge)
DEF_BINARY_EXPR_BUILDER(unsigned_less_than, Ult)
DEF_BINARY_EXPR_BUILDER(unsigned_less_equal, Ule)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_than, Ugt)
DEF_BINARY_EXPR_BUILDER(unsigned_greater_equal, Uge)
DEF_BINARY_EXPR_BUILDER(equal, Equal)
DEF_BINARY_EXPR_BUILDER(not_equal, Distinct)

DEF_BINARY_EXPR_BUILDER(bool_and, LAnd)
DEF_BINARY_EXPR_BUILDER(and, And)
DEF_BINARY_EXPR_BUILDER(bool_or, LOr)
DEF_BINARY_EXPR_BUILDER(or, Or)
DEF_BINARY_EXPR_BUILDER(bool_xor, Distinct)
DEF_BINARY_EXPR_BUILDER(xor, Xor)

#undef DEF_BINARY_EXPR_BUILDER

SymExpr _sym_build_neg(SymExpr expr) { return NULL; }

SymExpr _sym_build_not(SymExpr expr) { return NULL; }

SymExpr _sym_build_ite(SymExpr cond, SymExpr a, SymExpr b) { return NULL; }

SymExpr _sym_build_sext(SymExpr expr, uint8_t bits) { return NULL; }

SymExpr _sym_build_zext(SymExpr expr, uint8_t bits) { return NULL; }

SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits) { return NULL; }

void _sym_push_path_constraint(SymExpr constraint, int taken,
                               uintptr_t site_id) {}

SymExpr _sym_get_input_byte(size_t offset, uint8_t value) { return NULL; }

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) { return NULL; }

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) {
  return NULL;
}

size_t _sym_bits_helper(SymExpr expr) { return 0; }

SymExpr _sym_build_bool_to_bit(SymExpr expr) { return NULL; }

//
// Floating-point operations (unsupported in QSYM)
//

// Even if we don't generally support operations on floats in this backend, we
// need dummy implementations of a few functions to help the parts of the
// instrumentation that deal with structures; if structs contain floats, the
// instrumentation expects to be able to create bit-vector expressions for
// them.

SymExpr _sym_build_float(double, int is_double) { return NULL; }

SymExpr _sym_build_float_to_bits(SymExpr expr) { return expr; }

#define UNSUPPORTED(prototype)                                                 \
  prototype { return nullptr; }

UNSUPPORTED(SymExpr _sym_build_fp_add(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_sub(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_mul(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_div(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_rem(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_abs(SymExpr))
UNSUPPORTED(SymExpr _sym_build_fp_neg(SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_greater_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_less_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_less_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered_not_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_ordered(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_greater_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_less_than(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_less_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_float_unordered_not_equal(SymExpr, SymExpr))
UNSUPPORTED(SymExpr _sym_build_int_to_float(SymExpr, int, int))
UNSUPPORTED(SymExpr _sym_build_float_to_float(SymExpr, int))
UNSUPPORTED(SymExpr _sym_build_bits_to_float(SymExpr, int))
UNSUPPORTED(SymExpr _sym_build_float_to_signed_integer(SymExpr, uint8_t))
UNSUPPORTED(SymExpr _sym_build_float_to_unsigned_integer(SymExpr, uint8_t))

#undef UNSUPPORTED
#undef H

//
// Call-stack tracing
//

void _sym_notify_call(uintptr_t site_id) {}

void _sym_notify_ret(uintptr_t site_id) {}

void _sym_notify_basic_block(uintptr_t site_id) {}

//
// Debugging
//

const char *_sym_expr_to_string(SymExpr expr) { return NULL; }

bool _sym_feasible(SymExpr expr) { return false; }

//
// Garbage collection
//

void _sym_collect_garbage() { return; }

//
// Test-case handling
//

void symcc_set_test_case_handler(TestCaseHandler handler) {}
