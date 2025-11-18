// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

// clang-format off
#include "Runtime.h"
#include "RustRuntime.h"
#include "RuntimeCommon.h"
#include "Semaphore.h"
// clang-format on

#include <atomic>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <set>
#include <vector>
#ifndef NDEBUG
#include <chrono>
#endif

#include "Config.h"
#include "GarbageCollection.h"
#include "LibcWrappers.h"
#include "Shadow.h"
#include "Vector.h"
#ifndef NDEBUG
// Helper to print pointers properly.
#define P(ptr) reinterpret_cast<void *>(ptr)
#endif

/* TODO Eventually we'll want to inline as much of this as possible. I'm keeping
   it in C for now because that makes it easier to experiment with new features,
   but I expect that a lot of the functions will stay so simple that we can
   generate the corresponding bitcode directly in the compiler pass. */

namespace {

/// Indicate whether the runtime has been initialized.
std::atomic_flag g_initialized = ATOMIC_FLAG_INIT;

FILE *g_log = stderr;

#ifndef NDEBUG
[[maybe_unused]] void dump_known_regions() {
  std::cerr << "Known regions:" << std::endl;
  for (const auto &[page, shadow] : g_shadow_pages) {
    std::cerr << "  " << P(page) << " shadowed by " << P(shadow) << std::endl;
  }
}

#endif

/// The set of all expressions we have ever passed to client code.
std::set<SymExpr> allocatedExpressions;

SymExpr registerExpression(SymExpr expr) {
  allocatedExpressions.insert(expr);
  return expr;
}

// To understand why the following functions exist, read the Bits Helper section
// in the README.

// Get the bit width out of a SymExpr.
uint16_t symexpr_width(SymExpr expr) {
  return (uint16_t)((uintptr_t)expr & UINT16_MAX);
}

// Get the id out of a SymExpr (which is an RSymExpr).
RSymExpr symexpr_id(SymExpr expr) { return (uintptr_t)expr >> 16; }

// Construct a SymExpr from a RSymExpr and a bit width.
SymExpr symexpr(RSymExpr expr, uint16_t width) {
  if (expr == 0) {
    // ensure that 0 RSymExpr still maps to 0 in SymExpr, as this is a special
    // value for the rest of the backend.
    return 0;
  }
  // ensure that the RSymExpr fits inside the SymExpr.
  assert((((expr << 16) >> 16) == expr) && "expr is too large to be stored");
  return (SymExpr)((expr << 16) | width);
}
} // namespace

void _sym_initialize(void) {
  if (g_initialized.test_and_set())
    return;

#ifndef NDEBUG
  std::cerr << "Initializing symbolic runtime" << std::endl;
#endif

  loadConfig();
  initLibcWrappers();
  init_sema();
}

SymExpr _sym_build_integer(uint64_t value, uint8_t bits) {
  return registerExpression(symexpr(_rsym_build_integer(value, bits), bits));
}

SymExpr _sym_build_integer128(uint64_t high, uint64_t low, uint8_t bits) {
  return registerExpression(
      symexpr(_rsym_build_integer128(high, low, bits), 128));
}

SymExpr _sym_build_integer_from_buffer(void *buffer, unsigned num_bits) {
  assert(num_bits % 8 == 0 && num_bits > 0 &&
         "num_bits must be a multiple of 8");
  unsigned num_bytes = num_bits / 8;
  uint8_t *bufferPtr = (uint8_t *)buffer;
  auto retExpr = _sym_build_integer(*bufferPtr, 8);
  bufferPtr++;
  for (unsigned i = 1; i < num_bytes; i++, bufferPtr++) {
    retExpr = _sym_concat_helper(retExpr, _sym_build_integer(*bufferPtr, 8));
  }
  return retExpr;
}

SymExpr _sym_build_float(double value, int is_double) {
  return registerExpression(
      symexpr(_rsym_build_float(value, is_double), is_double ? 64 : 32));
}

SymExpr _sym_get_input_byte(size_t offset, uint8_t value) {
  return registerExpression(symexpr(_rsym_get_input_byte(offset, value), 8));
}

SymExpr _sym_build_null_pointer(void) {
  return registerExpression(
      symexpr(_rsym_build_null_pointer(), sizeof(uintptr_t) * 8));
}

SymExpr _sym_build_true(void) {
  return registerExpression(symexpr(_rsym_build_true(), 0));
}

SymExpr _sym_build_false(void) {
  return registerExpression(symexpr(_rsym_build_false(), 0));
}

SymExpr _sym_build_bool(bool value) {
  return registerExpression(symexpr(_rsym_build_bool(value), 0));
}

#define DEF_UNARY_EXPR_BUILDER(name)                                           \
  SymExpr _sym_build_##name(SymExpr expr) {                                    \
    return registerExpression(                                                 \
        symexpr(_rsym_build_##name(symexpr_id(expr)), symexpr_width(expr)));   \
  }

DEF_UNARY_EXPR_BUILDER(neg)

#define DEF_BINARY_BV_EXPR_BUILDER(name)                                       \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) {                            \
    return registerExpression(symexpr(                                         \
        _rsym_build_##name(symexpr_id(a), symexpr_id(b)), symexpr_width(a)));  \
  }

DEF_BINARY_BV_EXPR_BUILDER(add)
DEF_BINARY_BV_EXPR_BUILDER(sub)
DEF_BINARY_BV_EXPR_BUILDER(mul)
DEF_BINARY_BV_EXPR_BUILDER(unsigned_div)
DEF_BINARY_BV_EXPR_BUILDER(signed_div)
DEF_BINARY_BV_EXPR_BUILDER(unsigned_rem)
DEF_BINARY_BV_EXPR_BUILDER(signed_rem)
DEF_BINARY_BV_EXPR_BUILDER(shift_left)
DEF_BINARY_BV_EXPR_BUILDER(logical_shift_right)
DEF_BINARY_BV_EXPR_BUILDER(arithmetic_shift_right)

#define DEF_BINARY_BOOL_EXPR_BUILDER(name)                                     \
  SymExpr _sym_build_##name(SymExpr a, SymExpr b) {                            \
    return registerExpression(                                                 \
        symexpr(_rsym_build_##name(symexpr_id(a), symexpr_id(b)), 0));         \
  }

DEF_BINARY_BOOL_EXPR_BUILDER(signed_less_than)
DEF_BINARY_BOOL_EXPR_BUILDER(signed_less_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(signed_greater_than)
DEF_BINARY_BOOL_EXPR_BUILDER(signed_greater_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(unsigned_less_than)
DEF_BINARY_BOOL_EXPR_BUILDER(unsigned_less_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(unsigned_greater_than)
DEF_BINARY_BOOL_EXPR_BUILDER(unsigned_greater_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(equal)

DEF_BINARY_BV_EXPR_BUILDER(and)
DEF_BINARY_BV_EXPR_BUILDER(or)
DEF_BINARY_BV_EXPR_BUILDER(bool_xor)
DEF_BINARY_BV_EXPR_BUILDER(xor)

DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_greater_than)
DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_greater_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_less_than)
DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_less_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_equal)

DEF_BINARY_BV_EXPR_BUILDER(fp_add)
DEF_BINARY_BV_EXPR_BUILDER(fp_sub)
DEF_BINARY_BV_EXPR_BUILDER(fp_mul)
DEF_BINARY_BV_EXPR_BUILDER(fp_div)
DEF_BINARY_BV_EXPR_BUILDER(fp_rem)

#undef DEF_BINARY_BV_EXPR_BUILDER

DEF_UNARY_EXPR_BUILDER(fp_abs)
DEF_UNARY_EXPR_BUILDER(fp_neg)

DEF_UNARY_EXPR_BUILDER(not )
DEF_BINARY_BOOL_EXPR_BUILDER(not_equal)

#undef DEF_UNARY_EXPR_BUILDER

DEF_BINARY_BOOL_EXPR_BUILDER(bool_and)
DEF_BINARY_BOOL_EXPR_BUILDER(bool_or)

DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered_not_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_ordered)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered)

DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_greater_than)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_greater_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_less_than)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_less_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_equal)
DEF_BINARY_BOOL_EXPR_BUILDER(float_unordered_not_equal)

#undef DEF_BINARY_BOOL_EXPR_BUILDER

SymExpr _sym_build_ite(SymExpr cond, SymExpr a, SymExpr b) {
  return registerExpression(symexpr(
      _rsym_build_ite(symexpr_id(cond), symexpr_id(a), symexpr_id(b)), 0));
}

SymExpr _sym_build_sext(SymExpr expr, uint8_t bits) {
  return registerExpression(symexpr(_rsym_build_sext(symexpr_id(expr), bits),
                                    symexpr_width(expr) + bits));
}

SymExpr _sym_build_zext(SymExpr expr, uint8_t bits) {
  return registerExpression(symexpr(_rsym_build_zext(symexpr_id(expr), bits),
                                    symexpr_width(expr) + bits));
}

SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits) {
  return registerExpression(
      symexpr(_rsym_build_trunc(symexpr_id(expr), bits), bits));
}

SymExpr _sym_build_int_to_float(SymExpr expr, int is_double, int is_signed) {
  return registerExpression(
      symexpr(_rsym_build_int_to_float(symexpr_id(expr), is_double, is_signed),
              is_double ? 64 : 32));
}

SymExpr _sym_build_float_to_float(SymExpr expr, int to_double) {
  return registerExpression(
      symexpr(_rsym_build_float_to_float(symexpr_id(expr), to_double),
              to_double ? 64 : 32));
}

SymExpr _sym_build_bits_to_float(SymExpr expr, int to_double) {
  if (expr == 0)
    return 0;

  return registerExpression(
      symexpr(_rsym_build_bits_to_float(symexpr_id(expr), to_double),
              to_double ? 64 : 32));
}

SymExpr _sym_build_float_to_bits(SymExpr expr) {
  if (expr == nullptr)
    return nullptr;
  return registerExpression(symexpr(_rsym_build_float_to_bits(symexpr_id(expr)),
                                    symexpr_width(expr)));
}

SymExpr _sym_build_float_to_signed_integer(SymExpr expr, uint8_t bits) {
  return registerExpression(symexpr(
      _rsym_build_float_to_signed_integer(symexpr_id(expr), bits), bits));
}

SymExpr _sym_build_float_to_unsigned_integer(SymExpr expr, uint8_t bits) {
  return registerExpression(symexpr(
      _rsym_build_float_to_unsigned_integer(symexpr_id(expr), bits), bits));
}

SymExpr _sym_build_bool_to_bit(SymExpr expr) {
  return registerExpression(
      symexpr(_rsym_build_bool_to_bit(symexpr_id(expr)), 1));
}

void _sym_push_path_constraint(SymExpr constraint, int taken,
                               uintptr_t site_id) {
  if (!g_config.fullTrace && constraint == 0)
    return;
  // if full trace is enabled, this function will dump the path constraints to
  // the filesystem
  _rsym_push_path_constraint(symexpr_id(constraint), taken, site_id);
  if (g_config.fullTrace) {
    wait_start();
    sym_commit();
    post_end();
  }
}

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) {
  return registerExpression(
      symexpr(_rsym_concat_helper(symexpr_id(a), symexpr_id(b)),
              symexpr_width(a) + symexpr_width(b)));
}

SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) {
  return registerExpression(
      symexpr(_rsym_extract_helper(symexpr_id(expr), first_bit, last_bit),
              first_bit - last_bit + 1));
}

SymExpr _sym_build_scanf_extract(const char *format, int input_begin,
                                 int input_end, int arg_idx, int arg_size,
                                 int nonce, uint8_t success) {
  return registerExpression(
      symexpr(_rsym_build_scanf_extract(format, input_begin, input_end, arg_idx,
                                        arg_size, nonce, success),
              arg_size * 8));
}

SymExpr _sym_build_data_length(unsigned long data_length) {
  if (!g_config.symbolizeDataLength) {
    return nullptr;
  }
  return registerExpression(symexpr(_rsym_build_data_length(data_length), 64));
}

size_t _sym_bits_helper(SymExpr expr) { return symexpr_width(expr); }

void _sym_notify_call(uintptr_t loc) { _rsym_notify_call(loc); }
void _sym_notify_ret(uintptr_t loc) { _rsym_notify_ret(loc); }
void _sym_notify_basic_block(uintptr_t loc) { _rsym_notify_basic_block(loc); }
void _sym_notify_function(uintptr_t loc) { _rsym_notify_function(loc); }

/* Debugging */
const char *_sym_expr_to_string(SymExpr) { return nullptr; }

bool _sym_feasible(SymExpr) { return false; }

/* Garbage collection */
void _sym_collect_garbage() {
  if (allocatedExpressions.size() < g_config.garbageCollectionThreshold)
    return;

#ifndef NDEBUG
  auto start = std::chrono::high_resolution_clock::now();
  auto startSize = allocatedExpressions.size();
#endif

  std::vector<RSymExpr> unreachable_expressions;

  auto reachableExpressions = collectReachableExpressions();
  for (auto expr_it = allocatedExpressions.begin();
       expr_it != allocatedExpressions.end();) {
    if (reachableExpressions.count(*expr_it) == 0) {
      unreachable_expressions.push_back(symexpr_id(*expr_it));
      expr_it = allocatedExpressions.erase(expr_it);
    } else {
      ++expr_it;
    }
  }
  if (unreachable_expressions.size() > 0) {
    _rsym_expression_unreachable(unreachable_expressions.data(),
                                 unreachable_expressions.size());
  }

#ifndef NDEBUG
  auto end = std::chrono::high_resolution_clock::now();
  auto endSize = allocatedExpressions.size();

  std::cerr << "After garbage collection: " << endSize
            << " expressions remain (before: " << startSize << ")" << std::endl
            << "\t(collection took "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " milliseconds)" << std::endl;
#endif
}

void _sym_notify_symbolic_computation_input(SymExpr inputExpr, uint64_t locId,
                                            bool isSymbolic) {
  // inputExpr is always nonzero because it is concretized if not
  if (inputExpr == 0) {
    throw std::runtime_error{
        "inputExpr should be non null for symbolic computation input"};
  }
  if (g_config.fullTrace) {
    _rsym_notify_symbolic_computation_input(symexpr_id(inputExpr), locId,
                                            isSymbolic);
  }
}

void _sym_notify_read_memory(uint8_t *addr, size_t length, SymExpr output) {
  if (!g_config.fullTrace) {
    _rsym_notify_read_memory((uintptr_t)addr, length, symexpr_id(output));
  }
}

void _sym_notify_write_memory(uint8_t *addr, size_t length, SymExpr input) {
  if (!g_config.fullTrace) {
    _rsym_notify_write_memory((uintptr_t)addr, length, symexpr_id(input));
  }
}

SymExpr _sym_hook_function_call(uint64_t function_addr, uint64_t loc_id,
                                bool concrete_return_value_valid,
                                uint64_t concrete_return_value,
                                uint64_t concrete_return_value_size,
                                uint64_t nargs, ...) {
  // get all varargs
  va_list args_list;
  va_start(args_list, nargs);
  SymExpr *args = (SymExpr *)calloc(nargs, sizeof(SymExpr));
  bool *concrete_args_valid = (bool *)calloc(nargs, sizeof(bool));
  uint64_t *concrete_args = (uint64_t *)calloc(nargs, sizeof(uint64_t));
  for (uint64_t i = 0; i < nargs; i++) {
    args[i] = va_arg(args_list, SymExpr);
    concrete_args_valid[i] = va_arg(args_list, bool);
    concrete_args[i] = va_arg(args_list, uint64_t);
  }
  va_end(args_list);
  // be careful! although the name starts with _rsym, because we use _sym helper
  // functions inside the hook, args must be SymExpr
  RSymExpr rsym_ret = _rsym_hook_function_call(
      function_addr, loc_id, concrete_return_value_valid, concrete_return_value,
      args, concrete_args_valid, concrete_args, nargs);
  SymExpr ret = symexpr(rsym_ret, concrete_return_value_size);
  free(args);
  free(concrete_args_valid);
  free(concrete_args);
  return registerExpression(ret);
}

SymExpr _sym_hook_intrinsic_call(uint64_t intrinsic_id, uint64_t loc_id,
                                 bool concrete_return_value_valid,
                                 uint64_t concrete_return_value,
                                 uint64_t concrete_return_value_size,
                                 uint64_t nargs, ...) {
  // get all varargs
  va_list args_list;
  va_start(args_list, nargs);
  SymExpr *args = (SymExpr *)calloc(nargs, sizeof(SymExpr));
  bool *concrete_args_valid = (bool *)calloc(nargs, sizeof(bool));
  uint64_t *concrete_args = (uint64_t *)calloc(nargs, sizeof(uint64_t));
  for (uint64_t i = 0; i < nargs; i++) {
    args[i] = va_arg(args_list, SymExpr);
    concrete_args_valid[i] = va_arg(args_list, bool);
    concrete_args[i] = va_arg(args_list, uint64_t);
  }

  va_end(args_list);
  SymExpr ret = symexpr(_rsym_hook_intrinsic_call(
                            intrinsic_id, loc_id, concrete_return_value_valid,
                            concrete_return_value, args, concrete_args_valid,
                            concrete_args, nargs),
                        concrete_return_value_size);
  free(args);
  free(concrete_args_valid);
  free(concrete_args);
  return registerExpression(ret);
}

SymExpr _sym_build_insert_element(SymExpr expr, SymExpr element,
                                  uint64_t index) {
  // TODO: assert that target is an array type
  if (expr == 0) {
    // TODO: This should NEVER happen
    return 0;
  }
  VectorInfo vec_info = getVectorInfo(expr);
  SymExpr ret = symexpr(
      _rsym_build_insert_element(symexpr_id(expr), symexpr_id(element), index),
      symexpr_width(expr));
  if (ret) {
    registerVectorInfo(ret, vec_info.elem_cnt, vec_info.elem_size);
  }
  return ret;
}

SymExpr _sym_build_extract_element(SymExpr expr, uint64_t index) {
  if (expr == 0) {
    // TODO: This should NEVER happen
    return 0;
  }
  VectorInfo vec_info = getVectorInfo(expr);
  SymExpr ret = symexpr(_rsym_build_extract_element(symexpr_id(expr), index),
                        vec_info.elem_size);

  return ret;
}

SymExpr _sym_build_symbolic_array_int(uint64_t elem_cnt, uint64_t elem_size) {
  SymExpr ret = registerExpression(
      symexpr(_rsym_build_symbolic_array_int(elem_cnt, elem_size), 0));
  if (ret) {
    registerVectorInfo(ret, elem_cnt, elem_size);
  }
  return ret;
}

SymExpr _sym_build_symbolic_array_fp(uint64_t elem_cnt, bool is_double) {
  SymExpr ret = registerExpression(
      symexpr(_rsym_build_symbolic_array_fp(elem_cnt, is_double),
              // TODO: is this right?? what should we provide as size here?
              0));
  if (ret) {
    registerVectorInfo(ret, elem_cnt, is_double ? 64 : 32);
  }
  return ret;
}
