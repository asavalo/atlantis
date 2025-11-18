#include <cwchar>
#include <stdint.h>
#include <stdlib.h>
#include <Runtime.h>
void _sym_initialize(void) {};
SymExpr _sym_build_integer(uint64_t value, uint8_t bits) { return nullptr; }
SymExpr _sym_build_integer128(uint64_t high, uint64_t low) { return nullptr; }
SymExpr _sym_build_integer_from_buffer(void *buffer, unsigned num_bits) { return nullptr; }
SymExpr _sym_build_float(double value, int is_double) { return nullptr; }
SymExpr _sym_build_null_pointer(void) { return nullptr; }
SymExpr _sym_build_true(void) { return nullptr; }
SymExpr _sym_build_false(void) { return nullptr; }
SymExpr _sym_build_bool(bool value) { return nullptr; }

SymExpr _sym_build_neg(SymExpr expr) { return nullptr; }
SymExpr _sym_build_add(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_sub(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_mul(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_div(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_signed_div(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_rem(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_signed_rem(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_shift_left(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_logical_shift_right(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_arithmetic_shift_right(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_add(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_sub(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_mul(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_div(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_rem(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_fp_abs(SymExpr a) { return nullptr; }
SymExpr _sym_build_fp_neg(SymExpr a) { return nullptr; }

SymExpr _sym_build_not(SymExpr expr) { return nullptr; }
SymExpr _sym_build_signed_less_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_signed_less_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_signed_greater_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_signed_greater_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_less_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_less_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_greater_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_unsigned_greater_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_not_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_bool_and(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_and(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_bool_or(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_or(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_bool_xor(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_xor(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_ite(SymExpr cond, SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_greater_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_greater_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_less_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_less_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered_not_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_ordered(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_greater_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_greater_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_less_than(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_less_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_float_unordered_not_equal(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_build_sext(SymExpr expr, uint8_t bits) { return nullptr; }
SymExpr _sym_build_zext(SymExpr expr, uint8_t bits) { return nullptr; }
SymExpr _sym_build_trunc(SymExpr expr, uint8_t bits) { return nullptr; }
SymExpr _sym_build_int_to_float(SymExpr value, int is_double, int is_signed) { return nullptr; }
SymExpr _sym_build_float_to_float(SymExpr expr, int to_double) { return nullptr; }
SymExpr _sym_build_bits_to_float(SymExpr expr, int to_double) { return nullptr; }
SymExpr _sym_build_float_to_bits(SymExpr expr) { return nullptr; }
SymExpr _sym_build_float_to_signed_integer(SymExpr expr, uint8_t bits) { return nullptr; }
SymExpr _sym_build_float_to_unsigned_integer(SymExpr expr, uint8_t bits) { return nullptr; }
SymExpr _sym_build_bool_to_bit(SymExpr expr) { return nullptr; }

SymExpr _sym_concat_helper(SymExpr a, SymExpr b) { return nullptr; }
SymExpr _sym_extract_helper(SymExpr expr, size_t first_bit, size_t last_bit) { return nullptr; }
size_t _sym_bits_helper(SymExpr expr) { return 0; }

void _sym_push_path_constraint(SymExpr constraint, int taken, uintptr_t site_id) {}
SymExpr _sym_get_input_byte(size_t offset, uint8_t concrete_value) { return nullptr; }

void _sym_notify_call(uintptr_t site_id) {}
void _sym_notify_ret(uintptr_t site_id) {}
void _sym_notify_basic_block(uintptr_t site_id) {}
const char *_sym_expr_to_string(SymExpr expr) { return nullptr; } 
bool _sym_feasible(SymExpr expr) { return true; }
void _sym_collect_garbage(void) {}

