import ctypes

SymExpr = ctypes.c_void_p

lib = ctypes.CDLL(None)

# SymExpr _sym_build_integer(uint64_t, uint8_t)
_sym_build_integer = lib._sym_build_integer
_sym_build_integer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_sym_build_integer.restype = SymExpr

# SymExpr _sym_build_integer128(uint64_t, uint64_t, uint8_t)
_sym_build_integer128 = lib._sym_build_integer128
_sym_build_integer128.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_sym_build_integer128.restype = SymExpr

# SymExpr _sym_build_integer_from_buffer(void *, unsigned int)
_sym_build_integer_from_buffer = lib._sym_build_integer_from_buffer
_sym_build_integer_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_uint]
_sym_build_integer_from_buffer.restype = SymExpr

# SymExpr _sym_build_float(double, int)
_sym_build_float = lib._sym_build_float
_sym_build_float.argtypes = [ctypes.c_double, ctypes.c_int]
_sym_build_float.restype = SymExpr

# SymExpr _sym_build_null_pointer()
_sym_build_null_pointer = lib._sym_build_null_pointer
_sym_build_null_pointer.argtypes = []
_sym_build_null_pointer.restype = SymExpr

# SymExpr _sym_build_true()
_sym_build_true = lib._sym_build_true
_sym_build_true.argtypes = []
_sym_build_true.restype = SymExpr

# SymExpr _sym_build_false()
_sym_build_false = lib._sym_build_false
_sym_build_false.argtypes = []
_sym_build_false.restype = SymExpr

# SymExpr _sym_build_bool(bool)
_sym_build_bool = lib._sym_build_bool
_sym_build_bool.argtypes = [ctypes.c_bool]
_sym_build_bool.restype = SymExpr

# SymExpr _sym_build_neg(SymExpr)
_sym_build_neg = lib._sym_build_neg
_sym_build_neg.argtypes = [SymExpr]
_sym_build_neg.restype = SymExpr

# SymExpr _sym_build_add(SymExpr, SymExpr)
_sym_build_add = lib._sym_build_add
_sym_build_add.argtypes = [SymExpr, SymExpr]
_sym_build_add.restype = SymExpr

# SymExpr _sym_build_sub(SymExpr, SymExpr)
_sym_build_sub = lib._sym_build_sub
_sym_build_sub.argtypes = [SymExpr, SymExpr]
_sym_build_sub.restype = SymExpr

# SymExpr _sym_build_mul(SymExpr, SymExpr)
_sym_build_mul = lib._sym_build_mul
_sym_build_mul.argtypes = [SymExpr, SymExpr]
_sym_build_mul.restype = SymExpr

# SymExpr _sym_build_unsigned_div(SymExpr, SymExpr)
_sym_build_unsigned_div = lib._sym_build_unsigned_div
_sym_build_unsigned_div.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_div.restype = SymExpr

# SymExpr _sym_build_signed_div(SymExpr, SymExpr)
_sym_build_signed_div = lib._sym_build_signed_div
_sym_build_signed_div.argtypes = [SymExpr, SymExpr]
_sym_build_signed_div.restype = SymExpr

# SymExpr _sym_build_unsigned_rem(SymExpr, SymExpr)
_sym_build_unsigned_rem = lib._sym_build_unsigned_rem
_sym_build_unsigned_rem.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_rem.restype = SymExpr

# SymExpr _sym_build_signed_rem(SymExpr, SymExpr)
_sym_build_signed_rem = lib._sym_build_signed_rem
_sym_build_signed_rem.argtypes = [SymExpr, SymExpr]
_sym_build_signed_rem.restype = SymExpr

# SymExpr _sym_build_shift_left(SymExpr, SymExpr)
_sym_build_shift_left = lib._sym_build_shift_left
_sym_build_shift_left.argtypes = [SymExpr, SymExpr]
_sym_build_shift_left.restype = SymExpr

# SymExpr _sym_build_logical_shift_right(SymExpr, SymExpr)
_sym_build_logical_shift_right = lib._sym_build_logical_shift_right
_sym_build_logical_shift_right.argtypes = [SymExpr, SymExpr]
_sym_build_logical_shift_right.restype = SymExpr

# SymExpr _sym_build_arithmetic_shift_right(SymExpr, SymExpr)
_sym_build_arithmetic_shift_right = lib._sym_build_arithmetic_shift_right
_sym_build_arithmetic_shift_right.argtypes = [SymExpr, SymExpr]
_sym_build_arithmetic_shift_right.restype = SymExpr

# SymExpr _sym_build_funnel_shift_left(SymExpr, SymExpr, SymExpr)
_sym_build_funnel_shift_left = lib._sym_build_funnel_shift_left
_sym_build_funnel_shift_left.argtypes = [SymExpr, SymExpr, SymExpr]
_sym_build_funnel_shift_left.restype = SymExpr

# SymExpr _sym_build_funnel_shift_right(SymExpr, SymExpr, SymExpr)
_sym_build_funnel_shift_right = lib._sym_build_funnel_shift_right
_sym_build_funnel_shift_right.argtypes = [SymExpr, SymExpr, SymExpr]
_sym_build_funnel_shift_right.restype = SymExpr

# SymExpr _sym_build_abs(SymExpr)
_sym_build_abs = lib._sym_build_abs
_sym_build_abs.argtypes = [SymExpr]
_sym_build_abs.restype = SymExpr

# SymExpr _sym_build_add_overflow(SymExpr, SymExpr, bool, bool)
_sym_build_add_overflow = lib._sym_build_add_overflow
_sym_build_add_overflow.argtypes = [SymExpr, SymExpr, ctypes.c_bool, ctypes.c_bool]
_sym_build_add_overflow.restype = SymExpr

# SymExpr _sym_build_sub_overflow(SymExpr, SymExpr, bool, bool)
_sym_build_sub_overflow = lib._sym_build_sub_overflow
_sym_build_sub_overflow.argtypes = [SymExpr, SymExpr, ctypes.c_bool, ctypes.c_bool]
_sym_build_sub_overflow.restype = SymExpr

# SymExpr _sym_build_mul_overflow(SymExpr, SymExpr, bool, bool)
_sym_build_mul_overflow = lib._sym_build_mul_overflow
_sym_build_mul_overflow.argtypes = [SymExpr, SymExpr, ctypes.c_bool, ctypes.c_bool]
_sym_build_mul_overflow.restype = SymExpr

# SymExpr _sym_build_sadd_sat(SymExpr, SymExpr)
_sym_build_sadd_sat = lib._sym_build_sadd_sat
_sym_build_sadd_sat.argtypes = [SymExpr, SymExpr]
_sym_build_sadd_sat.restype = SymExpr

# SymExpr _sym_build_uadd_sat(SymExpr, SymExpr)
_sym_build_uadd_sat = lib._sym_build_uadd_sat
_sym_build_uadd_sat.argtypes = [SymExpr, SymExpr]
_sym_build_uadd_sat.restype = SymExpr

# SymExpr _sym_build_ssub_sat(SymExpr, SymExpr)
_sym_build_ssub_sat = lib._sym_build_ssub_sat
_sym_build_ssub_sat.argtypes = [SymExpr, SymExpr]
_sym_build_ssub_sat.restype = SymExpr

# SymExpr _sym_build_usub_sat(SymExpr, SymExpr)
_sym_build_usub_sat = lib._sym_build_usub_sat
_sym_build_usub_sat.argtypes = [SymExpr, SymExpr]
_sym_build_usub_sat.restype = SymExpr

# SymExpr _sym_build_sshl_sat(SymExpr, SymExpr)
_sym_build_sshl_sat = lib._sym_build_sshl_sat
_sym_build_sshl_sat.argtypes = [SymExpr, SymExpr]
_sym_build_sshl_sat.restype = SymExpr

# SymExpr _sym_build_ushl_sat(SymExpr, SymExpr)
_sym_build_ushl_sat = lib._sym_build_ushl_sat
_sym_build_ushl_sat.argtypes = [SymExpr, SymExpr]
_sym_build_ushl_sat.restype = SymExpr

# SymExpr _sym_build_fp_add(SymExpr, SymExpr)
_sym_build_fp_add = lib._sym_build_fp_add
_sym_build_fp_add.argtypes = [SymExpr, SymExpr]
_sym_build_fp_add.restype = SymExpr

# SymExpr _sym_build_fp_sub(SymExpr, SymExpr)
_sym_build_fp_sub = lib._sym_build_fp_sub
_sym_build_fp_sub.argtypes = [SymExpr, SymExpr]
_sym_build_fp_sub.restype = SymExpr

# SymExpr _sym_build_fp_mul(SymExpr, SymExpr)
_sym_build_fp_mul = lib._sym_build_fp_mul
_sym_build_fp_mul.argtypes = [SymExpr, SymExpr]
_sym_build_fp_mul.restype = SymExpr

# SymExpr _sym_build_fp_div(SymExpr, SymExpr)
_sym_build_fp_div = lib._sym_build_fp_div
_sym_build_fp_div.argtypes = [SymExpr, SymExpr]
_sym_build_fp_div.restype = SymExpr

# SymExpr _sym_build_fp_rem(SymExpr, SymExpr)
_sym_build_fp_rem = lib._sym_build_fp_rem
_sym_build_fp_rem.argtypes = [SymExpr, SymExpr]
_sym_build_fp_rem.restype = SymExpr

# SymExpr _sym_build_fp_abs(SymExpr)
_sym_build_fp_abs = lib._sym_build_fp_abs
_sym_build_fp_abs.argtypes = [SymExpr]
_sym_build_fp_abs.restype = SymExpr

# SymExpr _sym_build_fp_neg(SymExpr)
_sym_build_fp_neg = lib._sym_build_fp_neg
_sym_build_fp_neg.argtypes = [SymExpr]
_sym_build_fp_neg.restype = SymExpr

# SymExpr _sym_build_not(SymExpr)
_sym_build_not = lib._sym_build_not
_sym_build_not.argtypes = [SymExpr]
_sym_build_not.restype = SymExpr

# SymExpr _sym_build_signed_less_than(SymExpr, SymExpr)
_sym_build_signed_less_than = lib._sym_build_signed_less_than
_sym_build_signed_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_signed_less_than.restype = SymExpr

# SymExpr _sym_build_signed_less_equal(SymExpr, SymExpr)
_sym_build_signed_less_equal = lib._sym_build_signed_less_equal
_sym_build_signed_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_signed_less_equal.restype = SymExpr

# SymExpr _sym_build_signed_greater_than(SymExpr, SymExpr)
_sym_build_signed_greater_than = lib._sym_build_signed_greater_than
_sym_build_signed_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_signed_greater_than.restype = SymExpr

# SymExpr _sym_build_signed_greater_equal(SymExpr, SymExpr)
_sym_build_signed_greater_equal = lib._sym_build_signed_greater_equal
_sym_build_signed_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_signed_greater_equal.restype = SymExpr

# SymExpr _sym_build_unsigned_less_than(SymExpr, SymExpr)
_sym_build_unsigned_less_than = lib._sym_build_unsigned_less_than
_sym_build_unsigned_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_less_than.restype = SymExpr

# SymExpr _sym_build_unsigned_less_equal(SymExpr, SymExpr)
_sym_build_unsigned_less_equal = lib._sym_build_unsigned_less_equal
_sym_build_unsigned_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_less_equal.restype = SymExpr

# SymExpr _sym_build_unsigned_greater_than(SymExpr, SymExpr)
_sym_build_unsigned_greater_than = lib._sym_build_unsigned_greater_than
_sym_build_unsigned_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_greater_than.restype = SymExpr

# SymExpr _sym_build_unsigned_greater_equal(SymExpr, SymExpr)
_sym_build_unsigned_greater_equal = lib._sym_build_unsigned_greater_equal
_sym_build_unsigned_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_greater_equal.restype = SymExpr

# SymExpr _sym_build_equal(SymExpr, SymExpr)
_sym_build_equal = lib._sym_build_equal
_sym_build_equal.argtypes = [SymExpr, SymExpr]
_sym_build_equal.restype = SymExpr

# SymExpr _sym_build_not_equal(SymExpr, SymExpr)
_sym_build_not_equal = lib._sym_build_not_equal
_sym_build_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_not_equal.restype = SymExpr

# SymExpr _sym_build_bool_and(SymExpr, SymExpr)
_sym_build_bool_and = lib._sym_build_bool_and
_sym_build_bool_and.argtypes = [SymExpr, SymExpr]
_sym_build_bool_and.restype = SymExpr

# SymExpr _sym_build_and(SymExpr, SymExpr)
_sym_build_and = lib._sym_build_and
_sym_build_and.argtypes = [SymExpr, SymExpr]
_sym_build_and.restype = SymExpr

# SymExpr _sym_build_bool_or(SymExpr, SymExpr)
_sym_build_bool_or = lib._sym_build_bool_or
_sym_build_bool_or.argtypes = [SymExpr, SymExpr]
_sym_build_bool_or.restype = SymExpr

# SymExpr _sym_build_or(SymExpr, SymExpr)
_sym_build_or = lib._sym_build_or
_sym_build_or.argtypes = [SymExpr, SymExpr]
_sym_build_or.restype = SymExpr

# SymExpr _sym_build_bool_xor(SymExpr, SymExpr)
_sym_build_bool_xor = lib._sym_build_bool_xor
_sym_build_bool_xor.argtypes = [SymExpr, SymExpr]
_sym_build_bool_xor.restype = SymExpr

# SymExpr _sym_build_xor(SymExpr, SymExpr)
_sym_build_xor = lib._sym_build_xor
_sym_build_xor.argtypes = [SymExpr, SymExpr]
_sym_build_xor.restype = SymExpr

# SymExpr _sym_build_ite(SymExpr, SymExpr, SymExpr)
_sym_build_ite = lib._sym_build_ite
_sym_build_ite.argtypes = [SymExpr, SymExpr, SymExpr]
_sym_build_ite.restype = SymExpr

# SymExpr _sym_build_float_ordered_greater_than(SymExpr, SymExpr)
_sym_build_float_ordered_greater_than = lib._sym_build_float_ordered_greater_than
_sym_build_float_ordered_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_greater_than.restype = SymExpr

# SymExpr _sym_build_float_ordered_greater_equal(SymExpr, SymExpr)
_sym_build_float_ordered_greater_equal = lib._sym_build_float_ordered_greater_equal
_sym_build_float_ordered_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_greater_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered_less_than(SymExpr, SymExpr)
_sym_build_float_ordered_less_than = lib._sym_build_float_ordered_less_than
_sym_build_float_ordered_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_less_than.restype = SymExpr

# SymExpr _sym_build_float_ordered_less_equal(SymExpr, SymExpr)
_sym_build_float_ordered_less_equal = lib._sym_build_float_ordered_less_equal
_sym_build_float_ordered_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_less_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered_equal(SymExpr, SymExpr)
_sym_build_float_ordered_equal = lib._sym_build_float_ordered_equal
_sym_build_float_ordered_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered_not_equal(SymExpr, SymExpr)
_sym_build_float_ordered_not_equal = lib._sym_build_float_ordered_not_equal
_sym_build_float_ordered_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_not_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered(SymExpr, SymExpr)
_sym_build_float_ordered = lib._sym_build_float_ordered
_sym_build_float_ordered.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered.restype = SymExpr

# SymExpr _sym_build_float_unordered(SymExpr, SymExpr)
_sym_build_float_unordered = lib._sym_build_float_unordered
_sym_build_float_unordered.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered.restype = SymExpr

# SymExpr _sym_build_float_unordered_greater_than(SymExpr, SymExpr)
_sym_build_float_unordered_greater_than = lib._sym_build_float_unordered_greater_than
_sym_build_float_unordered_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_greater_than.restype = SymExpr

# SymExpr _sym_build_float_unordered_greater_equal(SymExpr, SymExpr)
_sym_build_float_unordered_greater_equal = lib._sym_build_float_unordered_greater_equal
_sym_build_float_unordered_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_greater_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_less_than(SymExpr, SymExpr)
_sym_build_float_unordered_less_than = lib._sym_build_float_unordered_less_than
_sym_build_float_unordered_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_less_than.restype = SymExpr

# SymExpr _sym_build_float_unordered_less_equal(SymExpr, SymExpr)
_sym_build_float_unordered_less_equal = lib._sym_build_float_unordered_less_equal
_sym_build_float_unordered_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_less_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_equal(SymExpr, SymExpr)
_sym_build_float_unordered_equal = lib._sym_build_float_unordered_equal
_sym_build_float_unordered_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_not_equal(SymExpr, SymExpr)
_sym_build_float_unordered_not_equal = lib._sym_build_float_unordered_not_equal
_sym_build_float_unordered_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_not_equal.restype = SymExpr

# SymExpr _sym_build_sext(SymExpr, uint8_t)
_sym_build_sext = lib._sym_build_sext
_sym_build_sext.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_sext.restype = SymExpr

# SymExpr _sym_build_zext(SymExpr, uint8_t)
_sym_build_zext = lib._sym_build_zext
_sym_build_zext.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_zext.restype = SymExpr

# SymExpr _sym_build_trunc(SymExpr, uint8_t)
_sym_build_trunc = lib._sym_build_trunc
_sym_build_trunc.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_trunc.restype = SymExpr

# SymExpr _sym_build_bswap(SymExpr)
_sym_build_bswap = lib._sym_build_bswap
_sym_build_bswap.argtypes = [SymExpr]
_sym_build_bswap.restype = SymExpr

# SymExpr _sym_build_int_to_float(SymExpr, int, int)
_sym_build_int_to_float = lib._sym_build_int_to_float
_sym_build_int_to_float.argtypes = [SymExpr, ctypes.c_int, ctypes.c_int]
_sym_build_int_to_float.restype = SymExpr

# SymExpr _sym_build_float_to_float(SymExpr, int)
_sym_build_float_to_float = lib._sym_build_float_to_float
_sym_build_float_to_float.argtypes = [SymExpr, ctypes.c_int]
_sym_build_float_to_float.restype = SymExpr

# SymExpr _sym_build_bits_to_float(SymExpr, int)
_sym_build_bits_to_float = lib._sym_build_bits_to_float
_sym_build_bits_to_float.argtypes = [SymExpr, ctypes.c_int]
_sym_build_bits_to_float.restype = SymExpr

# SymExpr _sym_build_float_to_bits(SymExpr)
_sym_build_float_to_bits = lib._sym_build_float_to_bits
_sym_build_float_to_bits.argtypes = [SymExpr]
_sym_build_float_to_bits.restype = SymExpr

# SymExpr _sym_build_float_to_signed_integer(SymExpr, uint8_t)
_sym_build_float_to_signed_integer = lib._sym_build_float_to_signed_integer
_sym_build_float_to_signed_integer.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_float_to_signed_integer.restype = SymExpr

# SymExpr _sym_build_float_to_unsigned_integer(SymExpr, uint8_t)
_sym_build_float_to_unsigned_integer = lib._sym_build_float_to_unsigned_integer
_sym_build_float_to_unsigned_integer.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_float_to_unsigned_integer.restype = SymExpr

# SymExpr _sym_build_bool_to_bit(SymExpr)
_sym_build_bool_to_bit = lib._sym_build_bool_to_bit
_sym_build_bool_to_bit.argtypes = [SymExpr]
_sym_build_bool_to_bit.restype = SymExpr

# SymExpr _sym_build_bit_to_bool(SymExpr)
_sym_build_bit_to_bool = lib._sym_build_bit_to_bool
_sym_build_bit_to_bool.argtypes = [SymExpr]
_sym_build_bit_to_bool.restype = SymExpr

# SymExpr _sym_concat_helper(SymExpr, SymExpr)
_sym_concat_helper = lib._sym_concat_helper
_sym_concat_helper.argtypes = [SymExpr, SymExpr]
_sym_concat_helper.restype = SymExpr

# SymExpr _sym_extract_helper(SymExpr, size_t, size_t)
_sym_extract_helper = lib._sym_extract_helper
_sym_extract_helper.argtypes = [SymExpr, ctypes.c_void_p, ctypes.c_void_p]
_sym_extract_helper.restype = SymExpr

# size_t _sym_bits_helper(SymExpr)
_sym_bits_helper = lib._sym_bits_helper
_sym_bits_helper.argtypes = [SymExpr]
_sym_bits_helper.restype = ctypes.c_void_p

# void _sym_push_path_constraint(SymExpr, int, uintptr_t)
_sym_push_path_constraint = lib._sym_push_path_constraint
_sym_push_path_constraint.argtypes = [SymExpr, ctypes.c_int, ctypes.c_void_p]
_sym_push_path_constraint.restype = None

# SymExpr _sym_read_memory(uint8_t *, size_t, bool)
_sym_read_memory = lib._sym_read_memory
_sym_read_memory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]
_sym_read_memory.restype = SymExpr

# void _sym_write_memory(uint8_t *, size_t, SymExpr, bool)
_sym_write_memory = lib._sym_write_memory
_sym_write_memory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, SymExpr, ctypes.c_bool]
_sym_write_memory.restype = None

# void _sym_memcpy(uint8_t *, const uint8_t *, size_t)
_sym_memcpy = lib._sym_memcpy
_sym_memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_sym_memcpy.restype = None

# SymExpr _sym_build_zero_bytes(size_t)
_sym_build_zero_bytes = lib._sym_build_zero_bytes
_sym_build_zero_bytes.argtypes = [ctypes.c_void_p]
_sym_build_zero_bytes.restype = SymExpr

# SymExpr _sym_build_insert(SymExpr, SymExpr, uint64_t, bool)
_sym_build_insert = lib._sym_build_insert
_sym_build_insert.argtypes = [SymExpr, SymExpr, ctypes.c_void_p, ctypes.c_bool]
_sym_build_insert.restype = SymExpr

# SymExpr _sym_build_insert_element(SymExpr, SymExpr, uint64_t)
_sym_build_insert_element = lib._sym_build_insert_element
_sym_build_insert_element.argtypes = [SymExpr, SymExpr, ctypes.c_void_p]
_sym_build_insert_element.restype = SymExpr

# SymExpr _sym_build_extract(SymExpr, uint64_t, uint64_t, bool)
_sym_build_extract = lib._sym_build_extract
_sym_build_extract.argtypes = [SymExpr, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_bool]
_sym_build_extract.restype = SymExpr

# SymExpr _sym_build_extract_element(SymExpr, uint64_t)
_sym_build_extract_element = lib._sym_build_extract_element
_sym_build_extract_element.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_extract_element.restype = SymExpr

# SymExpr _sym_build_scanf_extract(const char *, int, int, int, int, int, uint8_t)
_sym_build_scanf_extract = lib._sym_build_scanf_extract
_sym_build_scanf_extract.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_sym_build_scanf_extract.restype = SymExpr

# SymExpr _sym_build_data_length(unsigned long)
_sym_build_data_length = lib._sym_build_data_length
_sym_build_data_length.argtypes = [ctypes.c_ulong]
_sym_build_data_length.restype = SymExpr

# SymExpr _sym_build_extract_element(SymExpr, uint64_t)
_sym_build_extract_element = lib._sym_build_extract_element
_sym_build_extract_element.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_extract_element.restype = SymExpr

# SymExpr _sym_build_insert_element(SymExpr, SymExpr, uint64_t)
_sym_build_insert_element = lib._sym_build_insert_element
_sym_build_insert_element.argtypes = [SymExpr, SymExpr, ctypes.c_void_p]
_sym_build_insert_element.restype = SymExpr

# SymExpr _sym_build_symbolic_array_int(uint64_t, uint64_t)
_sym_build_symbolic_array_int = lib._sym_build_symbolic_array_int
_sym_build_symbolic_array_int.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_sym_build_symbolic_array_int.restype = SymExpr

# SymExpr _sym_build_symbolic_array_fp(uint64_t, bool)
_sym_build_symbolic_array_fp = lib._sym_build_symbolic_array_fp
_sym_build_symbolic_array_fp.argtypes = [ctypes.c_void_p, ctypes.c_bool]
_sym_build_symbolic_array_fp.restype = SymExpr

# SymExpr _sym_build_integer(uint64_t, uint8_t)
_sym_build_integer = lib._sym_build_integer
_sym_build_integer.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_sym_build_integer.restype = SymExpr

# SymExpr _sym_build_integer128(uint64_t, uint64_t, uint8_t)
_sym_build_integer128 = lib._sym_build_integer128
_sym_build_integer128.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p]
_sym_build_integer128.restype = SymExpr

# SymExpr _sym_build_integer_from_buffer(void *, unsigned int)
_sym_build_integer_from_buffer = lib._sym_build_integer_from_buffer
_sym_build_integer_from_buffer.argtypes = [ctypes.c_void_p, ctypes.c_uint]
_sym_build_integer_from_buffer.restype = SymExpr

# SymExpr _sym_build_float(double, int)
_sym_build_float = lib._sym_build_float
_sym_build_float.argtypes = [ctypes.c_double, ctypes.c_int]
_sym_build_float.restype = SymExpr

# SymExpr _sym_build_null_pointer()
_sym_build_null_pointer = lib._sym_build_null_pointer
_sym_build_null_pointer.argtypes = []
_sym_build_null_pointer.restype = SymExpr

# SymExpr _sym_build_true()
_sym_build_true = lib._sym_build_true
_sym_build_true.argtypes = []
_sym_build_true.restype = SymExpr

# SymExpr _sym_build_false()
_sym_build_false = lib._sym_build_false
_sym_build_false.argtypes = []
_sym_build_false.restype = SymExpr

# SymExpr _sym_build_bool(bool)
_sym_build_bool = lib._sym_build_bool
_sym_build_bool.argtypes = [ctypes.c_bool]
_sym_build_bool.restype = SymExpr

# SymExpr _sym_build_neg(SymExpr)
_sym_build_neg = lib._sym_build_neg
_sym_build_neg.argtypes = [SymExpr]
_sym_build_neg.restype = SymExpr

# SymExpr _sym_build_add(SymExpr, SymExpr)
_sym_build_add = lib._sym_build_add
_sym_build_add.argtypes = [SymExpr, SymExpr]
_sym_build_add.restype = SymExpr

# SymExpr _sym_build_sub(SymExpr, SymExpr)
_sym_build_sub = lib._sym_build_sub
_sym_build_sub.argtypes = [SymExpr, SymExpr]
_sym_build_sub.restype = SymExpr

# SymExpr _sym_build_mul(SymExpr, SymExpr)
_sym_build_mul = lib._sym_build_mul
_sym_build_mul.argtypes = [SymExpr, SymExpr]
_sym_build_mul.restype = SymExpr

# SymExpr _sym_build_unsigned_div(SymExpr, SymExpr)
_sym_build_unsigned_div = lib._sym_build_unsigned_div
_sym_build_unsigned_div.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_div.restype = SymExpr

# SymExpr _sym_build_signed_div(SymExpr, SymExpr)
_sym_build_signed_div = lib._sym_build_signed_div
_sym_build_signed_div.argtypes = [SymExpr, SymExpr]
_sym_build_signed_div.restype = SymExpr

# SymExpr _sym_build_unsigned_rem(SymExpr, SymExpr)
_sym_build_unsigned_rem = lib._sym_build_unsigned_rem
_sym_build_unsigned_rem.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_rem.restype = SymExpr

# SymExpr _sym_build_signed_rem(SymExpr, SymExpr)
_sym_build_signed_rem = lib._sym_build_signed_rem
_sym_build_signed_rem.argtypes = [SymExpr, SymExpr]
_sym_build_signed_rem.restype = SymExpr

# SymExpr _sym_build_shift_left(SymExpr, SymExpr)
_sym_build_shift_left = lib._sym_build_shift_left
_sym_build_shift_left.argtypes = [SymExpr, SymExpr]
_sym_build_shift_left.restype = SymExpr

# SymExpr _sym_build_logical_shift_right(SymExpr, SymExpr)
_sym_build_logical_shift_right = lib._sym_build_logical_shift_right
_sym_build_logical_shift_right.argtypes = [SymExpr, SymExpr]
_sym_build_logical_shift_right.restype = SymExpr

# SymExpr _sym_build_arithmetic_shift_right(SymExpr, SymExpr)
_sym_build_arithmetic_shift_right = lib._sym_build_arithmetic_shift_right
_sym_build_arithmetic_shift_right.argtypes = [SymExpr, SymExpr]
_sym_build_arithmetic_shift_right.restype = SymExpr

# SymExpr _sym_build_signed_less_than(SymExpr, SymExpr)
_sym_build_signed_less_than = lib._sym_build_signed_less_than
_sym_build_signed_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_signed_less_than.restype = SymExpr

# SymExpr _sym_build_signed_less_equal(SymExpr, SymExpr)
_sym_build_signed_less_equal = lib._sym_build_signed_less_equal
_sym_build_signed_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_signed_less_equal.restype = SymExpr

# SymExpr _sym_build_signed_greater_than(SymExpr, SymExpr)
_sym_build_signed_greater_than = lib._sym_build_signed_greater_than
_sym_build_signed_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_signed_greater_than.restype = SymExpr

# SymExpr _sym_build_signed_greater_equal(SymExpr, SymExpr)
_sym_build_signed_greater_equal = lib._sym_build_signed_greater_equal
_sym_build_signed_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_signed_greater_equal.restype = SymExpr

# SymExpr _sym_build_unsigned_less_than(SymExpr, SymExpr)
_sym_build_unsigned_less_than = lib._sym_build_unsigned_less_than
_sym_build_unsigned_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_less_than.restype = SymExpr

# SymExpr _sym_build_unsigned_less_equal(SymExpr, SymExpr)
_sym_build_unsigned_less_equal = lib._sym_build_unsigned_less_equal
_sym_build_unsigned_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_less_equal.restype = SymExpr

# SymExpr _sym_build_unsigned_greater_than(SymExpr, SymExpr)
_sym_build_unsigned_greater_than = lib._sym_build_unsigned_greater_than
_sym_build_unsigned_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_greater_than.restype = SymExpr

# SymExpr _sym_build_unsigned_greater_equal(SymExpr, SymExpr)
_sym_build_unsigned_greater_equal = lib._sym_build_unsigned_greater_equal
_sym_build_unsigned_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_unsigned_greater_equal.restype = SymExpr

# SymExpr _sym_build_equal(SymExpr, SymExpr)
_sym_build_equal = lib._sym_build_equal
_sym_build_equal.argtypes = [SymExpr, SymExpr]
_sym_build_equal.restype = SymExpr

# SymExpr _sym_build_and(SymExpr, SymExpr)
_sym_build_and = lib._sym_build_and
_sym_build_and.argtypes = [SymExpr, SymExpr]
_sym_build_and.restype = SymExpr

# SymExpr _sym_build_or(SymExpr, SymExpr)
_sym_build_or = lib._sym_build_or
_sym_build_or.argtypes = [SymExpr, SymExpr]
_sym_build_or.restype = SymExpr

# SymExpr _sym_build_bool_xor(SymExpr, SymExpr)
_sym_build_bool_xor = lib._sym_build_bool_xor
_sym_build_bool_xor.argtypes = [SymExpr, SymExpr]
_sym_build_bool_xor.restype = SymExpr

# SymExpr _sym_build_xor(SymExpr, SymExpr)
_sym_build_xor = lib._sym_build_xor
_sym_build_xor.argtypes = [SymExpr, SymExpr]
_sym_build_xor.restype = SymExpr

# SymExpr _sym_build_float_ordered_greater_than(SymExpr, SymExpr)
_sym_build_float_ordered_greater_than = lib._sym_build_float_ordered_greater_than
_sym_build_float_ordered_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_greater_than.restype = SymExpr

# SymExpr _sym_build_float_ordered_greater_equal(SymExpr, SymExpr)
_sym_build_float_ordered_greater_equal = lib._sym_build_float_ordered_greater_equal
_sym_build_float_ordered_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_greater_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered_less_than(SymExpr, SymExpr)
_sym_build_float_ordered_less_than = lib._sym_build_float_ordered_less_than
_sym_build_float_ordered_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_less_than.restype = SymExpr

# SymExpr _sym_build_float_ordered_less_equal(SymExpr, SymExpr)
_sym_build_float_ordered_less_equal = lib._sym_build_float_ordered_less_equal
_sym_build_float_ordered_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_less_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered_equal(SymExpr, SymExpr)
_sym_build_float_ordered_equal = lib._sym_build_float_ordered_equal
_sym_build_float_ordered_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_equal.restype = SymExpr

# SymExpr _sym_build_fp_add(SymExpr, SymExpr)
_sym_build_fp_add = lib._sym_build_fp_add
_sym_build_fp_add.argtypes = [SymExpr, SymExpr]
_sym_build_fp_add.restype = SymExpr

# SymExpr _sym_build_fp_sub(SymExpr, SymExpr)
_sym_build_fp_sub = lib._sym_build_fp_sub
_sym_build_fp_sub.argtypes = [SymExpr, SymExpr]
_sym_build_fp_sub.restype = SymExpr

# SymExpr _sym_build_fp_mul(SymExpr, SymExpr)
_sym_build_fp_mul = lib._sym_build_fp_mul
_sym_build_fp_mul.argtypes = [SymExpr, SymExpr]
_sym_build_fp_mul.restype = SymExpr

# SymExpr _sym_build_fp_div(SymExpr, SymExpr)
_sym_build_fp_div = lib._sym_build_fp_div
_sym_build_fp_div.argtypes = [SymExpr, SymExpr]
_sym_build_fp_div.restype = SymExpr

# SymExpr _sym_build_fp_rem(SymExpr, SymExpr)
_sym_build_fp_rem = lib._sym_build_fp_rem
_sym_build_fp_rem.argtypes = [SymExpr, SymExpr]
_sym_build_fp_rem.restype = SymExpr

# SymExpr _sym_build_fp_abs(SymExpr)
_sym_build_fp_abs = lib._sym_build_fp_abs
_sym_build_fp_abs.argtypes = [SymExpr]
_sym_build_fp_abs.restype = SymExpr

# SymExpr _sym_build_fp_neg(SymExpr)
_sym_build_fp_neg = lib._sym_build_fp_neg
_sym_build_fp_neg.argtypes = [SymExpr]
_sym_build_fp_neg.restype = SymExpr

# SymExpr _sym_build_not(SymExpr)
_sym_build_not = lib._sym_build_not
_sym_build_not.argtypes = [SymExpr]
_sym_build_not.restype = SymExpr

# SymExpr _sym_build_not_equal(SymExpr, SymExpr)
_sym_build_not_equal = lib._sym_build_not_equal
_sym_build_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_not_equal.restype = SymExpr

# SymExpr _sym_build_bool_and(SymExpr, SymExpr)
_sym_build_bool_and = lib._sym_build_bool_and
_sym_build_bool_and.argtypes = [SymExpr, SymExpr]
_sym_build_bool_and.restype = SymExpr

# SymExpr _sym_build_bool_or(SymExpr, SymExpr)
_sym_build_bool_or = lib._sym_build_bool_or
_sym_build_bool_or.argtypes = [SymExpr, SymExpr]
_sym_build_bool_or.restype = SymExpr

# SymExpr _sym_build_float_ordered_not_equal(SymExpr, SymExpr)
_sym_build_float_ordered_not_equal = lib._sym_build_float_ordered_not_equal
_sym_build_float_ordered_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered_not_equal.restype = SymExpr

# SymExpr _sym_build_float_ordered(SymExpr, SymExpr)
_sym_build_float_ordered = lib._sym_build_float_ordered
_sym_build_float_ordered.argtypes = [SymExpr, SymExpr]
_sym_build_float_ordered.restype = SymExpr

# SymExpr _sym_build_float_unordered(SymExpr, SymExpr)
_sym_build_float_unordered = lib._sym_build_float_unordered
_sym_build_float_unordered.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered.restype = SymExpr

# SymExpr _sym_build_float_unordered_greater_than(SymExpr, SymExpr)
_sym_build_float_unordered_greater_than = lib._sym_build_float_unordered_greater_than
_sym_build_float_unordered_greater_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_greater_than.restype = SymExpr

# SymExpr _sym_build_float_unordered_greater_equal(SymExpr, SymExpr)
_sym_build_float_unordered_greater_equal = lib._sym_build_float_unordered_greater_equal
_sym_build_float_unordered_greater_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_greater_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_less_than(SymExpr, SymExpr)
_sym_build_float_unordered_less_than = lib._sym_build_float_unordered_less_than
_sym_build_float_unordered_less_than.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_less_than.restype = SymExpr

# SymExpr _sym_build_float_unordered_less_equal(SymExpr, SymExpr)
_sym_build_float_unordered_less_equal = lib._sym_build_float_unordered_less_equal
_sym_build_float_unordered_less_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_less_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_equal(SymExpr, SymExpr)
_sym_build_float_unordered_equal = lib._sym_build_float_unordered_equal
_sym_build_float_unordered_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_equal.restype = SymExpr

# SymExpr _sym_build_float_unordered_not_equal(SymExpr, SymExpr)
_sym_build_float_unordered_not_equal = lib._sym_build_float_unordered_not_equal
_sym_build_float_unordered_not_equal.argtypes = [SymExpr, SymExpr]
_sym_build_float_unordered_not_equal.restype = SymExpr

# SymExpr _sym_build_ite(SymExpr, SymExpr, SymExpr)
_sym_build_ite = lib._sym_build_ite
_sym_build_ite.argtypes = [SymExpr, SymExpr, SymExpr]
_sym_build_ite.restype = SymExpr

# SymExpr _sym_build_sext(SymExpr, uint8_t)
_sym_build_sext = lib._sym_build_sext
_sym_build_sext.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_sext.restype = SymExpr

# SymExpr _sym_build_zext(SymExpr, uint8_t)
_sym_build_zext = lib._sym_build_zext
_sym_build_zext.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_zext.restype = SymExpr

# SymExpr _sym_build_trunc(SymExpr, uint8_t)
_sym_build_trunc = lib._sym_build_trunc
_sym_build_trunc.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_trunc.restype = SymExpr

# SymExpr _sym_build_int_to_float(SymExpr, int, int)
_sym_build_int_to_float = lib._sym_build_int_to_float
_sym_build_int_to_float.argtypes = [SymExpr, ctypes.c_int, ctypes.c_int]
_sym_build_int_to_float.restype = SymExpr

# SymExpr _sym_build_float_to_float(SymExpr, int)
_sym_build_float_to_float = lib._sym_build_float_to_float
_sym_build_float_to_float.argtypes = [SymExpr, ctypes.c_int]
_sym_build_float_to_float.restype = SymExpr

# SymExpr _sym_build_bits_to_float(SymExpr, int)
_sym_build_bits_to_float = lib._sym_build_bits_to_float
_sym_build_bits_to_float.argtypes = [SymExpr, ctypes.c_int]
_sym_build_bits_to_float.restype = SymExpr

# SymExpr _sym_build_float_to_bits(SymExpr)
_sym_build_float_to_bits = lib._sym_build_float_to_bits
_sym_build_float_to_bits.argtypes = [SymExpr]
_sym_build_float_to_bits.restype = SymExpr

# SymExpr _sym_build_float_to_signed_integer(SymExpr, uint8_t)
_sym_build_float_to_signed_integer = lib._sym_build_float_to_signed_integer
_sym_build_float_to_signed_integer.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_float_to_signed_integer.restype = SymExpr

# SymExpr _sym_build_float_to_unsigned_integer(SymExpr, uint8_t)
_sym_build_float_to_unsigned_integer = lib._sym_build_float_to_unsigned_integer
_sym_build_float_to_unsigned_integer.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_float_to_unsigned_integer.restype = SymExpr

# SymExpr _sym_build_bool_to_bit(SymExpr)
_sym_build_bool_to_bit = lib._sym_build_bool_to_bit
_sym_build_bool_to_bit.argtypes = [SymExpr]
_sym_build_bool_to_bit.restype = SymExpr

# void _sym_push_path_constraint(SymExpr, int, uintptr_t)
_sym_push_path_constraint = lib._sym_push_path_constraint
_sym_push_path_constraint.argtypes = [SymExpr, ctypes.c_int, ctypes.c_void_p]
_sym_push_path_constraint.restype = None

# SymExpr _sym_concat_helper(SymExpr, SymExpr)
_sym_concat_helper = lib._sym_concat_helper
_sym_concat_helper.argtypes = [SymExpr, SymExpr]
_sym_concat_helper.restype = SymExpr

# SymExpr _sym_extract_helper(SymExpr, size_t, size_t)
_sym_extract_helper = lib._sym_extract_helper
_sym_extract_helper.argtypes = [SymExpr, ctypes.c_void_p, ctypes.c_void_p]
_sym_extract_helper.restype = SymExpr

# SymExpr _sym_build_scanf_extract(const char *, int, int, int, int, int, uint8_t)
_sym_build_scanf_extract = lib._sym_build_scanf_extract
_sym_build_scanf_extract.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p]
_sym_build_scanf_extract.restype = SymExpr

# SymExpr _sym_build_data_length(unsigned long)
_sym_build_data_length = lib._sym_build_data_length
_sym_build_data_length.argtypes = [ctypes.c_ulong]
_sym_build_data_length.restype = SymExpr

# size_t _sym_bits_helper(SymExpr)
_sym_bits_helper = lib._sym_bits_helper
_sym_bits_helper.argtypes = [SymExpr]
_sym_bits_helper.restype = ctypes.c_void_p

# SymExpr _sym_build_insert_element(SymExpr, SymExpr, uint64_t)
_sym_build_insert_element = lib._sym_build_insert_element
_sym_build_insert_element.argtypes = [SymExpr, SymExpr, ctypes.c_void_p]
_sym_build_insert_element.restype = SymExpr

# SymExpr _sym_build_extract_element(SymExpr, uint64_t)
_sym_build_extract_element = lib._sym_build_extract_element
_sym_build_extract_element.argtypes = [SymExpr, ctypes.c_void_p]
_sym_build_extract_element.restype = SymExpr

# SymExpr _sym_build_symbolic_array_int(uint64_t, uint64_t)
_sym_build_symbolic_array_int = lib._sym_build_symbolic_array_int
_sym_build_symbolic_array_int.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
_sym_build_symbolic_array_int.restype = SymExpr

# SymExpr _sym_build_symbolic_array_fp(uint64_t, bool)
_sym_build_symbolic_array_fp = lib._sym_build_symbolic_array_fp
_sym_build_symbolic_array_fp.argtypes = [ctypes.c_void_p, ctypes.c_bool]
_sym_build_symbolic_array_fp.restype = SymExpr
