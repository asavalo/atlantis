/*
 * This file is part of SymQEMU.
 *
 * SymQEMU is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 2 of the License, or (at your option) any later
 * version.
 *
 * SymQEMU is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * SymQEMU. If not, see <https://www.gnu.org/licenses/>.
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "exec/translation-block.h"
#include "accel/tcg/tcg-runtime-sym-common.h"

#define HELPER_H "accel/tcg/tcg-runtime-sym.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

/* Include the symbolic backend, using void* as expression type. */
#include "LibcWrappers.h"
// clang-format off
#include "RuntimeCommon.h"
#include "GolangWrappers.h"
// clang-format on
// #include "LibcFuncWrappers.h"
#include "libfuzzer/libfuzzer-shm.h"
#include "multilang/concolic-multilang.h"
#include "linux-user/user-mmap.h"
#include "linux-user/qemu.h"
#include "linux-user/user-internals.h"

extern void setDontSymbolize(bool dont);

/* Returning NULL for unimplemented functions is equivalent to concretizing and
 * allows us to run without all symbolic handlers fully implemented. */

#define NOT_IMPLEMENTED NULL

/* A slightly questionable macro to help with the repetitive parts of
 * implementing the symbolic handlers: assuming the existence of concrete
 * arguments "arg1" and "arg2" along with variables "arg1_expr" and "arg2_expr"
 * for the corresponding expressions, it expands into code that returns early if
 * both expressions are NULL and otherwise creates the missing expression.*/

#define BINARY_HELPER_ENSURE_EXPRESSIONS                                       \
    if (arg1_expr == NULL && arg2_expr == NULL) {                              \
        return NULL;                                                           \
    }                                                                          \
                                                                               \
    if (arg1_expr == NULL) {                                                   \
        arg1_expr = _sym_build_integer(arg1, _sym_bits_helper(arg2_expr));     \
    }                                                                          \
                                                                               \
    if (arg2_expr == NULL) {                                                   \
        arg2_expr = _sym_build_integer(arg2, _sym_bits_helper(arg1_expr));     \
    }                                                                          \
                                                                               \
    assert(_sym_bits_helper(arg1_expr) == 32 ||                                \
           _sym_bits_helper(arg1_expr) == 64);                                 \
    assert(_sym_bits_helper(arg2_expr) == 32 ||                                \
           _sym_bits_helper(arg2_expr) == 64);                                 \
    assert(_sym_bits_helper(arg1_expr) == _sym_bits_helper(arg2_expr));

/* This macro declares a binary helper function with 64-bit arguments and
 * defines a 32-bit helper function that delegates to it. Use it instead of the
 * function prototype in helper definitions. */

#define DECL_HELPER_BINARY(name)                                               \
    void *HELPER(sym_##name##_i32)(CPUArchState * env, uint32_t arg1,          \
                                   void *arg1_expr, uint32_t arg2,             \
                                   void *arg2_expr) {                          \
        return HELPER(sym_##name##_i64)(env, arg1, arg1_expr, arg2,            \
                                        arg2_expr);                            \
    }                                                                          \
                                                                               \
    void *HELPER(sym_##name##_i64)(CPUArchState * env, uint64_t arg1,          \
                                   void *arg1_expr, uint64_t arg2,             \
                                   void *arg2_expr)

/* To save implementation effort, the macro below defines handlers following the
 * standard scheme of binary operations:
 *
 * 1. Return NULL if both operands are concrete.
 * 2. Create any missing expression.
 * 3. Create an expression representing the operation.
 *
 * For example, DEF_HELPER_BINARY(divu, unsigned_div) defines helpers
 * "helper_sym_divu_i32/i64" backed by the run-time function
 * "_sym_build_unsigned_div". The 32-bit helper just extends the arguments and
 * calls the 64-bit helper. */

#define DEF_HELPER_BINARY(qemu_name, symcc_name)                               \
    DECL_HELPER_BINARY(qemu_name) {                                            \
        if (env->sym_lock > 0) {                                               \
            return NULL;                                                       \
        }                                                                      \
        BINARY_HELPER_ENSURE_EXPRESSIONS;                                      \
        return _sym_build_##symcc_name(arg1_expr, arg2_expr);                  \
    }

/* The binary helpers */

DEF_HELPER_BINARY(add, add)
DEF_HELPER_BINARY(sub, sub)
DEF_HELPER_BINARY(mul, mul)
DEF_HELPER_BINARY(div, signed_div)
DEF_HELPER_BINARY(divu, unsigned_div)
DEF_HELPER_BINARY(rem, signed_rem)
DEF_HELPER_BINARY(remu, unsigned_rem)
DEF_HELPER_BINARY(and, and)
DEF_HELPER_BINARY(or, or)
DEF_HELPER_BINARY(xor, xor)
DEF_HELPER_BINARY(shift_right, logical_shift_right)
DEF_HELPER_BINARY(arithmetic_shift_right, arithmetic_shift_right)
DEF_HELPER_BINARY(shift_left, shift_left)

void *HELPER(sym_neg)(void *expr) {
    if (expr == NULL)
        return NULL;

    return _sym_build_neg(expr);
}
SYM_HELPER_WRAPPER(sym_neg, void *, (void *expr), (expr))

DECL_HELPER_BINARY(andc) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;
    return _sym_build_and(arg1_expr, _sym_build_not(arg2_expr));
}

DECL_HELPER_BINARY(eqv) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;
    return _sym_build_not(_sym_build_xor(arg1_expr, arg2_expr));
}

DECL_HELPER_BINARY(nand) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;
    return _sym_build_not(_sym_build_and(arg1_expr, arg2_expr));
}

DECL_HELPER_BINARY(nor) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;
    return _sym_build_not(_sym_build_or(arg1_expr, arg2_expr));
}

DECL_HELPER_BINARY(orc) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;
    return _sym_build_or(arg1_expr, _sym_build_not(arg2_expr));
}

void *HELPER(sym_not)(void *expr) {
    if (expr == NULL)
        return NULL;

    return _sym_build_not(expr);
}
SYM_HELPER_WRAPPER(sym_not, void *, (void *expr), (expr))

void *HELPER(sym_muluh_i64)(uint64_t arg1, void *arg1_expr, uint64_t arg2,
                            void *arg2_expr) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    assert(_sym_bits_helper(arg1_expr) == 64 &&
           _sym_bits_helper(arg2_expr) == 64);
    void *full_result = _sym_build_mul(_sym_build_zext(arg1_expr, 64),
                                       _sym_build_zext(arg2_expr, 64));
    return _sym_extract_helper(full_result, 127, 64);
}
SYM_HELPER_WRAPPER(sym_muluh_i64, void *,
                   (uint64_t arg1, void *arg1_expr, uint64_t arg2,
                    void *arg2_expr),
                   (arg1, arg1_expr, arg2, arg2_expr))

void *HELPER(sym_sext)(void *expr, uint64_t target_length) {
    if (expr == NULL)
        return NULL;

    size_t current_bits = _sym_bits_helper(expr);
    size_t bits_to_keep = target_length * 8;
    void *shift_distance_expr =
        _sym_build_integer(current_bits - bits_to_keep, current_bits);

    return _sym_build_arithmetic_shift_right(
        _sym_build_shift_left(expr, shift_distance_expr), shift_distance_expr);
}
SYM_HELPER_WRAPPER(sym_sext, void *, (void *expr, uint64_t target_length),
                   (expr, target_length))

void *HELPER(sym_zext)(void *expr, uint64_t target_length) {
    if (expr == NULL)
        return NULL;

    size_t current_bits = _sym_bits_helper(expr);
    size_t desired_bits = target_length * 8;

    return _sym_build_and(
        expr, _sym_build_integer((1ull << desired_bits) - 1, current_bits));
}
SYM_HELPER_WRAPPER(sym_zext, void *, (void *expr, uint64_t target_length),
                   (expr, target_length))

void *HELPER(sym_sext_i32_i64)(void *expr) {
    if (expr == NULL)
        return NULL;

    assert(_sym_bits_helper(expr) == 32);
    return _sym_build_sext(expr, 32); /* extend by 32 */
}
SYM_HELPER_WRAPPER(sym_sext_i32_i64, void *, (void *expr), (expr))

void *HELPER(sym_zext_i32_i64)(void *expr) {
    if (expr == NULL)
        return NULL;

    assert(_sym_bits_helper(expr) == 32);
    return _sym_build_zext(expr, 32); /* extend by 32 */
}
SYM_HELPER_WRAPPER(sym_zext_i32_i64, void *, (void *expr), (expr))

void *HELPER(sym_trunc_i64_i32)(void *expr) {
    if (expr == NULL)
        return NULL;

    assert(_sym_bits_helper(expr) == 64);
    return _sym_build_trunc(expr, 32);
}
SYM_HELPER_WRAPPER(sym_trunc_i64_i32, void *, (void *expr), (expr))

void *HELPER(sym_bswap)(void *expr, uint64_t length) {
    if (expr == NULL)
        return NULL;

    /* The implementation follows the alternative implementations of
     * tcg_gen_bswap* in tcg-op.c (which handle architectures that don't support
     * bswap directly). */

    size_t bits = _sym_bits_helper(expr);
    void *eight = _sym_build_integer(8, bits);
    void *sixteen = _sym_build_integer(16, bits);
    void *thirty_two = _sym_build_integer(32, bits);
    void *forty_eight = _sym_build_integer(48, bits);

    switch (length) {
    case 2:
        return _sym_build_or(
            _sym_build_shift_left(HELPER(sym_zext)(expr, 1), eight),
            _sym_build_logical_shift_right(expr, eight));
    case 4: {
        void *mask = _sym_build_integer(0x00ff00ff, bits);

        /* This is equivalent to the temporary "ret" after the first block. */
        void *first_block = _sym_build_or(
            _sym_build_and(_sym_build_logical_shift_right(expr, eight), mask),
            _sym_build_shift_left(_sym_build_and(expr, mask), eight));

        /* This is the second block. */
        if (bits == 32)
            return _sym_build_or(
                _sym_build_logical_shift_right(first_block, sixteen),
                _sym_build_shift_left(first_block, sixteen));
        else
            return _sym_build_or(
                _sym_build_logical_shift_right(first_block, sixteen),
                _sym_build_logical_shift_right(
                    _sym_build_shift_left(first_block, forty_eight),
                    thirty_two));
    }
    case 8: {
        void *mask1 = _sym_build_integer(0x00ff00ff00ff00ffull, 64);
        void *mask2 = _sym_build_integer(0x0000ffff0000ffffull, 64);

        /* This is equivalent to the temporary "ret" after the first block. */
        void *first_block = _sym_build_or(
            _sym_build_and(_sym_build_logical_shift_right(expr, eight), mask1),
            _sym_build_shift_left(_sym_build_and(expr, mask1), eight));

        /* Here we replicate the second block. */
        void *second_block = _sym_build_or(
            _sym_build_and(_sym_build_logical_shift_right(first_block, sixteen),
                           mask2),
            _sym_build_shift_left(_sym_build_and(first_block, mask2), sixteen));

        /* And finally the third block. */
        return _sym_build_or(
            _sym_build_logical_shift_right(second_block, thirty_two),
            _sym_build_shift_left(second_block, thirty_two));
    }
    default:
        g_assert_not_reached();
    }
}
SYM_HELPER_WRAPPER(sym_bswap, void *, (void *expr, uint64_t length),
                   (expr, length))

static void *sym_load_guest_internal(CPUArchState *env, target_ulong addr,
                                     void *addr_expr, uint64_t load_length,
                                     uint8_t result_length,
                                     target_ulong mmu_idx) {
    /* Try an alternative address */
    if (addr_expr != NULL)
        _sym_push_path_constraint(
            _sym_build_equal(addr_expr,
                             _sym_build_integer(addr, sizeof(addr) * 8)),
            true, get_pc(env));

    void *host_addr = tlb_vaddr_to_host(env, addr, MMU_DATA_LOAD, mmu_idx);
    void *memory_expr =
        _sym_read_memory((uint8_t *)host_addr, load_length, true);
    if (load_length == result_length || memory_expr == NULL)
        return memory_expr;
    else
        return _sym_build_zext(memory_expr, (result_length - load_length) * 8);
}

void *HELPER(sym_load_guest_i32)(CPUArchState *env, uint64_t addr,
                                 void *addr_expr, uint64_t length,
                                 uint64_t mmu_idx) {
    return sym_load_guest_internal(env, addr, addr_expr, length, 4, mmu_idx);
}
SYM_HELPER_WRAPPER(sym_load_guest_i32, void *,
                   (CPUArchState * env, uint64_t addr, void *addr_expr,
                    uint64_t length, uint64_t mmu_idx),
                   (env, addr, addr_expr, length, mmu_idx))

void *HELPER(sym_load_guest_i64)(CPUArchState *env, uint64_t addr,
                                 void *addr_expr, uint64_t length,
                                 uint64_t mmu_idx) {
    return sym_load_guest_internal(env, addr, addr_expr, length, 8, mmu_idx);
}
SYM_HELPER_WRAPPER(sym_load_guest_i64, void *,
                   (CPUArchState * env, uint64_t addr, void *addr_expr,
                    uint64_t length, uint64_t mmu_idx),
                   (env, addr, addr_expr, length, mmu_idx))

static void sym_store_guest_internal(CPUArchState *env, uint64_t value,
                                     void *value_expr, uint64_t addr,
                                     void *addr_expr, uint64_t length,
                                     target_ulong mmu_idx) {
    /* Try an alternative address */
    if (addr_expr != NULL)
        _sym_push_path_constraint(
            _sym_build_equal(addr_expr,
                             _sym_build_integer(addr, sizeof(addr) * 8)),
            true, get_pc(env));

    void *host_addr = tlb_vaddr_to_host(env, addr, MMU_DATA_STORE, mmu_idx);
    _sym_write_memory((uint8_t *)host_addr, length, value_expr, true);
}

void HELPER(sym_store_guest_i32)(CPUArchState *env, uint32_t value,
                                 void *value_expr, uint64_t addr,
                                 void *addr_expr, uint64_t length,
                                 uint64_t mmu_idx) {
    return sym_store_guest_internal(env, value, value_expr, addr, addr_expr,
                                    length, mmu_idx);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_store_guest_i32, void,
                             (CPUArchState * env, uint32_t value,
                              void *value_expr, uint64_t addr, void *addr_expr,
                              uint64_t length, uint64_t mmu_idx),
                             (env, value, value_expr, addr, addr_expr, length,
                              mmu_idx))

void HELPER(sym_store_guest_i64)(CPUArchState *env, uint64_t value,
                                 void *value_expr, uint64_t addr,
                                 void *addr_expr, uint64_t length,
                                 uint64_t mmu_idx) {
    return sym_store_guest_internal(env, value, value_expr, addr, addr_expr,
                                    length, mmu_idx);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_store_guest_i64, void,
                             (CPUArchState * env, uint64_t value,
                              void *value_expr, uint64_t addr, void *addr_expr,
                              uint64_t length, uint64_t mmu_idx),
                             (env, value, value_expr, addr, addr_expr, length,
                              mmu_idx))

static void *sym_load_host_internal(void *addr, uint64_t offset,
                                    uint64_t load_length,
                                    uint64_t result_length) {
    void *memory_expr =
        _sym_read_memory((uint8_t *)addr + offset, load_length, true);

    if (load_length == result_length || memory_expr == NULL)
        return memory_expr;
    else
        return _sym_build_zext(memory_expr, (result_length - load_length) * 8);
}

void *HELPER(sym_load_host_i32)(void *addr, uint64_t offset, uint64_t length) {
    return sym_load_host_internal(addr, offset, length, 4);
}
SYM_HELPER_WRAPPER(sym_load_host_i32, void *,
                   (void *addr, uint64_t offset, uint64_t length),
                   (addr, offset, length))

void *HELPER(sym_load_host_i64)(void *addr, uint64_t offset, uint64_t length) {
    return sym_load_host_internal(addr, offset, length, 8);
}
SYM_HELPER_WRAPPER(sym_load_host_i64, void *,
                   (void *addr, uint64_t offset, uint64_t length),
                   (addr, offset, length))

void *HELPER(sym_load_host_vec)(void *addr, uint64_t offset, uint64_t length) {
    return sym_load_host_internal(addr, offset, length, length);
}
SYM_HELPER_WRAPPER(sym_load_host_vec, void *,
                   (void *addr, uint64_t offset, uint64_t length),
                   (addr, offset, length))

void HELPER(sym_store_host)(void *value_expr, void *addr, uint64_t offset,
                            uint64_t length) {
    _sym_write_memory((uint8_t *)addr + offset, length, value_expr, true);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_store_host, void,
                             (void *value_expr, void *addr, uint64_t offset,
                              uint64_t length),
                             (value_expr, addr, offset, length))

DECL_HELPER_BINARY(rotate_left) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    /* The implementation follows the alternative implementation of
     * tcg_gen_rotl_i64 in tcg-op.c (which handles architectures that don't
     * support rotl directly). */

    uint8_t bits = _sym_bits_helper(arg1_expr);
    return _sym_build_or(
        _sym_build_shift_left(arg1_expr, arg2_expr),
        _sym_build_logical_shift_right(
            arg1_expr,
            _sym_build_sub(_sym_build_integer(bits, bits), arg2_expr)));
}

DECL_HELPER_BINARY(rotate_right) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    /* The implementation follows the alternative implementation of
     * tcg_gen_rotr_i64 in tcg-op.c (which handles architectures that don't
     * support rotr directly). */

    uint8_t bits = _sym_bits_helper(arg1_expr);
    return _sym_build_or(
        _sym_build_logical_shift_right(arg1_expr, arg2_expr),
        _sym_build_shift_left(
            arg1_expr,
            _sym_build_sub(_sym_build_integer(bits, bits), arg2_expr)));
}

void *HELPER(sym_extract_i64)(void *expr, uint64_t ofs, uint64_t len) {
    if (expr == NULL)
        return NULL;

    return _sym_build_zext(_sym_extract_helper(expr, ofs + len - 1, ofs),
                           _sym_bits_helper(expr) - len);
}
SYM_HELPER_WRAPPER(sym_extract_i64, void *,
                   (void *expr, uint64_t ofs, uint64_t len), (expr, ofs, len))

void *HELPER(sym_extract_i32)(void *expr, uint32_t ofs, uint32_t len) {
    return HELPER(sym_extract_i64)(expr, ofs, len);
}
SYM_HELPER_WRAPPER(sym_extract_i32, void *,
                   (void *expr, uint32_t ofs, uint32_t len), (expr, ofs, len))

void *HELPER(sym_deposit_i32)(uint32_t arg1, void *arg1_expr, uint32_t arg2,
                              void *arg2_expr, uint32_t ofs, uint32_t len) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    /* The symbolic implementation follows the alternative concrete
     * implementation of tcg_gen_deposit_i32 in tcg-op.c (which handles
     * architectures that don't support deposit directly). */

    uint32_t mask = (1u << len) - 1;
    return _sym_build_or(
        _sym_build_and(arg1_expr, _sym_build_integer(~(mask << ofs), 32)),
        _sym_build_shift_left(
            _sym_build_and(arg2_expr, _sym_build_integer(mask, 32)),
            _sym_build_integer(ofs, 32)));
}
SYM_HELPER_WRAPPER(sym_deposit_i32, void *,
                   (uint32_t arg1, void *arg1_expr, uint32_t arg2,
                    void *arg2_expr, uint32_t ofs, uint32_t len),
                   (arg1, arg1_expr, arg2, arg2_expr, ofs, len))

void *HELPER(sym_extract2_i32)(uint32_t ah, void *ah_expr, uint32_t al,
                               void *al_expr, uint64_t ofs) {
    if (ah_expr == NULL && al_expr == NULL)
        return NULL;

    if (ah_expr == NULL)
        ah_expr = _sym_build_integer(ah, 32);

    if (al_expr == NULL)
        al_expr = _sym_build_integer(al, 32);

    /* The implementation follows the alternative implementation of
     * tcg_gen_extract2_i32 in tcg-op.c (which handles architectures that don't
     * support extract2 directly). */

    if (ofs == 0)
        return al_expr;
    if (ofs == 32)
        return ah_expr;

    return HELPER(sym_deposit_i32)(
        al >> ofs,
        _sym_build_logical_shift_right(al_expr, _sym_build_integer(ofs, 32)),
        ah, ah_expr, 32 - ofs, ofs);
}
SYM_HELPER_WRAPPER(sym_extract2_i32, void *,
                   (uint32_t ah, void *ah_expr, uint32_t al, void *al_expr,
                    uint64_t ofs),
                   (ah, ah_expr, al, al_expr, ofs))

void *HELPER(sym_deposit_i64)(uint64_t arg1, void *arg1_expr, uint64_t arg2,
                              void *arg2_expr, uint64_t ofs, uint64_t len) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    /* The symbolic implementation follows the alternative concrete
     * implementation of tcg_gen_deposit_i64 in tcg-op.c (which handles
     * architectures that don't support deposit directly). */

    uint64_t mask = (1ull << len) - 1;
    return _sym_build_or(
        _sym_build_and(arg1_expr, _sym_build_integer(~(mask << ofs), 64)),
        _sym_build_shift_left(
            _sym_build_and(arg2_expr, _sym_build_integer(mask, 64)),
            _sym_build_integer(ofs, 64)));
}
SYM_HELPER_WRAPPER(sym_deposit_i64, void *,
                   (uint64_t arg1, void *arg1_expr, uint64_t arg2,
                    void *arg2_expr, uint64_t ofs, uint64_t len),
                   (arg1, arg1_expr, arg2, arg2_expr, ofs, len))

void *HELPER(sym_extract2_i64)(uint64_t ah, void *ah_expr, uint64_t al,
                               void *al_expr, uint64_t ofs) {
    if (ah_expr == NULL && al_expr == NULL)
        return NULL;

    if (ah_expr == NULL)
        ah_expr = _sym_build_integer(ah, 64);

    if (al_expr == NULL)
        al_expr = _sym_build_integer(al, 64);

    /* The implementation follows the alternative implementation of
     * tcg_gen_extract2_i64 in tcg-op.c (which handles architectures that don't
     * support extract2 directly). */

    if (ofs == 0)
        return al_expr;
    if (ofs == 64)
        return ah_expr;

    return HELPER(sym_deposit_i64)(
        al >> ofs,
        _sym_build_logical_shift_right(al_expr, _sym_build_integer(ofs, 64)),
        ah, ah_expr, 64 - ofs, ofs);
}
SYM_HELPER_WRAPPER(sym_extract2_i64, void *,
                   (uint64_t ah, void *ah_expr, uint64_t al, void *al_expr,
                    uint64_t ofs),
                   (ah, ah_expr, al, al_expr, ofs))

void *HELPER(sym_sextract_i64)(void *expr, uint64_t ofs, uint64_t len) {
    if (expr == NULL)
        return NULL;

    return _sym_build_sext(_sym_extract_helper(expr, ofs + len - 1, ofs),
                           _sym_bits_helper(expr) - len);
}
SYM_HELPER_WRAPPER(sym_sextract_i64, void *,
                   (void *expr, uint64_t ofs, uint64_t len), (expr, ofs, len))

void *HELPER(sym_sextract_i32)(void *expr, uint32_t ofs, uint32_t len) {
    return HELPER(sym_sextract_i64)(expr, ofs, len);
}
SYM_HELPER_WRAPPER(sym_sextract_i32, void *,
                   (void *expr, uint32_t ofs, uint32_t len), (expr, ofs, len))

static void *sym_setcond_internal(CPUArchState *env, uint64_t arg1,
                                  void *arg1_expr, uint64_t arg2,
                                  void *arg2_expr, int32_t comparison_operator,
                                  uint64_t is_taken, uint8_t result_bits,
                                  uint64_t addr) {
    BINARY_HELPER_ENSURE_EXPRESSIONS;

    void *condition_symbol = build_and_push_path_constraint(
        env, arg1_expr, arg2_expr, comparison_operator, is_taken, addr);

    assert(result_bits > 1);
    return _sym_build_zext(_sym_build_bool_to_bit(condition_symbol),
                           result_bits - 1);
}

void *HELPER(sym_setcond_i32)(CPUArchState *env, uint32_t arg1, void *arg1_expr,
                              uint32_t arg2, void *arg2_expr,
                              int32_t comparison_operator, uint32_t is_taken) {
    return sym_setcond_internal(env, arg1, arg1_expr, arg2, arg2_expr,
                                comparison_operator, is_taken, 32, 0x0);
}
SYM_HELPER_WRAPPER(sym_setcond_i32, void *,
                   (CPUArchState * env, uint32_t arg1, void *arg1_expr,
                    uint32_t arg2, void *arg2_expr, int32_t comparison_operator,
                    uint32_t is_taken),
                   (env, arg1, arg1_expr, arg2, arg2_expr, comparison_operator,
                    is_taken))

void *HELPER(sym_setcond_i64)(CPUArchState *env, uint64_t arg1, void *arg1_expr,
                              uint64_t arg2, void *arg2_expr,
                              int32_t comparison_operator, uint64_t is_taken,
                              uint64_t addr) {
    return sym_setcond_internal(env, arg1, arg1_expr, arg2, arg2_expr,
                                comparison_operator, is_taken, 64, addr);
}
SYM_HELPER_WRAPPER(sym_setcond_i64, void *,
                   (CPUArchState * env, uint64_t arg1, void *arg1_expr,
                    uint64_t arg2, void *arg2_expr, int32_t comparison_operator,
                    uint64_t is_taken, uint64_t addr),
                   (env, arg1, arg1_expr, arg2, arg2_expr, comparison_operator,
                    is_taken, addr))

static void *sym_movcond_internal(CPUArchState *env, uint64_t c1, void *c1_expr,
                                  uint64_t c2, void *c2_expr, uint64_t v1,
                                  void *v1_expr, uint64_t v2, void *v2_expr,
                                  int32_t comparison_operator,
                                  uint64_t is_taken, uint8_t result_bits) {
    if (c1_expr == NULL && c2_expr == NULL && v1_expr == NULL && v2_expr == NULL) { 
        return NULL;
    }

    if (c1_expr == NULL && c2_expr == NULL) {
        if (v1_expr == NULL) {
            v1_expr = _sym_build_integer(v1, _sym_bits_helper(v2_expr));
        }
        else {
            v2_expr = _sym_build_integer(v2, _sym_bits_helper(v1_expr));
        }
        uint64_t mask = (is_taken) ? (1 << result_bits) - 1: 0x0;
        void *mask_expr = _sym_build_integer(mask, result_bits);
        void *v1_masked = _sym_build_and(v1_expr, mask_expr); 
        void *v2_masked = _sym_build_and(v2_expr, mask_expr);
        return _sym_build_xor(v1_masked, v2_masked);
    }

    if (c1_expr == NULL) {
        c1_expr = _sym_build_integer(c1, _sym_bits_helper(c2_expr));
    }

    if (c2_expr == NULL) {
        c2_expr = _sym_build_integer(c2, _sym_bits_helper(c1_expr));
    }

    if (v1_expr == NULL) {
        v1_expr = _sym_build_integer(v1, _sym_bits_helper(c1_expr));
    }

    if (v2_expr == NULL) {
        v2_expr = _sym_build_integer(v2, _sym_bits_helper(c1_expr));
    }

    assert(_sym_bits_helper(c1_expr) == result_bits);
    assert(_sym_bits_helper(c2_expr) == result_bits);
    assert(_sym_bits_helper(v1_expr) == result_bits);
    assert(_sym_bits_helper(v2_expr) == result_bits);

    void *condition_symbol = build_and_push_path_constraint(
        env, c1_expr, c2_expr, comparison_operator, is_taken, 0xdeadbeef);

    void *condition_ext = _sym_build_sext(
        _sym_build_bool_to_bit(condition_symbol), result_bits - 1);

    assert(_sym_bits_helper(condition_ext) == result_bits);

    void *v1_masked = _sym_build_and(v1_expr, condition_ext);
    void *v2_masked = _sym_build_and(v2_expr, condition_ext);

    return _sym_build_xor(v1_masked, v2_masked);
}

void *HELPER(sym_movcond_i32)(CPUArchState *env, uint32_t c1, void *c1_expr,
                              uint32_t c2, void *c2_expr, uint32_t v1,
                              void *v1_expr, uint32_t v2, void *v2_expr,
                              int32_t comparison_operator, uint32_t is_taken) {
    return sym_movcond_internal(env, c1, c1_expr, c2, c2_expr, v1, v1_expr, v2,
                                v2_expr, comparison_operator, is_taken, 32);
}
SYM_HELPER_WRAPPER(sym_movcond_i32, void *,
                   (CPUArchState * env, uint32_t c1, void *c1_expr, uint32_t c2,
                    void *c2_expr, uint32_t v1, void *v1_expr, uint32_t v2,
                    void *v2_expr, int32_t comparison_operator,
                    uint32_t is_taken),
                   (env, c1, c1_expr, c2, c2_expr, v1, v1_expr, v2, v2_expr,
                    comparison_operator, is_taken))

void *HELPER(sym_movcond_i64)(CPUArchState *env, uint64_t c1, void *c1_expr,
                              uint64_t c2, void *c2_expr, uint64_t v1,
                              void *v1_expr, uint64_t v2, void *v2_expr,
                              int32_t comparison_operator, uint64_t is_taken) {
    return sym_movcond_internal(env, c1, c1_expr, c2, c2_expr, v1, v1_expr, v2,
                                v2_expr, comparison_operator, is_taken, 64);
}
SYM_HELPER_WRAPPER(sym_movcond_i64, void *,
                   (CPUArchState * env, uint64_t c1, void *c1_expr, uint64_t c2,
                    void *c2_expr, uint64_t v1, void *v1_expr, uint64_t v2,
                    void *v2_expr, int32_t comparison_operator,
                    uint64_t is_taken),
                   (env, c1, c1_expr, c2, c2_expr, v1, v1_expr, v2, v2_expr,
                    comparison_operator, is_taken))

void HELPER(sym_notify_call)(uint64_t return_address) {
    _sym_notify_call(return_address);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_notify_call, void, (uint64_t return_address),
                             (return_address))

void HELPER(sym_notify_return)(uint64_t return_address) {
    _sym_notify_ret(return_address);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_notify_return, void, (uint64_t return_address),
                             (return_address))

void HELPER(sym_notify_block)(uint64_t block_id) {
    _sym_notify_basic_block(block_id);
}
SYM_HELPER_WRAPPER_NO_RETVAL(sym_notify_block, void, (uint64_t block_id),
                             (block_id))

void HELPER(sym_collect_garbage)(void) { _sym_collect_garbage(); }
SYM_HELPER_WRAPPER_NO_RETVAL_0(sym_collect_garbage, void)

void *HELPER(sym_cc_compute_all_logicq)(uint64_t dst, void *dst_expr) {
    if (dst_expr == NULL) {
        return NULL;
    }
    // void* bitcount_expr = _sym_build_integer(0, 64);
    // for (int i=0; i < 64; i++) {
    //     bitcount_expr = _sym_build_add(bitcount_expr,
    //     _sym_build_zext(_sym_extract_helper(dst_expr, i, i), 64));
    // }
    void *bitcount_expr = _sym_build_integer(0, 64);
    bitcount_expr = _sym_build_ite(
        _sym_build_equal(_sym_build_integer(1, 64),
                         _sym_build_and(dst_expr, _sym_build_integer(1, 64))),
        _sym_build_integer(1, 64), _sym_build_integer(0, 64));
    for (int i = 1; i < 64; i++) {
        bitcount_expr = _sym_build_add(
            bitcount_expr,
            _sym_build_ite(
                _sym_build_equal(
                    _sym_build_integer(1, 64),
                    _sym_build_and(_sym_build_logical_shift_right(
                                       dst_expr, _sym_build_integer(i, 64)),
                                   _sym_build_integer(1, 64))),
                _sym_build_integer(1, 64), _sym_build_integer(0, 64)));
    }
    void *is_even_expr = _sym_build_equal(
        _sym_build_unsigned_rem(bitcount_expr, _sym_build_integer(2, 64)),
        _sym_build_integer(0, 64));

    void *pf_expr = _sym_build_ite(is_even_expr, _sym_build_integer(4, 64),
                                   _sym_build_integer(0, 64));

    void *cf_expr = _sym_build_integer(0, 64);
    void *af_expr = _sym_build_integer(0, 64);
    void *of_expr = _sym_build_integer(0, 64);

    void *zf_expr = _sym_build_mul(
        _sym_build_integer(0x40, 64),
        _sym_build_ite(_sym_build_equal(dst_expr, _sym_build_integer(0, 64)),
                       _sym_build_integer(1, 64), _sym_build_integer(0, 64)));
    void *sf_expr = _sym_build_and(
        _sym_build_logical_shift_right(dst_expr, _sym_build_integer(56, 64)),
        _sym_build_integer(0x80, 64));
    return _sym_build_or(
        cf_expr,
        _sym_build_or(
            pf_expr,
            _sym_build_or(
                af_expr,
                _sym_build_or(zf_expr, _sym_build_or(sf_expr, of_expr)))));
}
SYM_HELPER_WRAPPER(sym_cc_compute_all_logicq, void *,
                   (uint64_t dst, void *dst_expr), (dst, dst_expr))

/*
static int glue(compute_all_logic, SUFFIX)(DATA_TYPE dst, DATA_TYPE src1)
{
    int cf, pf, af, zf, sf, of;

    # cf = 0;
    # pf = parity_table[(uint8_t)dst];
    # af = 0;
    zf = (dst == 0) * CC_Z;
    sf = lshift(dst, 8 - DATA_BITS) & CC_S;
    # of = 0;
    return cf | pf | af | zf | sf | of;
}
*/

void HELPER(sym_lock_inc)(CPUArchState *env) { env->sym_lock++; }

void HELPER(sym_lock_dec)(CPUArchState *env) { env->sym_lock--; }

void *HELPER(sym_recover_expr)(CPUArchState *env) {
    return env->sym_backup_expr;
}

void HELPER(sym_backup_ret)(CPUArchState *env, uint64_t ret) {
    env->sym_backup_ret = (void *)ret;
}

void *HELPER(sym_recover_ret)(CPUArchState *env) { return env->sym_backup_ret; }

void HELPER(pre_gofunc_runtime_memequal)(CPUArchState *env, uint64_t a,
                                         uint64_t b, uint64_t size) {
    // Symbolize
    void *retval =
        (void *)sym_pre_gofunc_runtime_memequal((void *)a, (void *)b, size);

    // Save symbolic expression
    env->sym_backup_expr = retval;
}

void HELPER(pre_gofunc_internal_bytealg_compare)(
    CPUArchState *env, uint64_t a_base, uint64_t a_len, uint64_t b_base,
    uint64_t b_len, void *a_len_expr, void *b_len_expr) {
    // Symbolize
    void *retval = sym_pre_gofunc_internal_bytealg_compare(
        (void *)a_base, a_len, (void *)b_base, b_len, a_len_expr, b_len_expr);

    // Save symbolic expression
    env->sym_backup_expr = retval;
}

void HELPER(pre_gofunc_internal_bytealg_count)(CPUArchState *env, uint64_t fp,
                                               uint64_t for_string) {
    void *base;
    uint64_t len;
    char needle;
    char *needle_ptr;
    uint64_t *result_ptr;

    cpu_memory_rw_debug(env, fp + 8, &base, sizeof(base), 0);
    cpu_memory_rw_debug(env, fp + 16, &len, sizeof(len), 0);

    if (for_string) {
        cpu_memory_rw_debug(env, fp + 24, &needle, sizeof(needle), 0);
        needle_ptr = (char *)fp + 24;
        cpu_memory_rw_debug(env, fp + 32, &result_ptr, sizeof(result_ptr), 0);
    } else {
        cpu_memory_rw_debug(env, fp + 32, &needle, sizeof(needle), 0);
        needle_ptr = (char *)fp + 32;
        cpu_memory_rw_debug(env, fp + 40, &result_ptr, sizeof(result_ptr), 0);
    }

    // Symbolize
    sym_pre_gofunc_internal_bytealg_count(base, len, needle, needle_ptr,
                                          result_ptr);

    env->sym_backup_expr = NULL;
}

void HELPER(pre_gofunc_internal_bytealg_indexbyte)(CPUArchState *env,
                                                   uint64_t fp,
                                                   uint64_t for_string) {
    void *base;
    uint64_t len;
    char needle;
    char *needle_ptr;
    uint64_t *result_ptr;

    cpu_memory_rw_debug(env, fp + 8, &base, sizeof(base), 0);
    cpu_memory_rw_debug(env, fp + 16, &len, sizeof(len), 0);

    if (for_string) {
        cpu_memory_rw_debug(env, fp + 24, &needle, sizeof(needle), 0);
        needle_ptr = (char *)fp + 24;
        cpu_memory_rw_debug(env, fp + 32, &result_ptr, sizeof(result_ptr), 0);
    } else {
        cpu_memory_rw_debug(env, fp + 32, &needle, sizeof(needle), 0);
        needle_ptr = (char *)fp + 32;
        cpu_memory_rw_debug(env, fp + 40, &result_ptr, sizeof(result_ptr), 0);
    }

    // Symbolize
    sym_pre_gofunc_internal_bytealg_indexbyte(base, len, needle, needle_ptr,
                                              result_ptr);

    env->sym_backup_expr = NULL;
}

void HELPER(pre_libc_func_strncmp)(CPUArchState *env, uint64_t lhs,
                                   uint64_t rhs, uint64_t count) {
    void *retval = sym_pre_libc_func_strncmp((void *)lhs, (void *)rhs, count);

    // Symbolize
    env->sym_backup_expr = retval;
}

void HELPER(destroy_symbolic_input)(CPUArchState *env) {
    fprintf(stderr, "[LIBFUZZER] target function end\n");
    if (libfuzzer_shm_fini() == -1) {
        fprintf(stderr, "[LIBFUZZER] Failed to finalize\n");
        exit(-1);
    }
    size_t size_aligned = (env->symbolic_input_data_size + 0xfff) & ~0xfff;
    if (target_munmap((abi_ulong)env->symbolic_input_data, size_aligned) ==
        -1) {
        fprintf(stderr, "[LIBFUZZER] Failed to unmap memory\n");
        exit(-1);
    }
    setDontSymbolize(true);
}

void HELPER(initialize_symbolic_input)(CPUArchState *env) {
    fprintf(stderr, "[LIBFUZZER] Pending receive input data\n");
    /* Wait for receive data */
    uint8_t *data;
    size_t size;
    if (libfuzzer_shm_recv(&data, &size) == -1) {
        fprintf(stderr, "[LIBFUZZER] Failed to receive input data\n");
        exit(-1);
    }

    fprintf(stderr, "[LIBFUZZER] Successfully received input data\n");
    // symbolize data contents
    symcc_make_symbolic(data, size);
    setDontSymbolize(false);
    size_t size_aligned = (size + 0xfff) & ~0xfff;
    abi_long target_data = target_mmap(0, size_aligned, PROT_READ | PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *p;
    if (!(p = lock_user(VERIFY_READ, target_data, size, 1))) {
        fprintf(stderr, "[LIBFUZZER] Failed to lock user memory\n");
        exit(-1);
    }
    memcpy(p, data, size);
    _sym_memcpy(p, data, size);
    env->symbolic_input_data = (uint8_t *)target_data;
    env->symbolic_input_data_size = size;
}

uint64_t HELPER(get_symbolic_input_data)(CPUArchState *env) {
    return (uint64_t)env->symbolic_input_data;
}

uint64_t HELPER(get_symbolic_input_data_size)(CPUArchState *env) {
    return (uint64_t)env->symbolic_input_data_size;
}

void *HELPER(get_symbolic_input_data_size_expr)(CPUArchState *env) {
    // We don't need to check the SYMCC_SYMBOLIZE_DATA_LENGTH environment variables
    // It is done internally in the symcc runtime and returns a NULL if not set 
    void *expr = _sym_build_data_length(env->symbolic_input_data_size);
    return expr;
}

void HELPER(pre_libc_func_memcmp)(CPUArchState *env, uint64_t lhs, uint64_t rhs,
                                  uint64_t count) {
    void *retval = sym_pre_libc_func_memcmp((void *)lhs, (void *)rhs, count);

    // Symbolize
    env->sym_backup_expr = retval;
}
