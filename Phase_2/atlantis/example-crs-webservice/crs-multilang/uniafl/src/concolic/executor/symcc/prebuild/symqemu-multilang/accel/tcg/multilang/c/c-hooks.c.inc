/*
 *  Real implementations of C-specific hooking routines
 *
 * This file will be included at the end of `target/i386/tcg/translate.c`
 * 
 */
#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "tcg/tcg-op.h"
#include "target/i386/tcg/helper-tcg.h"
#include "target/i386/cpu.h"
#include "exec/translation-block.h"

void pre_hook_libc_func(DisasContext *s, uint64_t pc) {
    gen_helper_sym_lock_inc(tcg_env);

    MemOp ot = gen_pop_T0(s);
    gen_pop_update(s, ot);
    gen_helper_sym_backup_ret(tcg_env, s->T0);

    tcg_gen_subi_tl(cpu_regs[R_ESP], cpu_regs[R_ESP], 8);
    TCGv addr = cpu_regs[R_ESP];
    TCGv new_ret = tcg_constant_i64(pc + 1);
    tcg_gen_qemu_st_tl(new_ret, addr, (TCGArg)tcg_env, MO_64);
    tcg_temp_free_i64(new_ret);
}

void post_hook_libc_func(DisasContext *s) {
    gen_helper_sym_lock_dec(tcg_env);

    TCGv orig_ret = tcg_temp_new_i64();
    gen_helper_sym_recover_ret(orig_ret, tcg_env);
    gen_op_jmp_v(s, orig_ret);
    gen_bnd_jmp(s);
    s->base.is_jmp = DISAS_JUMP;
}

void post_hook_libc_func_recover_expr_to_rax() {
    gen_helper_sym_recover_expr(tcgv_i64_expr(cpu_regs[R_EAX]), tcg_env);
}

void pre_hook_libc_func_strncmp() {
    TCGv lhs = cpu_regs[R_EDI];
    TCGv rhs = cpu_regs[R_ESI];
    TCGv count = cpu_regs[R_EDX];

    // Symbolize strncmp
    gen_helper_pre_libc_func_strncmp(tcg_env, lhs, rhs, count);
}

void pre_hook_libc_func_memcmp() {
    TCGv lhs = cpu_regs[R_EDI];
    TCGv rhs = cpu_regs[R_ESI];
    TCGv count = cpu_regs[R_EDX];

    // Symbolize strncmp
    gen_helper_pre_libc_func_memcmp(tcg_env, lhs, rhs, count);
}
