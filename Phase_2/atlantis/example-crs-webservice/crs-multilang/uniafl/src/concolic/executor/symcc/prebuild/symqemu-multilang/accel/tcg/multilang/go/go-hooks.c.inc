/*
 *  Real implementations of Go-specific hooking routines
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

void pre_hook_gofunc(DisasContext *s, uint64_t pc) {
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

void post_hook_gofunc(DisasContext *s) {
    gen_helper_sym_lock_dec(tcg_env);

    TCGv orig_ret = tcg_temp_new_i64();
    gen_helper_sym_recover_ret(orig_ret, tcg_env);
    gen_op_jmp_v(s, orig_ret);
    gen_bnd_jmp(s);
    s->base.is_jmp = DISAS_JUMP;
}

void pre_hook_gofunc_runtime_memequal() {
    TCGv a = cpu_regs[R_EAX];
    TCGv b = cpu_regs[R_EBX];
    TCGv size = cpu_regs[R_ECX];

    // Symbolize runtime.memequal
    gen_helper_pre_gofunc_runtime_memequal(tcg_env, a, b, size);
}

void pre_hook_gofunc_internal_bytealg_compare(bool for_string) {
    TCGv a_base = cpu_regs[R_EAX];
    TCGv a_len = cpu_regs[R_EBX];
    TCGv b_base = cpu_regs[R_EDI];
    TCGv b_len = cpu_regs[R_ESI];

    if(for_string) {
        b_base = cpu_regs[R_ECX];
        b_len = cpu_regs[R_EDI];
    }
    
    TCGv_ptr a_len_expr = tcgv_i64_expr(a_len);
    TCGv_ptr b_len_expr = tcgv_i64_expr(b_len);

    // Symbolize iternal/bytealg.compare
    gen_helper_pre_gofunc_internal_bytealg_compare(tcg_env, a_base, a_len, b_base, b_len, a_len_expr, b_len_expr);
}

void pre_hook_gofunc_internal_bytealg_count(bool for_string) {
    TCGv fp = cpu_regs[R_ESP];
    TCGv for_string_tcg = tcg_constant_i64(for_string ? 1 : 0);

    // Symbolize internal/bytealg.count
    gen_helper_pre_gofunc_internal_bytealg_count(tcg_env, fp, for_string_tcg);

    tcg_temp_free_i64(for_string_tcg);
}

void pre_hook_gofunc_internal_bytealg_indexbyte(bool for_string) {
    TCGv fp = cpu_regs[R_ESP];
    TCGv for_string_tcg = tcg_constant_i64(for_string ? 1 : 0);

    // Symbolize internal/bytealg.indexbyte
    gen_helper_pre_gofunc_internal_bytealg_indexbyte(tcg_env, fp, for_string_tcg);

    tcg_temp_free_i64(for_string_tcg);
}

void post_hook_gofunc_recover_expr_to_rax() {
    gen_helper_sym_recover_expr(tcgv_i64_expr(cpu_regs[R_EAX]), tcg_env);
}
