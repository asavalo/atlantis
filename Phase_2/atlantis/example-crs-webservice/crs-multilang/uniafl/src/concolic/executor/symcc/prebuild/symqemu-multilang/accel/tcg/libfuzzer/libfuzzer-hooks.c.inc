#include "tcg/tcg-temp-internal.h"
void libfuzzer_skip_trace_cov_func(DisasContext *s) {
    MemOp ot = gen_pop_T0(s);
    gen_pop_update(s, ot);
    
    gen_op_jmp_v(s, s->T0);
    gen_bnd_jmp(s);
    s->base.is_jmp = DISAS_JUMP;
}

void pre_hook_libfuzzer_func(DisasContext *s, uint64_t pc) {
    MemOp ot = gen_pop_T0(s);
    gen_pop_update(s, ot);
    gen_helper_sym_backup_ret(tcg_env, s->T0);

    tcg_gen_subi_tl(cpu_regs[R_ESP], cpu_regs[R_ESP], 8);
    TCGv addr = cpu_regs[R_ESP];
    TCGv new_ret = tcg_constant_i64(pc + 1);
    tcg_gen_qemu_st_tl(new_ret, addr, (unsigned long)tcg_env, MO_64);
    tcg_temp_free_i64(new_ret);
}

void post_hook_libfuzzer_func(DisasContext *s) {
    TCGv orig_ret = tcg_temp_new_i64();
    gen_helper_sym_recover_ret(orig_ret, tcg_env);
    gen_op_jmp_v(s, orig_ret);
    gen_bnd_jmp(s);
    s->base.is_jmp = DISAS_JUMP;
}

void libfuzzer_end_symbolize() {
    gen_helper_destroy_symbolic_input(tcg_env);
    gen_helper_sym_lock_inc(tcg_env);
}

void libfuzzer_begin_symbolize(DisasContext *s) {
    TCGv_i64 buffer = tcg_temp_new_i64();
    TCGv_i64 size = tcg_temp_new_i64();

    gen_helper_initialize_symbolic_input(tcg_env);
    gen_helper_get_symbolic_input_data(buffer, tcg_env);
    gen_helper_get_symbolic_input_data_size(size, tcg_env);
    gen_helper_get_symbolic_input_data_size_expr(tcgv_i64_expr(size), tcg_env);

    tcg_gen_mov_i64(cpu_regs[R_EDI], buffer);
    tcg_gen_mov_i64(cpu_regs[R_ESI], size);
    
    tcg_temp_free_i64(buffer);
    tcg_temp_free_i64(size);
    gen_helper_sym_lock_dec(tcg_env);
}

void libfuzzer_sym_lock() {
    gen_helper_sym_lock_inc(tcg_env);
}

void libfuzzer_sym_unlock() {
    gen_helper_sym_lock_dec(tcg_env);
}
