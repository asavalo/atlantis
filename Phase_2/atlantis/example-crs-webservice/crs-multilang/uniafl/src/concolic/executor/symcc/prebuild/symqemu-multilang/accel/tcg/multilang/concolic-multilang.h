#ifndef CONCOLIC_MULTILANG_H
#define CONCOLIC_MULTILANG_H

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "qemu/error-report.h"
#include "exec/exec-all.h"
#include "exec/translator.h"
#include "exec/cpu_ldst.h"
#include "exec/plugin-gen.h"
#include "exec/cpu_ldst.h"
#include "tcg/tcg-op-common.h"
#include "disas/disas.h"

#include "go/concolic-go.h"
#include "c/concolic-c.h"
#include "c/c-hooks.h"
#include "go/go-hooks.h"

typedef struct multilang_context {
    bool status;
} multilang_ctxt_t;

typedef bool skip_translation_t;

void multilang_module_init(char *exec_path);

skip_translation_t multilang_insert_hooks(CPUState *cpu, DisasContextBase *s,
                                          uint64_t pc);

void multilang_handle_translate_loop(uint64_t pc);

#endif

extern void *sym_pre_libc_func_memcmp(void *lhs, void *rhs, size_t size);
extern void *sym_pre_libc_func_strncmp(void *lhs, void *rhs, size_t size);
extern void *sym_pre_gofunc_runtime_memequal(void *lhs, void *rhs, size_t size);
extern void *sym_pre_gofunc_internal_bytealg_compare(void *lhs, size_t size_lhs,
                                                     void *rhs, size_t size_rhs,
                                                     void *expr_lhs,
                                                     void *expr_rhs);
