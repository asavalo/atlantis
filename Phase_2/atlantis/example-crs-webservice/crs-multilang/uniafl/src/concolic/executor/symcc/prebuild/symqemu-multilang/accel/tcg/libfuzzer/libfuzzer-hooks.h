#ifndef GO_HOOKS_H
#define GO_HOOKS_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "exec/translation-block.h"
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

void init_libfuzzer_hooks(const char *exec_path, uint64_t guest_base);
bool libfuzzer_insert_hooks(CPUState *cpu, DisasContextBase *s, uint64_t pc);
bool libfuzzer_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc);
void libfuzzer_skip_trace_cov_func(DisasContextBase *s); 

typedef struct libfuzzer_symbol_address_record {
    int symbol_id;
    uint64_t address;
} libfuzzer_symbol_address_record;

#endif
