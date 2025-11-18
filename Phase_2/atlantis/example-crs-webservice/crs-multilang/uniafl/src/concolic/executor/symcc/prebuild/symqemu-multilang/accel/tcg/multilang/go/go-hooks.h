#ifndef GO_HOOKS_H
#define GO_HOOKS_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "exec/translation-block.h"

#include "concolic-go-common.h"

void init_go_hooks(char* exec_path);
bool go_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc);


#endif