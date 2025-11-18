#ifndef CONCOLIC_GO_H
#define CONCOLIC_GO_H

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/helper-proto.h"
#include "exec/cpu_ldst.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "exec/translation-block.h"

#include "concolic-go-common.h"
#include "go-hooks.h"

void init_go_module(char* exec_path);
bool is_interesting(uint64_t addr);
void go_translate_loop(uint64_t pc);


#endif
