#ifndef C_HOOKS_H
#define C_HOOKS_H
#include "qemu/osdep.h"
#include "qemu/thread.h"
#include "qemu/main-loop.h"
#include "hw/core/cpu.h"
#include "sysemu/accel-blocker.h"

#include "concolic-c-common.h"

void init_c_hooks(char* exec_path);
bool c_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc);

#endif
