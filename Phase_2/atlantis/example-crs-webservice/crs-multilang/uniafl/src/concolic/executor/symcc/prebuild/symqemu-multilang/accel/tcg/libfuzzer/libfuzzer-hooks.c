#include <dlfcn.h>
#include "libfuzzer-hooks.h"
#include "cpu.h"
#include "exec/cpu_ldst.h"
#include "exec/helper-proto.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "target/i386/cpu.h"
#include "target/i386/tcg/helper-tcg.h"
#include "tcg/tcg-op.h"
#include "tcg/tcg.h"
#include <stdio.h>
#include "libfuzzer-shm.h"

/*
__sanitizer_cov_trace_pc_indir
__sanitizer_cov_trace_cmp8
__sanitizer_cov_trace_const_cmp8
__sanitizer_cov_trace_cmp4
__sanitizer_cov_trace_const_cmp4
__sanitizer_cov_trace_cmp2
__sanitizer_cov_trace_const_cmp2
__sanitizer_cov_trace_cmp1
__sanitizer_cov_trace_const_cmp1
__sanitizer_cov_trace_switch
__sanitizer_cov_trace_div4
__sanitizer_cov_trace_div8
__sanitizer_cov_trace_gep
__sanitizer_weak_hook_memcmp
__sanitizer_weak_hook_strncmp
__sanitizer_weak_hook_strcmp
__sanitizer_weak_hook_strncasecmp
__sanitizer_weak_hook_strcasecmp
__sanitizer_weak_hook_strstr
__sanitizer_weak_hook_strcasestr
__sanitizer_weak_hook_memmem
*/

#define UNASSIGNED_LIBFUZZER_SYMBOL_ID -1
#define LIBFUZZER_SYMBOL_LLVM_FUZZER_TEST_ONE_INPUT 0
#define SANITIZER_COV_TRACE_PC_INDIR 1
#define SANITIZER_COV_TRACE_CMP8 2
#define SANITIZER_COV_TRACE_CONST_CMP8 3
#define SANITIZER_COV_TRACE_CMP4 4
#define SANITIZER_COV_TRACE_CONST_CMP4 5
#define SANITIZER_COV_TRACE_CMP2 6
#define SANITIZER_COV_TRACE_CONST_CMP2 7
#define SANITIZER_COV_TRACE_CMP1 8
#define SANITIZER_COV_TRACE_CONST_CMP1 9
#define SANITIZER_COV_TRACE_SWITCH 10
#define SANITIZER_COV_TRACE_DIV4 11
#define SANITIZER_COV_TRACE_DIV8 12
#define SANITIZER_COV_TRACE_GEP 13
#define SANITIZER_WEAK_HOOK_MEMCMP 14
#define SANITIZER_WEAK_HOOK_STRNCMP 15
#define SANITIZER_WEAK_HOOK_STRCMP 16
#define SANITIZER_WEAK_HOOK_STRNCASECMP 17
#define SANITIZER_WEAK_HOOK_STRCASECMP 18
#define SANITIZER_WEAK_HOOK_STRSTR 19
#define SANITIZER_WEAK_HOOK_STRCASESTR 20
#define SANITIZER_WEAK_HOOK_MEMMEM 21

struct LibFuzzerHook {
    libfuzzer_symbol_address_record *libfuzzer_symbol_address_tbl;
    size_t libfuzzer_symbol_address_cnt;
    char *exec_path;
    uint64_t guest_base;
    sem_t *start_sem;
    sem_t *end_sem;
    uint8_t *input_buffer;
};

static struct LibFuzzerHook libfuzzer_hook;

bool libfuzzer_insert_hooks(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    return libfuzzer_insert_hook(cpu, s, pc);
}

static int libfuzzer_compare_symbol_address_record(const void *a,
                                                   const void *b) {
    uint64_t addr_a = (uint64_t)((libfuzzer_symbol_address_record *)a)->address;
    uint64_t addr_b = (uint64_t)((libfuzzer_symbol_address_record *)b)->address;
    if (addr_a < addr_b)
        return -1;
    if (addr_a > addr_b)
        return 1;
    return 0;
};

static int libfuzzer_get_symbol_id_by_pc(uint64_t pc) {
    // TODO: Fix when binary is not PIE
    libfuzzer_symbol_address_record tmp = {.address =
                                               pc - libfuzzer_hook.guest_base};
    libfuzzer_symbol_address_record *res =
        bsearch(&tmp, libfuzzer_hook.libfuzzer_symbol_address_tbl,
                libfuzzer_hook.libfuzzer_symbol_address_cnt,
                sizeof(libfuzzer_symbol_address_record),
                libfuzzer_compare_symbol_address_record);
    if (res) {
        return res->symbol_id;
    }
    return UNASSIGNED_LIBFUZZER_SYMBOL_ID;
}

void init_libfuzzer_hooks(const char *exec_path, uint64_t guest_base) {
    char *libfuzzer_server_env = getenv("LIBFUZZER_SERVER");
    if (!libfuzzer_server_env) {
        return;
    } else {
        if (atoi(libfuzzer_server_env) == 0) {
            return;
        }
    }
    // load symbol address table
    char *libfuzzer_symbol_address_tbl_path = getenv("LIBFUZZER_SYMBOL_TBL");
    if (!libfuzzer_symbol_address_tbl_path) {
        fprintf(stderr,
                "SymQEMU-Go: `LIBFUZZER_SYMBOL_TBL` environment variable is "
                "not set.\nPlease set the path to the symbol address table "
                "file.\n");

        fprintf(
            stderr,
            "Example:\n\texport LIBFUZZER_SYMBOL_TBL=[path-to-symbol-table]\n");

        exit(-1);
        return;
    }
    FILE *file = fopen(libfuzzer_symbol_address_tbl_path, "r");
    if (!file) {
        fprintf(stderr,
                "SymQEMU-Go: `libfuzzer_symbol_address_tbl.txt` file does "
                "not exist.\nPlease run "
                "`scripts/extract-libfuzzer-symbol-address.py` first\n");

        fprintf(
            stderr,
            "Example:\n\tpython3 "
            "[path-to-symqemu-go]/scripts/extract-libfuzzer-symbol-address.py "
            "[target_binary] > libfuzzer-symbol_address_tbl.txt\n");

        exit(-1);
        return;
    }

    size_t symbol_count = 0;

    if (fscanf(file, "%ld", &symbol_count) != 1) {
        fprintf(stderr, "[LIBFUZZER] symbol address tbl format error\n");
        exit(-1);
    }
    libfuzzer_hook.libfuzzer_symbol_address_tbl =
        (libfuzzer_symbol_address_record *)malloc(
            sizeof(libfuzzer_symbol_address_record) * (symbol_count));

    for (int i = 0; i < symbol_count; i++) {
        libfuzzer_symbol_address_record record;
        if (fscanf(file, "%d,%lx\n", &record.symbol_id, &record.address) != 2) {
            fprintf(stderr, "[LIBFUZZER] symbol address tbl format error\n");
            exit(-1);
        }
        libfuzzer_hook.libfuzzer_symbol_address_tbl[i] = record;
    }
    fclose(file);

    libfuzzer_hook.libfuzzer_symbol_address_cnt = symbol_count;
    libfuzzer_hook.guest_base = guest_base;

    qsort(libfuzzer_hook.libfuzzer_symbol_address_tbl, symbol_count,
          sizeof(libfuzzer_symbol_address_record),
          libfuzzer_compare_symbol_address_record);

    libfuzzer_shm_init();
}

typedef void *DisasContext;

void __attribute__((weak)) pre_hook_libfuzzer_func(DisasContext *s,
                                                   uint64_t pc) {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

void __attribute__((weak)) post_hook_libfuzzer_func(DisasContext *s) {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

void __attribute__((weak)) libfuzzer_begin_symbolize(DisasContext *s) {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

void __attribute__((weak)) libfuzzer_end_symbolize() {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

void __attribute__((weak)) libfuzzer_sym_lock() {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

void __attribute__((weak)) libfuzzer_sym_unlock() {
    printf("`%s` is not implemented. Implement this function in "
           "`libfuzzer-hooks.c.inc`\n",
           __func__);
    assert(false);
}

static bool libfuzzer_pre_hook(CPUState *cpu, DisasContextBase *s,
                               uint64_t pc) {
    int symbol_id = libfuzzer_get_symbol_id_by_pc(pc);
    if (symbol_id == LIBFUZZER_SYMBOL_LLVM_FUZZER_TEST_ONE_INPUT) {
        if (cpu_env(cpu)->sym_lock != 1) {
            puts("[LIBFUZZER] invalid symlock counter");
            assert(false);
        }
        pre_hook_libfuzzer_func(s, pc);
        libfuzzer_begin_symbolize(s);

        return false;
    }

    if (symbol_id != UNASSIGNED_LIBFUZZER_SYMBOL_ID &&
        cpu_env(cpu)->sym_lock == 0) {
        switch (symbol_id) {
        case SANITIZER_COV_TRACE_PC_INDIR:
        case SANITIZER_COV_TRACE_CMP8:
        case SANITIZER_COV_TRACE_CONST_CMP8:
        case SANITIZER_COV_TRACE_CMP4:
        case SANITIZER_COV_TRACE_CONST_CMP4:
        case SANITIZER_COV_TRACE_CMP2:
        case SANITIZER_COV_TRACE_CONST_CMP2:
        case SANITIZER_COV_TRACE_CMP1:
        case SANITIZER_COV_TRACE_CONST_CMP1:
        case SANITIZER_COV_TRACE_SWITCH:
        case SANITIZER_COV_TRACE_DIV4:
        case SANITIZER_COV_TRACE_DIV8:
        case SANITIZER_COV_TRACE_GEP:
        case SANITIZER_WEAK_HOOK_MEMCMP:
        case SANITIZER_WEAK_HOOK_STRNCMP:
        case SANITIZER_WEAK_HOOK_STRCMP:
        case SANITIZER_WEAK_HOOK_STRNCASECMP:
        case SANITIZER_WEAK_HOOK_STRCASECMP:
        case SANITIZER_WEAK_HOOK_STRSTR:
        case SANITIZER_WEAK_HOOK_STRCASESTR:
        case SANITIZER_WEAK_HOOK_MEMMEM:
            break;
        default:
            fprintf(stderr, "[LIBFUZZER] (Unreachable) Unknown symbol id: %d\n",
                    symbol_id);
            exit(-1);
        }
        libfuzzer_skip_trace_cov_func(s);
        s->pc_next += 1;
        return true;
    }
    return false;
}

static bool libfuzzer_post_hook(CPUState *cpu, DisasContextBase *s,
                                uint64_t pc) {
    int symbol_id = libfuzzer_get_symbol_id_by_pc(pc - 1);
    if (symbol_id != UNASSIGNED_LIBFUZZER_SYMBOL_ID) {
        switch (symbol_id) {
        case LIBFUZZER_SYMBOL_LLVM_FUZZER_TEST_ONE_INPUT:
            libfuzzer_end_symbolize();
            break;
        case SANITIZER_COV_TRACE_PC_INDIR:
        case SANITIZER_COV_TRACE_CMP8:
        case SANITIZER_COV_TRACE_CONST_CMP8:
        case SANITIZER_COV_TRACE_CMP4:
        case SANITIZER_COV_TRACE_CONST_CMP4:
        case SANITIZER_COV_TRACE_CMP2:
        case SANITIZER_COV_TRACE_CONST_CMP2:
        case SANITIZER_COV_TRACE_CMP1:
        case SANITIZER_COV_TRACE_CONST_CMP1:
        case SANITIZER_COV_TRACE_SWITCH:
        case SANITIZER_COV_TRACE_DIV4:
        case SANITIZER_COV_TRACE_DIV8:
        case SANITIZER_COV_TRACE_GEP:
        case SANITIZER_WEAK_HOOK_MEMCMP:
        case SANITIZER_WEAK_HOOK_STRNCMP:
        case SANITIZER_WEAK_HOOK_STRCMP:
        case SANITIZER_WEAK_HOOK_STRNCASECMP:
        case SANITIZER_WEAK_HOOK_STRCASECMP:
        case SANITIZER_WEAK_HOOK_STRSTR:
        case SANITIZER_WEAK_HOOK_STRCASESTR:
        case SANITIZER_WEAK_HOOK_MEMMEM:
            break;
        default:
            fprintf(stderr, "[LIBFUZZER] (Unreachable) Unknown symbol id: %d\n",
                    symbol_id);
            exit(-1);
        }

        post_hook_libfuzzer_func(s);
        s->pc_next += 1;

        return true;
    }

    return false;
}

bool libfuzzer_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    char *libfuzzer_server_env = getenv("LIBFUZZER_SERVER");
    if (!libfuzzer_server_env) {
        return false;
    } else {
        if (atoi(libfuzzer_server_env) == 0) {
            return false;
        }
    }
    if (libfuzzer_pre_hook(cpu, s, pc)) {
        return true;
    }
    if (libfuzzer_post_hook(cpu, s, pc)) {
        return true;
    }
    return false;
}
