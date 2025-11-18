#include <stdio.h>
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
#include "exec/translator.h"

#include "c-hooks.h"

#define UNASSIGNED_LIBC_FUNC_ID -1

#define LIBC_FUNC_ID_STRNCMP        0
#define LIBC_FUNC_ID_MEMCMP         1

static int compare_plt_entry_record(const void *a, const void *b) {
    uint64_t addr_a = (uint64_t)((plt_entry_record *)a)->address;
    uint64_t addr_b = (uint64_t)((plt_entry_record *)b)->address;
    if (addr_a < addr_b) return -1;
    if (addr_a > addr_b) return 1;
    return 0;
};

static int get_symbol_id_by_pc(uint64_t pc) {
    plt_entry_record tmp = {.address = pc};
    plt_entry_record *res = bsearch(&tmp, concolic_c.plt_entry_tbl, concolic_c.plt_entry_cnt, sizeof(plt_entry_record), compare_plt_entry_record);
    if (res) {
        return res->symbol_id;
    }
    return UNASSIGNED_LIBC_FUNC_ID;
}

void init_c_hooks(char* exec_path) {
    char *tbl_file = getenv("SYMQEMU_PLT_ENTRIES_TBL");
    if (tbl_file == NULL) {
        tbl_file = "plt_entries_tbl.txt";
    }
    FILE *file = fopen(tbl_file, "r"); 
    size_t symbol_count = 0;

    if (fscanf(file, "%ld", &symbol_count) != 1) {
        printf("plt entries tbl format error\n");
        exit(-1);
    }
    concolic_c.plt_entry_tbl = (plt_entry_record*)malloc(sizeof(plt_entry_record)*(symbol_count));

    for(int i = 0; i < symbol_count; i++) {
        plt_entry_record record;
        if (fscanf(file, "%d,%lx\n", &record.symbol_id, &record.address) != 2) {
            printf("plt entry tbl format error\n");
            exit(-1);
        }
        concolic_c.plt_entry_tbl[i] = record;
    }
    fclose(file);

    concolic_c.plt_entry_cnt = symbol_count;

    qsort(concolic_c.plt_entry_tbl, symbol_count, sizeof(plt_entry_record), compare_plt_entry_record);
}

// The original `DisasContext` struct is declared in `target/i386/tcg/translate.c`.
// This statement is to avoid compilation errors due to missing declaration.
typedef void* DisasContext;

void __attribute__((weak))
pre_hook_libc_func(DisasContext *s, uint64_t pc) {
    printf("`%s` is not implemented. Implement this function in 'c-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
post_hook_libc_func(DisasContext *s) {
    printf("`%s` is not implemented. Implement this function in `c-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
post_hook_libc_func_recover_expr_to_rax(void) {
    printf("`%s` is not implemented. Implement this function in `c-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_libc_func_strncmp(void) {
    printf("`%s` is not implemented. Implement this function in `c-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_libc_func_memcmp(void) {
    printf("`%s` is not implemented. Implement this function in `c-hooks.c.inc`\n", __func__);
    assert(false);
}

static bool c_insert_prehook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    int symbol_id = get_symbol_id_by_pc(pc);
    if (symbol_id != UNASSIGNED_LIBC_FUNC_ID && cpu_env(cpu)->sym_lock == 0) {
        pre_hook_libc_func(s, pc);

        switch(symbol_id) {
        case LIBC_FUNC_ID_STRNCMP:
            pre_hook_libc_func_strncmp();
            break;
        case LIBC_FUNC_ID_MEMCMP:
            pre_hook_libc_func_memcmp();
            break;
        default:
            fprintf(stderr, "(Unreachable) Unknown symbol id: %d\n", symbol_id);
            exit(-1);
        }
        
        return true;
    }

    return false;
}

static bool c_insert_posthook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    int symbol_id = get_symbol_id_by_pc(pc - 1);
    if (symbol_id != UNASSIGNED_LIBC_FUNC_ID) {
        switch(symbol_id) {
        case LIBC_FUNC_ID_STRNCMP:
        case LIBC_FUNC_ID_MEMCMP:
            post_hook_libc_func_recover_expr_to_rax();
            break;
        default:
            fprintf(stderr, "(Unreachable) Unknown symbol id: %d\n", symbol_id);
            exit(-1);
        }

        post_hook_libc_func(s);
        s->pc_next += 1;
        
        return true;
    }

    return false;
}

bool c_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    c_insert_prehook(cpu, s, pc);
    if (c_insert_posthook(cpu, s, pc)) {
        // it needs skipping QEMU's original translations
        return true;
    }
    return false;
    
}
