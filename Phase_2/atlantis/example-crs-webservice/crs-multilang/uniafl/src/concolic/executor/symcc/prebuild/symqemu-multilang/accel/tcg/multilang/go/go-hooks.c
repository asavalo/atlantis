#include "go-hooks.h"
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

// // We need this header for using helper functions. Do NOT directly include the `accel/tcg/tcg-runtime-sym.h`
// #include "exec/helper-gen-common.h"
// #include "target/i386/tcg/translate.c"

// #define HELPER_H "helper.h"
// #include "exec/helper-info.c.inc"
// #undef  HELPER_H

// #define HELPER_H "accel/tcg/tcg-runtime-sym.h"
// #include "exec/helper-info.c.inc"
// #undef  HELPER_H


#define UNASSIGNED_GO_SYMBOL_ID -1

#define GO_SYMBOL_ID_RUNTIME_MEMEQUAL                   0
#define GO_SYMBOL_ID_INTERNAL_BYTEALG_COMPARE           1
#define GO_SYMBOL_ID_RUNTIME_CMPSTRING                  2
#define GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNT             3
#define GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNTSTRING       4
#define GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTE         5
#define GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTESTRING   6


static int compare_symbol_address_record(const void *a, const void *b) {
    uint64_t addr_a = (uint64_t)((symbol_address_record *)a)->address;
    uint64_t addr_b = (uint64_t)((symbol_address_record *)b)->address;
    if (addr_a < addr_b) return -1;
    if (addr_a > addr_b) return 1;
    return 0;
};

static int get_symbol_id_by_pc(uint64_t pc) {
    symbol_address_record tmp = {.address = pc};
    symbol_address_record *res = bsearch(&tmp, concolic_go.symbol_address_tbl, concolic_go.symbol_address_cnt, sizeof(symbol_address_record), compare_symbol_address_record);
    if (res) {
        return res->symbol_id;
    }
    return UNASSIGNED_GO_SYMBOL_ID;
}

uint64_t target_base = 0x0;
uint64_t get_base_address(char *library_name) {
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) {
        fprintf(stderr, "[%s] Error opening /proc/self/maps: %s\n", __func__, strerror(errno));
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), maps)) {
        char address_range[64];
        char perms[16];
        char offset[16];
        char dev[16];
        char inode[16];
        char pathname[1024];

        if (sscanf(line, "%s %s %s %s %s %[^\n]", address_range, perms, offset, dev, inode, pathname) == 6) {
            if (strstr(pathname, library_name)) {
                uintptr_t start_address;
                if (sscanf(address_range, "%lx-", &start_address) == 1) {
                    fclose(maps);
                    target_base = start_address;
                    fprintf(stderr, "[%s] found: target_base 0x%lx\n", __func__, target_base);
                    return start_address;
                }
            }
        }
    }

    fclose(maps);
    fprintf(stderr, "[%s] Library not found: %s\n", __func__, library_name);
    return 0;
}

void init_go_hooks(char* exec_path) {
    char* symqemu_home_path = getenv("SYMQEMU_HOME");
    if (symqemu_home_path == NULL) {
        fprintf(stderr, "\nPlease set `SYMQEMU_HOME` before running symqemu-go (which represents the root path of symqemu-go repository).\n");
        fprintf(stderr, "Example:\n\texport SYMQEMU_HOME=/home/user/work/symqemu-go\n\n");
        exit(-1);
    }

    // load symbol address table
    char *tbl_file = getenv("SYMQEMU_SYMBOL_ADDRESS_TBL");
    if (tbl_file == NULL) {
        tbl_file = "symbol_address_tbl.txt";
    }

    FILE *file = fopen(tbl_file, "r");
    if (!file) {

        pid_t pid = fork();
        
        if (pid == -1) {
            perror("fork");
            exit(EXIT_FAILURE);
        }        

        if (pid == 0) {
            fprintf(stderr, "`symbol_address_tbl.txt` file does not exist. generate it.\n");

            const char *command = "python3";
            char extract_symbol_script_path[512] = {0, };

            sprintf(extract_symbol_script_path, "%s/scripts/extract-symbol-address.py", symqemu_home_path);
            char *const args[] = { "python3", extract_symbol_script_path, exec_path, "symbol_address_tbl.txt", NULL };

            if (execvp(command, args) == -1) {
                perror("execvp");
                exit(EXIT_FAILURE);
            }
        } else {
            int status;
            waitpid(pid, &status, 0);  // Wait for the child process to finish
            printf("Child process finished with status %d\n", WEXITSTATUS(status));

            file = fopen(tbl_file, "r");
        }
    }

    size_t symbol_count = 0;

    if (fscanf(file, "%ld", &symbol_count) != 1) {
        printf("symbol address tbl format error\n");
        exit(-1);
    }
    concolic_go.symbol_address_tbl = (symbol_address_record*)malloc(sizeof(symbol_address_record)*(symbol_count));

    for(int i = 0; i < symbol_count; i++) {
        symbol_address_record record;
        if (fscanf(file, "%d,%lx\n", &record.symbol_id, &record.address) != 2) {
            printf("symbol address tbl format error\n");
            exit(-1);
        }
        concolic_go.symbol_address_tbl[i] = record;
    }
    fclose(file);

    concolic_go.symbol_address_cnt = symbol_count;

    qsort(concolic_go.symbol_address_tbl, symbol_count, sizeof(symbol_address_record), compare_symbol_address_record);



}


// The original `DisasContext` struct is declared in `target/i386/tcg/translate.c`.
// This statement is to avoid compilation errors due to missing declaration.
typedef void* DisasContext;

void __attribute__((weak))
pre_hook_gofunc(DisasContext *s, uint64_t pc) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
post_hook_gofunc(DisasContext *s) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_gofunc_runtime_memequal(void) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_gofunc_internal_bytealg_compare(bool for_string) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_gofunc_internal_bytealg_count(bool for_string) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
pre_hook_gofunc_internal_bytealg_indexbyte(bool for_string) {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

void __attribute__((weak))
post_hook_gofunc_recover_expr_to_rax() {
    printf("`%s` is not implemented. Implement this function in `go-hooks.c.inc`\n", __func__);
    assert(false);
}

static bool go_insert_prehook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    int symbol_id = get_symbol_id_by_pc(pc);
    if (symbol_id != UNASSIGNED_GO_SYMBOL_ID && cpu_env(cpu)->sym_lock == 0) {
        pre_hook_gofunc(s, pc);

        switch(symbol_id) {
        case GO_SYMBOL_ID_RUNTIME_MEMEQUAL:
            pre_hook_gofunc_runtime_memequal();
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COMPARE:
            pre_hook_gofunc_internal_bytealg_compare(false);
            break;
        case GO_SYMBOL_ID_RUNTIME_CMPSTRING:
            pre_hook_gofunc_internal_bytealg_compare(true);
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNT:
            pre_hook_gofunc_internal_bytealg_count(false);
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNTSTRING:
            pre_hook_gofunc_internal_bytealg_count(true);
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTE:
            pre_hook_gofunc_internal_bytealg_indexbyte(false);
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTESTRING:
            pre_hook_gofunc_internal_bytealg_indexbyte(true);
            break;
        default:
            fprintf(stderr, "(Unreachable) Unknown symbol id: %d\n", symbol_id);
            exit(-1);
        }
        
        return true;
    }

    return false;
}

static bool go_insert_posthook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    int symbol_id = get_symbol_id_by_pc(pc - 1);
    if (symbol_id != UNASSIGNED_GO_SYMBOL_ID) {
        switch(symbol_id) {
        case GO_SYMBOL_ID_RUNTIME_MEMEQUAL:
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COMPARE:
        case GO_SYMBOL_ID_RUNTIME_CMPSTRING:
            post_hook_gofunc_recover_expr_to_rax();
            break;
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNT:
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_COUNTSTRING:
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTE:
        case GO_SYMBOL_ID_INTERNAL_BYTEALG_INDEXBYTESTRING:
            break;
        default:
            fprintf(stderr, "(Unreachable) Unknown symbol id: %d\n", symbol_id);
            exit(-1);
        }

        post_hook_gofunc(s);
        s->pc_next += 1;
        
        return true;
    }

    return false;
}


bool go_insert_hook(CPUState *cpu, DisasContextBase *s, uint64_t pc) {
    go_insert_prehook(cpu, s, pc);
    if (go_insert_posthook(cpu, s, pc)) {
        // it needs skipping QEMU's original translations
        return true;
    }
    return false;
    
}
