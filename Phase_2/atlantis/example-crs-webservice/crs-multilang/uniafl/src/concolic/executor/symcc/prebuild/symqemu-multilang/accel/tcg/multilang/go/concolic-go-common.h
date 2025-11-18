#ifndef CONCOLIC_GO_COMMON_H
#define CONCOLIC_GO_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct symbol_address_record {
    int symbol_id;
    uint64_t address;
} symbol_address_record;

typedef struct panic_branch_tuple {
    uint64_t branch_addr;
    uint64_t jmp_addr;
} panic_branch_tup_t;


typedef struct ConcolicGo {
    bool init;
    size_t panic_branch_map_cnt; // (`panic_branch`, `panic_jmp`) tuples
    panic_branch_tup_t* panic_branch_map;
    size_t symbol_address_cnt;
    symbol_address_record* symbol_address_tbl;
    size_t panic_branch_visited_cnt;
    panic_branch_tup_t* panic_branch_visited;
} ConcolicGo;

extern ConcolicGo concolic_go;

#endif