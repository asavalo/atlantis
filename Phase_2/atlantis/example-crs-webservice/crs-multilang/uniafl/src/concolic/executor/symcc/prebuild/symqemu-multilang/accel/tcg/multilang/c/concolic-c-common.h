#ifndef CONCOLIC_C_COMMON_H
#define CONCOLIC_C_COMMON_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct plt_entry_record {
    int symbol_id;
    uint64_t address;
} plt_entry_record;

typedef struct ConcolicC {
    bool init;
    size_t plt_entry_cnt;
    plt_entry_record* plt_entry_tbl;
} ConcolicC;

extern ConcolicC concolic_c;


#endif
