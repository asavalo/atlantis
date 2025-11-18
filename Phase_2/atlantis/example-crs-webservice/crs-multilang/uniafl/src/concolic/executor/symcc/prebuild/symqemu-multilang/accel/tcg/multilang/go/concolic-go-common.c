#include "concolic-go-common.h"

ConcolicGo concolic_go = {
    .init = false,
    .panic_branch_map_cnt = 0,
    .panic_branch_map = NULL,
    .symbol_address_cnt = 0,
    .symbol_address_tbl = NULL,
    .panic_branch_visited_cnt = 0,
    .panic_branch_visited = NULL,
};