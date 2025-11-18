#include "concolic-go.h"

/*
 * Example:
```
    0x49bc29:   mov    rcx,QWORD PTR [rsp+0xa0]
    0x49bc31:   mov    rax,QWORD PTR [rcx]
    0x49bc34:   cmp    rax,0x4                       // `panic_branch`
    0x49bc38:   jae    0x49bc84 <main.main+452>      // `panic_jmp`
    0x49bc3a:   movzx  edx,BYTE PTR [rsp+rax*1+0x2c]
    0x49bc3f:   lea    r8,[rip+0x903a]
    ...           ...
    0x49bc73:   mov    rsi,rdi
    0x49bc76:   call   0x492260 <fmt.Fprintln>
    0x49bc7b:   add    rsp,0xa8
    0x49bc82:   pop    rbp
    0x49bc83:   ret    
    0x49bc84:   mov    ecx,0x4                       // `jmp_target` 
    0x49bc89:   call   0x46c2e0 <runtime.panicIndex> // `panic_call`
    0x49bc8e:   nop
```
*/

// typedef struct ConcolicGo {
//     bool init;
//     size_t panic_branch_map_cnt; // (`panic_branch`, `panic_jmp`) tuples
//     panic_branch_tup_t* panic_branch_map;
//     size_t symbol_address_cnt;
//     symbol_address_record* symbol_address_tbl;
//     size_t panic_branch_visited_cnt;
//     panic_branch_tup_t* panic_branch_visited;
// } ConcolicGo;


// static ConcolicGo cgo = {
//     .init = false,
//     .panic_branch_map_cnt = 0,
//     .panic_branch_map = NULL,
//     .symbol_address_cnt = 0,
//     .symbol_address_tbl = NULL,
//     .panic_branch_visited_cnt = 0,
//     .panic_branch_visited = NULL,
// };

static int compare_addr_tuple(panic_branch_tup_t *a, panic_branch_tup_t *b) {
    uint64_t addr_a = a->jmp_addr;
    uint64_t addr_b = b->jmp_addr;
    if (addr_a < addr_b) return -1;
    if (addr_a > addr_b) return 1;
    return 0;
};

void extract_go_panic_checks() {
    size_t total_cnt = 0;
    size_t count = 0;    
    
    // load panic branch table
    FILE *file = fopen("panic_branch_tbl.txt", "r");
    if (!file) {
        fprintf(stderr, 
            "SymQEMU-Go: `panic_branch_tbl.txt` file does not exist.\nPlease run `scripts/extract_panic_branch` first\n");
        
        fprintf(stderr, 
            "Example:\n\tpython3 [path-to-symqemu-go]/scripts/extract_panic_branch [target_binary] > panic_branch_tbl.txt\n");

        exit(-1);
        return;
    }

    if (fscanf(file, "%ld", &total_cnt) != 1) {
        printf("panic branch file format error\n");
        exit(-1);
    }

    // map for panic branches
    concolic_go.panic_branch_map = 
        (panic_branch_tup_t*)malloc( sizeof(panic_branch_tup_t)*(total_cnt + 1) );

    printf("runtime check branch cnt: %ld\n", total_cnt);

    while (1) {
        if (fscanf(file, "%lx,%lx", &concolic_go.panic_branch_map[count].branch_addr, &concolic_go.panic_branch_map[count].jmp_addr) == 1) {
            break;
        }        

        count++;
        
        if (count == total_cnt) {
            break;
        }
    }
    fclose(file);

    // initialize panic branch count
    concolic_go.panic_branch_map_cnt = count;
    qsort(concolic_go.panic_branch_map, 
        concolic_go.panic_branch_map_cnt, 
        sizeof(panic_branch_tup_t), 
        (int(*)(const void *,const void *))compare_addr_tuple);
    // qsort(cgo.panic_jmp_tbl, count, sizeof(uint64_t), compare_addr);

    // map for visited panic branches
    concolic_go.panic_branch_visited
        = (panic_branch_tup_t*)malloc( sizeof(panic_branch_tup_t)*(total_cnt + 1) );
    concolic_go.panic_branch_visited_cnt = 0;

}

void init_go_module(char* exec_path) {
    init_go_hooks(exec_path);

    printf("Concolic Go module initialized\n");

    concolic_go.init = true;
    return;
};

static int insert_panic_jmp_visit(panic_branch_tup_t* panic_tuple) {    
    // insert current tuple
    concolic_go.panic_branch_visited[concolic_go.panic_branch_visited_cnt].branch_addr = panic_tuple->branch_addr;
    concolic_go.panic_branch_visited[concolic_go.panic_branch_visited_cnt].jmp_addr = panic_tuple->jmp_addr;

    concolic_go.panic_branch_visited_cnt++;

    qsort(concolic_go.panic_branch_visited, 
        concolic_go.panic_branch_visited_cnt, 
        sizeof(panic_branch_tup_t), 
        (int(*)(const void *,const void *))compare_addr_tuple);

    return 0;
}

/*
 * check if the current translation block includes a panic check branch.
 * If it does, insert it to our internal table.
 */
void go_translate_loop(uint64_t pc) {
    return;

    // Disable panic branch identification

    if (!concolic_go.panic_branch_map) {
        fprintf(stderr, "Error: `concolic_go` not initialized\n");
        exit(-1);
    }

    panic_branch_tup_t tup = {
        .jmp_addr = pc
    };

    panic_branch_tup_t* result = (panic_branch_tup_t*)bsearch(&tup, 
        concolic_go.panic_branch_map, 
        concolic_go.panic_branch_map_cnt, 
        sizeof(panic_branch_tup_t), 
        (int(*)(const void *,const void *))compare_addr_tuple);

    if (!result) // not a panic branch
        return;

    // insert current tuple
    insert_panic_jmp_visit(result);

    return ;
}

static bool is_panic_branch(uint64_t pc) {
    // check if current address is `panic_jmp` address
    panic_branch_tup_t tup = {
        .jmp_addr = pc
    };    
    panic_branch_tup_t* result 
        = (panic_branch_tup_t*) bsearch(&tup, 
            concolic_go.panic_branch_visited, 
            concolic_go.panic_branch_visited_cnt, 
            sizeof(panic_branch_tup_t), 
            (int(*)(const void *,const void *))compare_addr_tuple);

    if (result != NULL) {
        printf("0x%lx is a panic jmp addr\n", result->jmp_addr);
        return true;
    }

    return false;
}

bool is_interesting(uint64_t addr) {
    return false;
    if (is_panic_branch(addr)) {
        return true;
    }

    // @TODO: check other criteria for interesting branch

    return false;
}
