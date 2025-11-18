#include "concolic-c.h"
#include "c-hooks.h"
#include <stdio.h>

void init_c_module(char* exec_path) {
    init_c_hooks(exec_path);

    printf("Concolic C module initialized\n");

    concolic_c.init = true;
    return;
}
