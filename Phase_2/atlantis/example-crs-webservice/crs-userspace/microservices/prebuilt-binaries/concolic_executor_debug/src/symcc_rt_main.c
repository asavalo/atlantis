#include <stdlib.h>
#include <stdbool.h>

extern int symcc_main(int argc, char **argv);

int __attribute__((weak)) LLVMFuzzerTestOneInput(char *data, long size) {
    // do nothing
    return 0;
}

int __attribute__((weak)) main(int argc, char **argv) {
    return symcc_main(argc, argv);
}
