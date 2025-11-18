#include <signal.h>
#include <stdint.h>
#include <stddef.h>

// These are weak symbols that can be overridden by the user.
// They must be weakly defined because they are always called by symcc_main in
// lib.rs, but may not exist in the user's code. LLVMFuzzerInitialize may not be
// defined for some harnesses, and LLVMFuzzerTestOneInput may not be defined for
// executables compiled during the configure phase of the build process.
__attribute__((weak)) extern int LLVMFuzzerInitialize(int *argc, char ***argv) {
    return 0;
}

__attribute__((weak)) extern int LLVMFuzzerTestOneInput(const uint8_t *Data,
                                                        size_t Size) {
    return 0;
}

// This function may be invoekd by the fuzzer. It doesn't need to be a 
// weak symbol.
size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize) {
    return 0;
}
