#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern unsigned short __afl_prev_loc;
extern unsigned char *__afl_area_ptr;


// Declare the fuzzer function
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

// Notify AFL about persistent mode
static volatile char AFL_PERSISTENT[] = "##SIG_AFL_PERSISTENT##";
int __afl_persistent_loop(unsigned int);

// Input buffer
#define MAX_AFL_INPUT_SIZE (1 << 20)
static uint8_t AflInputBuf[MAX_AFL_INPUT_SIZE];

__attribute__((weak)) int main(int argc, char **argv) {
    (void)argc; (void)argv; // Suppress unused variable warnings
    
    // Run a dummy input to avoid initial coverage influence
    uint8_t dummy_input[1] = {0};
    LLVMFuzzerTestOneInput(dummy_input, 1);
    
    while (__afl_persistent_loop(10000)) {
        ssize_t n_read = read(0, AflInputBuf, MAX_AFL_INPUT_SIZE);
        if (n_read > 0) {
            uint8_t *copy = (uint8_t *)malloc(n_read);
            if (!copy) exit(1);
            // memcpy(copy, AflInputBuf, n_read);
            // LLVMFuzzerTestOneInput(copy, n_read);
            LLVMFuzzerTestOneInput(AflInputBuf, n_read);
            // free(copy);
        }
    }
    return 0;
}
