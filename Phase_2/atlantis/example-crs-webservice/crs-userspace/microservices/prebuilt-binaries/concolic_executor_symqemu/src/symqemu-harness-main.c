#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <syscall.h>
#include <unistd.h>

// weak symbol for LLVMFuzzerTestOneInput
int __attribute__((weak)) LLVMFuzzerTestOneInput(const uint8_t *data,
                                                 size_t size) {
  return 0;
}

#define SYS_SYMCC_MAKE_SYMBOLIC 0x13371338
#define SYS_SYMCC_EXIT 0x13371337 

void symcc_exit(void) {
  syscall(SYS_SYMCC_EXIT, 1);
}

int main(int argc, char **argv) {
  atexit(symcc_exit);
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
    exit(1);
  }
  FILE *fp = fopen(argv[1], "rb");
  if (fp == NULL) {
    fprintf(stderr, "Error: could not open file %s\n", argv[1]);
    exit(1);
  }
  fseek(fp, 0, SEEK_END);
  size_t size = ftell(fp);
  fseek(fp, 0, SEEK_SET);
  uint8_t *data = (uint8_t *)malloc(size);
  if (data == NULL) {
    fprintf(stderr, "Error: could not allocate memory\n");
    exit(1);
  }
  fread(data, 1, size, fp);
  fclose(fp);
  syscall(SYS_SYMCC_MAKE_SYMBOLIC, data, size);
  LLVMFuzzerTestOneInput(data, size);
  return 0;
}
