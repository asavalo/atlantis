#include <stdint.h>
#include <stdio.h>
#include "common.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(struct MyStruct))
    return 0;
  struct MyStruct *s = (struct MyStruct *)data;
  return step1(s) && step2(s);
}
