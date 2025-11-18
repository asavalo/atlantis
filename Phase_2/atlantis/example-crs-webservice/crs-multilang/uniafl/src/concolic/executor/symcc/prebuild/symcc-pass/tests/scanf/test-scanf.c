#include <stdio.h>
#include <stdlib.h>

int main() {
  int a, b, c, res;
  int n = scanf("%d %d %d\n", &a, &b, &c);
  if (n != 1) {
    fprintf(stderr, "invalid number");
    exit(-1);
  }
  switch (a) {
  case 1: {
    res = b * c;
  }
  case 2: {
    res = b + c;
  }
  case 3: {
    res = b - c;
  }
  case 4: {
    res = b / c;
  }
  case 5:
    break;
  default: {
    res = 0;
    fprintf(stderr, "invalid operation %d", a);
  }
  }
  printf("result: %d\n", res);
  return 0;
}
