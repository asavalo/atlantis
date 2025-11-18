#include <stdio.h>
#include <stdlib.h>
void _cpp__sym_build_scanf_extract(const char *format, int input_begin,
                                   int input_end, int arg_index, int arg_size) {
  printf("build_scanf_extract { format: %s, input_begin: %d, input_end: %d, "
         "arg_index: %d , arg_size: %d }\n",
         format, input_begin, input_end, arg_index, arg_size);
}

extern int pipe_symbolized(int pipes[2]);
extern int dup2_symbolized(int oldfd, int newfd);

extern void __isoc99_scanf_symbolized_vararg(int count, int nbytes,
                                             const char *format, ...);

int main() {
  int a, b, c, d, e;
  int pipes[2];
  if (pipe_symbolized(pipes)) {
    perror("pipe");
    exit(1);
  };
  if (dup2_symbolized(pipes[0], 0)) {
    perror("dup2");
    exit(1);
  }

  __isoc99_scanf_symbolized_vararg(5, 10, "%d %c %x %s HI %p", &a, &b, &c, &d,
                                   &e);
  // invalid: should read bytes but not symbolize anythin: should read bytes but
  // not symbolize anythingg
  __isoc99_scanf_symbolized_vararg(5, 10, "%d", &a, &b, &c, &d, &e);
  __isoc99_scanf_symbolized_vararg(4, 20, "%d %d %d %d", &a, &b, &c, &d);

  return 0;
}
