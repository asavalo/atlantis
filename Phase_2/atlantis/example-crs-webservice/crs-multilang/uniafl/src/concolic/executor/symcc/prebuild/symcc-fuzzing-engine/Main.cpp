#include <cstdio>
#include <cstdlib>

extern "C" {

int symcc_main(int argc, char **argv);

int __attribute__((__weak__)) main(int argc, char **argv) {
    symcc_main(argc, argv);
}
}
