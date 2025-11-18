export LLVM_COMPILER=clang
export LLVM_CC_NAME=clang-11
export LLVM_CXX_NAME=clang++-11
export LLVM_LINK_NAME=llvm-link-11

CC ?= clang
CXX ?= clang++
CFLAGS = -Wno-pointer-sign -g -c -I../Bullseye/ -fPIC
CXXFLAGS = -stdlib=libc++ -std=c++11 -g -O2 -c -fPIC

SRCS = afl_driver.c
OBJS = $(SRCS:.c=.o)

.PHONY: all clean

all: libAFL.a libAFL.so

# Static Library with forced inclusion
libAFL.a: afl_driver.o ../Bullseye/afl-compiler-rt.o
	ar rcs $@ $^
	ranlib $@

# Shared Library
libAFL.so: $(OBJS)
	$(CC) -shared -o $@ $^ -fPIC

%.o: %.c
	$(CC) $(CFLAGS) $< -o $@

# Clean up
clean:
	rm -f $(OBJS) libAFL.a libAFL.so
