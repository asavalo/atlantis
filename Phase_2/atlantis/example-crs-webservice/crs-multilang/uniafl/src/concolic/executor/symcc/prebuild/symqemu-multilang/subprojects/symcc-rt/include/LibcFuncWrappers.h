#ifndef LIBCFUNCWRAPPERS_H
#define LIBCFUNCWRAPPERS_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif

SymExpr sym_pre_libc_func_strncmp(const char *lhs, const char *rhs, const size_t count);
SymExpr sym_pre_libc_func_memcmp(const char *lhs, const char *rhs, const size_t count);

#ifdef __cplusplus
} 
#endif

#endif
