#ifndef GOLANGWRAPPERS_H
#define GOLANGWRAPPERS_H

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif

SymExpr sym_pre_gofunc_runtime_memequal(void *a, void *b, size_t size);
SymExpr sym_pre_gofunc_internal_bytealg_compare(void *a_base, size_t a_len, void *b_base, size_t b_len, SymExpr a_len_expr, SymExpr b_len_expr);
void sym_pre_gofunc_internal_bytealg_count(void *base, size_t len, char needle, char *needle_ptr, uint64_t *result_ptr);
void sym_pre_gofunc_internal_bytealg_indexbyte(void *base, size_t len, char needle, char *needle_ptr, uint64_t *result_ptr);

#ifdef __cplusplus
} 
#endif

#endif
