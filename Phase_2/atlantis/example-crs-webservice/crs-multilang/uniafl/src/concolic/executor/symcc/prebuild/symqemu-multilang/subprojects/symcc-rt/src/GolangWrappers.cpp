#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include "Config.h"
#include "Shadow.h"
#include <Runtime.h>

namespace {

/// Tell the solver to try an alternative value than the given one.
template <typename V, typename F>
void tryAlternative(V value, SymExpr valueExpr, F caller) {
  if (valueExpr) {
    _sym_push_path_constraint(
        _sym_build_equal(valueExpr,
                         _sym_build_integer(value, sizeof(value) * 8)),
        true, reinterpret_cast<uintptr_t>(caller));
  }
}

// A partial specialization for pointer types for convenience.
template <typename E, typename F>
void tryAlternative(E *value, SymExpr valueExpr, F caller) {
  tryAlternative(reinterpret_cast<intptr_t>(value), valueExpr, caller);
}

} // namespace

SymExpr _sym_build_integer_from_shadow(const ReadOnlyShadow &shadow) {
  auto expr = _sym_build_integer(0, shadow.length_ * 8);
  for(auto it = shadow.end(); it != shadow.begin();) {
    --it;
    expr = _sym_build_shift_left(expr, _sym_build_integer(8, 64));
    expr = _sym_build_or(expr, *it);
  }
  return expr;
}

extern "C" {

void golang_bytes_Compare_symbolized(const void *a_buf, const size_t *a_len, const void *b_buf, const size_t *b_len, const size_t *ret) {  
  if (isConcrete(a_buf, *a_len) && isConcrete(b_buf, *b_len)){
    _sym_memset((uint8_t *)ret, nullptr, sizeof(*ret));
    return;
  }

  SymExpr aLenExpr;
  SymExpr bLenExpr;

  if(isConcrete(a_len, sizeof(*a_len))) {
    aLenExpr = _sym_build_integer(*a_len, 64);
  } else {
    aLenExpr = _sym_build_integer_from_shadow(ReadOnlyShadow(a_len, sizeof(*a_len)));
  }
  if(isConcrete(b_len, sizeof(*b_len))) {
    bLenExpr = _sym_build_integer(*b_len, 64);
  } else {
    bLenExpr = _sym_build_integer_from_shadow(ReadOnlyShadow(b_len, sizeof(*b_len)));
  }

  auto *lengthEq = _sym_build_equal(aLenExpr, bLenExpr);
  auto *lengthLt = _sym_build_unsigned_less_than(aLenExpr, bLenExpr);
  auto *lengthGt = _sym_build_unsigned_greater_than(aLenExpr, bLenExpr);

  auto aShadowIt = ReadOnlyShadow(a_buf, *a_len).begin_non_null();
  auto bShadowIt = ReadOnlyShadow(b_buf, *b_len).begin_non_null();
  auto *prefixEq = _sym_build_equal(*aShadowIt, *bShadowIt);
  auto *prefixLt = _sym_build_unsigned_less_than(*aShadowIt, *bShadowIt);
  auto *prefixGt = _sym_build_unsigned_greater_than(*aShadowIt, *bShadowIt);
  for (size_t i = 1; i < std::min(*a_len, *b_len); i++) {
    ++aShadowIt;
    ++bShadowIt;
    prefixLt = _sym_build_bool_or(
        prefixLt,
        _sym_build_bool_and(prefixEq, _sym_build_unsigned_less_than(*aShadowIt, *bShadowIt)));
    prefixGt = _sym_build_bool_or(
        prefixGt,
        _sym_build_bool_and(prefixEq, _sym_build_unsigned_greater_than(*aShadowIt, *bShadowIt)));
    prefixEq =
        _sym_build_bool_and(prefixEq, _sym_build_equal(*aShadowIt, *bShadowIt));
  }

  auto *allEq = _sym_build_bool_and(prefixEq, lengthEq);
  auto *allLt = _sym_build_bool_or(prefixLt, _sym_build_bool_and(lengthLt, prefixEq));
  auto *allGt = _sym_build_bool_or(prefixGt, _sym_build_bool_and(lengthGt, prefixEq));

  auto *retExpr = _sym_build_ite(allEq, _sym_build_integer(0, sizeof(*ret) * 8),
                                 _sym_build_ite(allLt, _sym_build_integer(-1LL, sizeof(*ret) * 8),
                                                _sym_build_integer(1LL, sizeof(*ret) * 8)));

  for(auto i=0; i<sizeof(*ret); i++) {
    auto *byteExpr = _sym_build_logical_shift_right(retExpr, _sym_build_integer(i*8, 64));
    byteExpr = _sym_build_trunc(byteExpr, 8);
    _sym_memset((uint8_t *)ret + i, byteExpr, 1);
  }
}

void golang_bytes_Equal_symbolized(const void *a_buf, const size_t *a_len, const void *b_buf, const size_t *b_len, const uint8_t *ret) {
  if (isConcrete(a_buf, *a_len) && isConcrete(b_buf, *b_len)) {
    _sym_memset((uint8_t *)ret, nullptr, 1);
    return;
  }

  SymExpr aLenExpr;
  SymExpr bLenExpr;

  if(isConcrete(a_len, sizeof(*a_len))) {
    aLenExpr = _sym_build_integer(*a_len, 64);
  } else {
    aLenExpr = _sym_build_integer_from_shadow(ReadOnlyShadow(a_len, sizeof(*a_len)));
  }
  if(isConcrete(b_len, sizeof(*b_len))) {
    bLenExpr = _sym_build_integer(*b_len, 64);
  } else {
    bLenExpr = _sym_build_integer_from_shadow(ReadOnlyShadow(b_len, sizeof(*b_len)));
  }
  auto *lengthEq = _sym_build_equal(aLenExpr, bLenExpr);

  auto aShadowIt = ReadOnlyShadow(a_buf, *a_len).begin_non_null();
  auto bShadowIt = ReadOnlyShadow(b_buf, *b_len).begin_non_null();
  auto *dataEq = _sym_build_equal(*aShadowIt, *bShadowIt);
  for (size_t i = 1; i < std::min(*a_len, *b_len); i++) {
    ++aShadowIt;
    ++bShadowIt;
    dataEq =
        _sym_build_bool_and(dataEq, _sym_build_equal(*aShadowIt, *bShadowIt));
  }

  auto *allEq = _sym_build_bool_and(dataEq, lengthEq);

  auto *retExpr = _sym_build_ite(allEq, _sym_build_integer(1, sizeof(*ret) * 8),
                                 _sym_build_integer(0, sizeof(*ret) * 8));
  _sym_memset((uint8_t *)ret, retExpr, 1);
}

void golang_bytes_Clone_symbolized(const void *b_buf, const size_t *b_len, const size_t *b_cap, const void *ret_buf, const size_t *ret_len, const size_t *ret_cap) {
  _sym_memcpy((uint8_t*)ret_buf, (uint8_t*)b_buf, *b_len);
  _sym_memcpy((uint8_t*)ret_len, (uint8_t*)b_len, sizeof(*b_len));
  _sym_memcpy((uint8_t*)ret_cap, (uint8_t*)b_cap, sizeof(*b_cap));
}

SymExpr sym_pre_gofunc_runtime_memequal(void *a, void *b, size_t size) {
  if(isConcrete(a, size) && isConcrete(b, size)) {
    return nullptr;
  }

  auto aShadowIt = ReadOnlyShadow(a, size).begin_non_null();
  auto bShadowIt = ReadOnlyShadow(b, size).begin_non_null();
  auto cond = _sym_build_equal(*aShadowIt, *bShadowIt);
  for (size_t i = 1; i < size; i++) {
    ++aShadowIt;
    ++bShadowIt;
    cond = _sym_build_bool_and(cond, _sym_build_equal(*aShadowIt, *bShadowIt));
  }

  return _sym_build_ite(cond, _sym_build_integer(1, 64), _sym_build_integer(0, 64));
}

SymExpr sym_pre_gofunc_internal_bytealg_compare(void *a_base, size_t a_len, void *b_base, size_t b_len, SymExpr a_len_expr, SymExpr b_len_expr) {
  if (isConcrete(a_base, a_len) && isConcrete(b_base, b_len)){
    // TOOD(kyuheon): if len exprs are not concrete, it can be symbolized more precisely
    return nullptr;
  }

  auto aShadowIt = ReadOnlyShadow(a_base, a_len).begin_non_null(); 
  auto bShadowIt = ReadOnlyShadow(b_base, b_len).begin_non_null();
  
  SymExpr prefixEq = nullptr;
  SymExpr prefixLt = nullptr;
  SymExpr prefixGt = nullptr;

  for (size_t i = 0; i < std::min(a_len, b_len); i++) {
    if(prefixEq == nullptr) {
      prefixEq = _sym_build_equal(*aShadowIt, *bShadowIt);
      prefixLt = _sym_build_unsigned_less_than(*aShadowIt, *bShadowIt);
      prefixGt = _sym_build_unsigned_greater_than(*aShadowIt, *bShadowIt);
    }
    else {
      prefixLt = _sym_build_bool_or(
          prefixLt,
          _sym_build_bool_and(prefixEq, _sym_build_unsigned_less_than(*aShadowIt, *bShadowIt)));
      prefixGt = _sym_build_bool_or(
          prefixGt,
          _sym_build_bool_and(prefixEq, _sym_build_unsigned_greater_than(*aShadowIt, *bShadowIt)));
      prefixEq =
          _sym_build_bool_and(prefixEq, _sym_build_equal(*aShadowIt, *bShadowIt));
    }
    ++aShadowIt;
    ++bShadowIt;
  }

  if(a_len_expr == nullptr) {
    a_len_expr = _sym_build_integer(a_len, 64);
  }
  if(b_len_expr == nullptr) {
    b_len_expr = _sym_build_integer(b_len, 64);
  }
  if(prefixEq == nullptr) {
    prefixEq = _sym_build_true();
  }
  if(prefixLt == nullptr) {
    prefixLt = _sym_build_false();
  }
  if(prefixGt == nullptr) {
    prefixGt = _sym_build_false();
  }

  auto *allEq = _sym_build_bool_and(prefixEq, _sym_build_equal(a_len_expr, b_len_expr));
  auto *allLt = _sym_build_bool_or(prefixLt, _sym_build_bool_and(prefixEq, _sym_build_unsigned_less_than(a_len_expr, b_len_expr)));
  auto *allGt = _sym_build_bool_or(prefixGt, _sym_build_bool_and(prefixEq, _sym_build_unsigned_greater_than(a_len_expr, b_len_expr)));

  return _sym_build_ite(allEq, _sym_build_integer(0, 64),
                        _sym_build_ite(allLt, _sym_build_integer(-1, 64),
                                       _sym_build_integer(1, 64)));
}

void sym_pre_gofunc_internal_bytealg_count(void *base, size_t len, char needle, char *needle_ptr, uint64_t *result_ptr) {
  if(isConcrete(base, len)) {
    _sym_memset((uint8_t *)result_ptr, nullptr, sizeof(*result_ptr));
    return;
  }

  auto countExpr = _sym_build_integer(0, 64);
  auto dataShadowIt = ReadOnlyShadow(base, len).begin_non_null();
  auto needleExpr = *ReadOnlyShadow(needle_ptr, 1).begin_non_null();
  for (size_t i = 0; i < len; i++) {
    countExpr = _sym_build_add(countExpr, _sym_build_ite(
        _sym_build_equal(*dataShadowIt, needleExpr), _sym_build_integer(1, 64),
        _sym_build_integer(0, 64)));
    ++dataShadowIt;
  }
  _sym_memset((uint8_t *)result_ptr, countExpr, sizeof(*result_ptr));
}

void sym_pre_gofunc_internal_bytealg_indexbyte(void *base, size_t len, char needle, char *needle_ptr, uint64_t *result_ptr) {
  if(isConcrete(base, len)) {
    _sym_memset((uint8_t *)result_ptr, nullptr, sizeof(*result_ptr));
    return;
  }

  auto idxExpr = _sym_build_integer(-1, 64);
  auto dataShadowIt = ReadOnlyShadow(base, len).begin_non_null();
  auto needleExpr = *ReadOnlyShadow(needle_ptr, 1).begin_non_null();
  auto foundExpr = _sym_build_false();
  auto neverExpr = _sym_build_true();
  for (size_t i = 0; i < len; i++) {
    idxExpr = _sym_build_add(idxExpr, _sym_build_ite(foundExpr, _sym_build_integer(0, 64), _sym_build_integer(1, 64)));
    foundExpr = _sym_build_or(foundExpr, _sym_build_equal(*dataShadowIt, needleExpr));
    neverExpr = _sym_build_and(neverExpr, _sym_build_not_equal(*dataShadowIt, needleExpr));
    ++dataShadowIt;
  }

  _sym_memset((uint8_t *)result_ptr, _sym_build_ite(foundExpr, idxExpr, _sym_build_integer(-1, 64)), sizeof(*result_ptr));
}

}
