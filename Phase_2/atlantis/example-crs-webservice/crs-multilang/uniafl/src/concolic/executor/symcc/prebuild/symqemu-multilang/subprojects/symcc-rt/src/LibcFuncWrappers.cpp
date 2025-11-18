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

extern "C" {

SymExpr sym_pre_libc_func_strncmp(const char *lhs, const char *rhs, const size_t count) {
  // TODO(kyuheon): symbolization is incomplete
  if(isConcrete(lhs, count) && isConcrete(rhs, count)) {
    return nullptr;
  }

  auto lhsIt = ReadOnlyShadow(lhs, count).begin_non_null();
  auto rhsIt = ReadOnlyShadow(rhs, count).begin_non_null();

  auto *eq = _sym_build_true();

  for(size_t i = 0; i < count ; i++) {
    eq = _sym_build_bool_and(eq, _sym_build_equal(*lhsIt, *rhsIt));
    ++lhsIt;
    ++rhsIt;
  }

  return _sym_build_ite(eq, _sym_build_integer(0, 64), _sym_build_integer(-1, 64));
}

SymExpr sym_pre_libc_func_memcmp(const char *lhs, const char *rhs, const size_t count) {
  if(isConcrete(lhs, count) && isConcrete(rhs, count)) {
    return nullptr;
  }

  auto lhsIt = ReadOnlyShadow(lhs, count).begin_non_null();
  auto rhsIt = ReadOnlyShadow(rhs, count).begin_non_null();

  auto *eq = _sym_build_true();
  auto *lt = _sym_build_false();
  auto *gt = _sym_build_false();

  for(size_t i = 0; i < count ; i++) {
    lt = _sym_build_bool_or(lt, _sym_build_bool_and(eq, _sym_build_unsigned_less_than(*lhsIt, *rhsIt)));
    gt = _sym_build_bool_or(gt, _sym_build_bool_and(eq, _sym_build_unsigned_greater_than(*lhsIt, *rhsIt)));
    eq = _sym_build_bool_and(eq, _sym_build_equal(*lhsIt, *rhsIt));
    ++lhsIt;
    ++rhsIt;
  }

  return _sym_build_ite(eq, _sym_build_integer(0, 64), _sym_build_ite(lt, _sym_build_integer(-1, 64), _sym_build_integer(1, 64)));
}

}
