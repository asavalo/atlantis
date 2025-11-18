// clang-format off
#include "Runtime.h"
#include "Vector.h"
// clang-format on
#include <map>
std::map<SymExpr, VectorInfo> vectorInfos;

void registerVectorInfo(SymExpr expr, uint64_t elem_cnt, uint64_t elem_size) {
  vectorInfos[expr] = VectorInfo{elem_cnt, elem_size};
}

VectorInfo getVectorInfo(SymExpr expr) {
  auto it = vectorInfos.find(expr);
  if (it != vectorInfos.end()) {
    return it->second;
  }
  throw std::runtime_error("Vector info not found for the given expression");
}
