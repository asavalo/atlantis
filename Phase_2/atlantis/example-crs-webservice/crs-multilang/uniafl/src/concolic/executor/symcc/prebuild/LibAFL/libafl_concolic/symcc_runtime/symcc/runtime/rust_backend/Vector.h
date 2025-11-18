#include <cstdint>

struct VectorInfo {
    uint64_t elem_cnt;
    uint64_t elem_size;
};

void registerVectorInfo(SymExpr expr, uint64_t elem_cnt, uint64_t elem_size);
VectorInfo getVectorInfo(SymExpr expr);
