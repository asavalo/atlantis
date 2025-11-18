// This file is part of SymCC.
//
// SymCC is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// SymCC is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// SymCC. If not, see <https://www.gnu.org/licenses/>.

#include "Runtime.h"

#include <llvm/ADT/StringSet.h>
#include <llvm/Config/llvm-config.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/InlineAsm.h>

using namespace llvm;

namespace {

template <typename... ArgsTy>
SymFnT import(llvm::Module &M, llvm::StringRef name, llvm::Type *ret,
              ArgsTy... args) {
#if LLVM_VERSION_MAJOR >= 9 && LLVM_VERSION_MAJOR < 11
  return M.getOrInsertFunction(name, ret, args...).getCallee();
#else
  return M.getOrInsertFunction(name, ret, args...);
#endif
}

} // namespace

Runtime::Runtime(Module &M) {
  IRBuilder<> IRB(M.getContext());
  auto *intPtrType = M.getDataLayout().getIntPtrType(M.getContext());
  auto *ptrT = IRB.getInt8Ty()->getPointerTo();
  auto *int8T = IRB.getInt8Ty();
  auto *int1T = IRB.getInt1Ty();
  auto *voidT = IRB.getVoidTy();

  buildInteger = import(M, "_sym_build_integer", ptrT, IRB.getInt64Ty(), int8T);
  buildInteger128 = import(M, "_sym_build_integer128", ptrT, IRB.getInt64Ty(),
                           IRB.getInt64Ty());
  buildFloat = import(M, "_sym_build_float", ptrT, IRB.getDoubleTy(), int1T);
  buildNullPointer = import(M, "_sym_build_null_pointer", ptrT);
  buildTrue = import(M, "_sym_build_true", ptrT);
  buildFalse = import(M, "_sym_build_false", ptrT);
  buildBool = import(M, "_sym_build_bool", ptrT, int1T);
  buildSExt = import(M, "_sym_build_sext", ptrT, ptrT, int8T);
  buildZExt = import(M, "_sym_build_zext", ptrT, ptrT, int8T);
  buildTrunc = import(M, "_sym_build_trunc", ptrT, ptrT, int8T);
  buildBswap = import(M, "_sym_build_bswap", ptrT, ptrT);
  buildIntToFloat =
      import(M, "_sym_build_int_to_float", ptrT, ptrT, int1T, int1T);
  buildFloatToFloat = import(M, "_sym_build_float_to_float", ptrT, ptrT, int1T);
  buildBitsToFloat = import(M, "_sym_build_bits_to_float", ptrT, ptrT, int1T);
  buildFloatToBits = import(M, "_sym_build_float_to_bits", ptrT, ptrT);
  buildFloatToSignedInt =
      import(M, "_sym_build_float_to_signed_integer", ptrT, ptrT, int8T);
  buildFloatToUnsignedInt =
      import(M, "_sym_build_float_to_unsigned_integer", ptrT, ptrT, int8T);
  buildFloatAbs = import(M, "_sym_build_fp_abs", ptrT, ptrT);
  buildBoolAnd = import(M, "_sym_build_bool_and", ptrT, ptrT, ptrT);
  buildBoolOr = import(M, "_sym_build_bool_or", ptrT, ptrT, ptrT);
  buildBoolXor = import(M, "_sym_build_bool_xor", ptrT, ptrT, ptrT);
  buildBoolToBit = import(M, "_sym_build_bool_to_bit", ptrT, ptrT);
  buildBitToBool = import(M, "_sym_build_bit_to_bool", ptrT, ptrT);
  buildConcat =
      import(M, "_sym_concat_helper", ptrT, ptrT,
             ptrT); // doesn't follow naming convention for historic reasons
  pushPathConstraint =
      import(M, "_sym_push_path_constraint", voidT, ptrT, int1T, intPtrType);

  // Overflow arithmetic
  buildAddOverflow =
      import(M, "_sym_build_add_overflow", ptrT, ptrT, ptrT, int1T, int1T);
  buildSubOverflow =
      import(M, "_sym_build_sub_overflow", ptrT, ptrT, ptrT, int1T, int1T);
  buildMulOverflow =
      import(M, "_sym_build_mul_overflow", ptrT, ptrT, ptrT, int1T, int1T);

  // Saturating arithmetic
  buildSAddSat = import(M, "_sym_build_sadd_sat", ptrT, ptrT, ptrT);
  buildUAddSat = import(M, "_sym_build_uadd_sat", ptrT, ptrT, ptrT);
  buildSSubSat = import(M, "_sym_build_ssub_sat", ptrT, ptrT, ptrT);
  buildUSubSat = import(M, "_sym_build_usub_sat", ptrT, ptrT, ptrT);
  buildSShlSat = import(M, "_sym_build_sshl_sat", ptrT, ptrT, ptrT);
  buildUShlSat = import(M, "_sym_build_ushl_sat", ptrT, ptrT, ptrT);

  buildFshl = import(M, "_sym_build_funnel_shift_left", ptrT, ptrT, ptrT, ptrT);
  buildFshr =
      import(M, "_sym_build_funnel_shift_right", ptrT, ptrT, ptrT, ptrT);
  buildAbs = import(M, "_sym_build_abs", ptrT, ptrT);

  setParameterExpression =
      import(M, "_sym_set_parameter_expression", voidT, int8T, ptrT);
  getParameterExpression =
      import(M, "_sym_get_parameter_expression", ptrT, int8T);
  setReturnExpression = import(M, "_sym_set_return_expression", voidT, ptrT);
  getReturnExpression = import(M, "_sym_get_return_expression", ptrT);

#define LOAD_BINARY_OPERATOR_HANDLER(constant, name)                           \
  binaryOperatorHandlers[Instruction::constant] =                              \
      import(M, "_sym_build_" #name, ptrT, ptrT, ptrT);

  LOAD_BINARY_OPERATOR_HANDLER(Add, add)
  LOAD_BINARY_OPERATOR_HANDLER(Sub, sub)
  LOAD_BINARY_OPERATOR_HANDLER(Mul, mul)
  LOAD_BINARY_OPERATOR_HANDLER(UDiv, unsigned_div)
  LOAD_BINARY_OPERATOR_HANDLER(SDiv, signed_div)
  LOAD_BINARY_OPERATOR_HANDLER(URem, unsigned_rem)
  LOAD_BINARY_OPERATOR_HANDLER(SRem, signed_rem)
  LOAD_BINARY_OPERATOR_HANDLER(Shl, shift_left)
  LOAD_BINARY_OPERATOR_HANDLER(LShr, logical_shift_right)
  LOAD_BINARY_OPERATOR_HANDLER(AShr, arithmetic_shift_right)
  LOAD_BINARY_OPERATOR_HANDLER(And, and)
  LOAD_BINARY_OPERATOR_HANDLER(Or, or)
  LOAD_BINARY_OPERATOR_HANDLER(Xor, xor)

  // Floating-point arithmetic
  LOAD_BINARY_OPERATOR_HANDLER(FAdd, fp_add)
  LOAD_BINARY_OPERATOR_HANDLER(FSub, fp_sub)
  LOAD_BINARY_OPERATOR_HANDLER(FMul, fp_mul)
  LOAD_BINARY_OPERATOR_HANDLER(FDiv, fp_div)
  LOAD_BINARY_OPERATOR_HANDLER(FRem, fp_rem)

#undef LOAD_BINARY_OPERATOR_HANDLER

#define LOAD_UNARY_OPERATOR_HANDLER(constant, name)                            \
  unaryOperatorHandlers[Instruction::constant] =                               \
      import(M, "_sym_build_" #name, ptrT, ptrT);

  LOAD_UNARY_OPERATOR_HANDLER(FNeg, fp_neg)

#undef LOAD_UNARY_OPERATOR_HANDLER

#define LOAD_COMPARISON_HANDLER(constant, name)                                \
  comparisonHandlers[CmpInst::constant] =                                      \
      import(M, "_sym_build_" #name, ptrT, ptrT, ptrT);

  LOAD_COMPARISON_HANDLER(ICMP_EQ, equal)
  LOAD_COMPARISON_HANDLER(ICMP_NE, not_equal)
  LOAD_COMPARISON_HANDLER(ICMP_UGT, unsigned_greater_than)
  LOAD_COMPARISON_HANDLER(ICMP_UGE, unsigned_greater_equal)
  LOAD_COMPARISON_HANDLER(ICMP_ULT, unsigned_less_than)
  LOAD_COMPARISON_HANDLER(ICMP_ULE, unsigned_less_equal)
  LOAD_COMPARISON_HANDLER(ICMP_SGT, signed_greater_than)
  LOAD_COMPARISON_HANDLER(ICMP_SGE, signed_greater_equal)
  LOAD_COMPARISON_HANDLER(ICMP_SLT, signed_less_than)
  LOAD_COMPARISON_HANDLER(ICMP_SLE, signed_less_equal)

  // Floating-point comparisons
  LOAD_COMPARISON_HANDLER(FCMP_OGT, float_ordered_greater_than)
  LOAD_COMPARISON_HANDLER(FCMP_OGE, float_ordered_greater_equal)
  LOAD_COMPARISON_HANDLER(FCMP_OLT, float_ordered_less_than)
  LOAD_COMPARISON_HANDLER(FCMP_OLE, float_ordered_less_equal)
  LOAD_COMPARISON_HANDLER(FCMP_OEQ, float_ordered_equal)
  LOAD_COMPARISON_HANDLER(FCMP_ONE, float_ordered_not_equal)
  LOAD_COMPARISON_HANDLER(FCMP_ORD, float_ordered)
  LOAD_COMPARISON_HANDLER(FCMP_UNO, float_unordered)
  LOAD_COMPARISON_HANDLER(FCMP_UGT, float_unordered_greater_than)
  LOAD_COMPARISON_HANDLER(FCMP_UGE, float_unordered_greater_equal)
  LOAD_COMPARISON_HANDLER(FCMP_ULT, float_unordered_less_than)
  LOAD_COMPARISON_HANDLER(FCMP_ULE, float_unordered_less_equal)
  LOAD_COMPARISON_HANDLER(FCMP_UEQ, float_unordered_equal)
  LOAD_COMPARISON_HANDLER(FCMP_UNE, float_unordered_not_equal)

#undef LOAD_COMPARISON_HANDLER

  memcpy = import(M, "_sym_memcpy", voidT, ptrT, ptrT, intPtrType);
  memset = import(M, "_sym_memset", voidT, ptrT, ptrT, intPtrType);
  memmove = import(M, "_sym_memmove", voidT, ptrT, ptrT, intPtrType);
  readMemory =
      import(M, "_sym_read_memory", ptrT, intPtrType, intPtrType, int1T);
  writeMemory = import(M, "_sym_write_memory", voidT, intPtrType, intPtrType,
                       ptrT, int1T);
  buildZeroBytes = import(M, "_sym_build_zero_bytes", ptrT, intPtrType);
  buildInsert =
      import(M, "_sym_build_insert", ptrT, ptrT, ptrT, IRB.getInt64Ty(), int1T);
  buildExtract = import(M, "_sym_build_extract", ptrT, ptrT, IRB.getInt64Ty(),
                        IRB.getInt64Ty(), int1T);

  notifyCall = import(M, "_sym_notify_call", voidT, intPtrType);
  notifyRet = import(M, "_sym_notify_ret", voidT, intPtrType);
  notifyBasicBlock = import(M, "_sym_notify_basic_block", voidT, intPtrType);
  notifyFunction = import(M, "_sym_notify_function", voidT, intPtrType);
}

/// Decide whether a function is called symbolically.
bool isInterceptedFunction(const Function &f) {
  static const StringSet<> kInterceptedFunctions = {
      "malloc",
      "calloc",
      "mmap",
      "mmap64", /* "open",    "read" , */
      "lseek",
      "lseek64",
      "fopen",
      "fopen64",
      "fseek",
      "fseeko",
      "rewind",
      "fseeko64",
      "getc",
      "ungetc",
      "memcpy",
      "memset",
      "strncpy",
      "strchr",
      "memcmp",
      "memmove",
      "ntohl",
      "fgets",
      "fgetc",
      "getchar",
      "bcopy",
      "bcmp",
      "bzero",
      /* newly added */
      "strcmp",
      "strncmp",
      "pipe",
      "read",
      "write",
      "dup2",
      "fread",
      "fgets",
  };

  return (kInterceptedFunctions.count(f.getName()) > 0);
}

static void propagateCountToSymccRuntime(Module &M, CallInst *oldCI,
                                         CallInst **newCI, Function *symScanf,
                                         ConstantInt *count) {
  IRBuilder<> IRB(oldCI->getNextNode());
  std::vector<Value *> args;
  /* call __isoc99_scanf_symbolized_varargs(int, int, const char *, ....) */
  args.push_back(count);
  uint64_t nargs = count->getZExtValue() + 1;
  for (size_t i = 0; i < nargs; i++) {
    args.push_back(oldCI->getArgOperand(i));
  }
  ArrayRef<Value *> argsRef(args);
  *newCI = IRB.CreateCall(symScanf, argsRef);
}

static void countArgumentsInScanfCall(Module &M, CallInst *CI,
                                      ConstantInt **count) {
  /* get number of variadic arguments
   * Args(0): function
   * Args(1): format string */
  size_t numVariadicArgs = CI->getNumOperands() - 2;
  *count = ConstantInt::get(Type::getInt32Ty(M.getContext()), numVariadicArgs);
}

void instrumentScanf(Module &M) {
  if (auto *F = M.getFunction("__isoc99_scanf")) {
    /* create an external function with the name
     * __isoc99_scanf_symbolized_varags. Its function type is void F(int count,
     * const char *, ...)
     */
    FunctionType *FT = FunctionType::get(
        Type::getInt32Ty(M.getContext()),
        {Type::getInt32Ty(M.getContext()),
         PointerType::getUnqual(Type::getInt8Ty(M.getContext()))},
        true);
    auto *symScanf = Function::Create(FT, GlobalValue::ExternalLinkage,
                                      "__isoc99_scanf_symbolized_vararg", &M);
    // create a global variable to store the number of bytes read (scanf_nbytes)
    for (auto iter = F->user_begin(); iter != F->user_end(); ++iter) {
      if (auto *CI = dyn_cast<CallInst>(*iter)) {
        Constant *newFmtStr;
        Value *nbytes;
        ConstantInt *count;
        CallInst *newCI;
        countArgumentsInScanfCall(M, CI, &count);
        propagateCountToSymccRuntime(M, CI, &newCI, symScanf, count);
        CI->replaceAllUsesWith(newCI);
        CI->eraseFromParent();
      }
    }
  }
}
