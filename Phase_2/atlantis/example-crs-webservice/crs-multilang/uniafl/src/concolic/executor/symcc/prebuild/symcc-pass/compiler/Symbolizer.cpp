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

#include "Symbolizer.h"

#include "Runtime.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InlineAsm.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdint>
#include <cstdlib>
#include <llvm/ADT/Hashing.h>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/ADT/StringRef.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/GlobalValue.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>
#include <sys/stat.h>
#include <utility>

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

using namespace llvm;

void Symbolizer::symbolizeFunctionArguments(Function &F) {
  // The main function doesn't receive symbolic arguments.
  if (F.getName() == "main")
    return;

  IRBuilder<> IRB(F.getEntryBlock().getFirstNonPHI());

  for (auto &arg : F.args()) {
    if (!arg.user_empty())
      symbolicExpressions[&arg] = IRB.CreateCall(runtime.getParameterExpression,
                                                 IRB.getInt8(arg.getArgNo()));
  }
}

void Symbolizer::insertBasicBlockNotification(llvm::BasicBlock &B) {
  DEBUG(errs() << "[Symbolizer::insertBasicBlockNotification]" << B.getName()
               << '\n');
  IRBuilder<> IRB(&*B.getFirstInsertionPt());
  IRB.CreateCall(runtime.notifyBasicBlock, getTargetPreferredInt(&B));
}

void Symbolizer::insertFunctionNotification(llvm::Function &F) {
  DEBUG(errs() << "[Symbolizer::insertFunctionNotification]" << F.getName()
               << '\n');
  IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
  IRB.CreateCall(runtime.notifyFunction, getTargetPreferredInt(&F));
}

void Symbolizer::finalizePHINodes() {
  SmallPtrSet<PHINode *, 32> nodesToErase;

  for (auto *phi : phiNodes) {
    DEBUG(errs() << "[Symbolizer::finalizePHINodes] " << *phi << '\n');
    auto symbolicPHI = cast<PHINode>(symbolicExpressions[phi]);

    // A PHI node that receives only compile-time constants can be replaced by
    // a null expression.
    if (std::all_of(phi->op_begin(), phi->op_end(), [this](Value *input) {
          return (getSymbolicExpression(input) == nullptr);
        })) {
      nodesToErase.insert(symbolicPHI);
      continue;
    }

    for (unsigned incoming = 0, totalIncoming = phi->getNumIncomingValues();
         incoming < totalIncoming; incoming++) {
      symbolicPHI->setIncomingValue(
          incoming,
          getSymbolicExpressionOrNull(phi->getIncomingValue(incoming)));
    }
  }

  for (auto *symbolicPHI : nodesToErase) {
    symbolicPHI->replaceAllUsesWith(
        ConstantPointerNull::get(cast<PointerType>(symbolicPHI->getType())));
    symbolicPHI->eraseFromParent();
  }

  // Replacing all uses has fixed uses of the symbolic PHI nodes in existing
  // code, but the nodes may still be referenced via symbolicExpressions. We
  // therefore invalidate symbolicExpressions, meaning that it cannot be used
  // after this point.
  symbolicExpressions.clear();
}

struct CastToIntegerResult {
  bool valid;
  Value *value;

  CastToIntegerResult(bool valid, Value *value) : valid(valid), value(value) {}
};

CastToIntegerResult castToInteger(IRBuilder<> &IRB, Value *V) {
  Type *T = V->getType();
  if (T->isPointerTy()) {
    return CastToIntegerResult(true, IRB.CreatePtrToInt(V, IRB.getInt64Ty()));
  } else if (T->isIntegerTy()) {
    return CastToIntegerResult(true,
                               IRB.CreateSExtOrTrunc(V, IRB.getInt64Ty()));
  } else if (T->isFloatTy()) {
    return CastToIntegerResult(
        true, IRB.CreateZExt(IRB.CreateBitCast(V, IRB.getInt32Ty()),
                             IRB.getInt64Ty()));
  } else if (T->isDoubleTy()) {
    return CastToIntegerResult(true, IRB.CreateBitCast(V, IRB.getInt64Ty()));
  } else {
    return CastToIntegerResult(false, IRB.getInt64(0));
  }
}
void Symbolizer::handleIntrinsicCall(CallBase &I) {
  DEBUG(errs() << "[Symbolizer::handleIntrinsicCall] " << I << '\n');
  auto *callee = I.getCalledFunction();

  switch (callee->getIntrinsicID()) {
  case Intrinsic::dbg_value:
  case Intrinsic::dbg_assign:
  case Intrinsic::dbg_declare:
  case Intrinsic::dbg_label:
  case Intrinsic::is_constant:
  case Intrinsic::trap:
    // These are safe to ignore.
    break;
  case Intrinsic::memcpy: {
    IRBuilder<> IRB(&I);

#ifdef ENABLE_TRY_ALTERNATIVE
    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(1));
    tryAlternative(IRB, I.getOperand(2));
#endif
    // The intrinsic allows both 32 and 64-bit integers to specify the length;
    // convert to the right type if necessary. This may truncate the value on
    // 32-bit architectures. However, what's the point of specifying a length to
    // memcpy that is larger than your address space?

    IRB.CreateCall(runtime.memcpy,
                   {I.getOperand(0), I.getOperand(1),
                    IRB.CreateZExtOrTrunc(I.getOperand(2), intPtrType)});
    break;
  }
  case Intrinsic::memset: {
    IRBuilder<> IRB(&I);
#ifdef ENABLE_TRY_ALTERNATIVE
    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(2));
#endif
    // The comment on memcpy's length parameter applies analogously.

    IRB.CreateCall(runtime.memset,
                   {I.getOperand(0),
                    getSymbolicExpressionOrNull(I.getOperand(1)),
                    IRB.CreateZExtOrTrunc(I.getOperand(2), intPtrType)});
    break;
  }
  case Intrinsic::memmove: {
    IRBuilder<> IRB(&I);
#ifdef ENABLE_TRY_ALTERNATIVE
    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(1));
    tryAlternative(IRB, I.getOperand(2));
#endif
    // The comment on memcpy's length parameter applies analogously.

    IRB.CreateCall(runtime.memmove,
                   {I.getOperand(0), I.getOperand(1),
                    IRB.CreateZExtOrTrunc(I.getOperand(2), intPtrType)});
    break;
  }
  case Intrinsic::stacksave: {
    // The intrinsic returns an opaque pointer that should only be passed to
    // the stackrestore intrinsic later. We treat the pointer as a constant.
    break;
  }
  case Intrinsic::stackrestore:
    // Ignored; see comment on stacksave above.
    break;
  case Intrinsic::expect:
    // Just a hint for the optimizer; the value is the first parameter.
    if (auto *expr = getSymbolicExpression(I.getArgOperand(0)))
      symbolicExpressions[&I] = expr;
    break;
  case Intrinsic::fabs: {
    // Floating-point absolute value; use the runtime to build the
    // corresponding symbolic expression.

    IRBuilder<> IRB(&I);
    auto abs = buildRuntimeCall(IRB, runtime.buildFloatAbs, I.getOperand(0));
    registerSymbolicComputation(abs, &I);
    break;
  }
  case Intrinsic::returnaddress:
  case Intrinsic::frameaddress:
  case Intrinsic::addressofreturnaddress: {
    // Obtain the return address of the current function or one of its parents
    // on the stack. We just concretize.

    DEBUG(errs() << "Warning: using concrete value for return/frame address\n");
    break;
  }
  case Intrinsic::bswap: {
    // Bswap changes the endian-ness of integer values.

    IRBuilder<> IRB(&I);
    auto swapped = buildRuntimeCall(IRB, runtime.buildBswap, I.getOperand(0));
    registerSymbolicComputation(swapped, &I);
    break;
  }

// Overflow arithmetic
#define DEF_OVF_ARITH_BUILDER(intrinsic_op, runtime_name)                      \
  case Intrinsic::s##intrinsic_op##_with_overflow:                             \
  case Intrinsic::u##intrinsic_op##_with_overflow: {                           \
    IRBuilder<> IRB(&I);                                                       \
                                                                               \
    bool isSigned =                                                            \
        I.getIntrinsicID() == Intrinsic::s##intrinsic_op##_with_overflow;      \
    auto overflow = buildRuntimeCall(                                          \
        IRB, runtime.build##runtime_name,                                      \
        {{I.getOperand(0), true},                                              \
         {I.getOperand(1), true},                                              \
         {IRB.getInt1(isSigned), false},                                       \
         {IRB.getInt1(dataLayout.isLittleEndian() ? 1 : 0), false}});          \
    registerSymbolicComputation(overflow, &I);                                 \
                                                                               \
    break;                                                                     \
  }

    DEF_OVF_ARITH_BUILDER(add, AddOverflow)
    DEF_OVF_ARITH_BUILDER(sub, SubOverflow)
    DEF_OVF_ARITH_BUILDER(mul, MulOverflow)

#undef DEF_OVF_ARITH_BUILDER

// Saturating arithmetic
#define DEF_SAT_ARITH_BUILDER(intrinsic_op, runtime_name)                      \
  case Intrinsic::intrinsic_op##_sat: {                                        \
    IRBuilder<> IRB(&I);                                                       \
    auto result = buildRuntimeCall(IRB, runtime.build##runtime_name,           \
                                   {I.getOperand(0), I.getOperand(1)});        \
    registerSymbolicComputation(result, &I);                                   \
    break;                                                                     \
  }

    DEF_SAT_ARITH_BUILDER(sadd, SAddSat)
    DEF_SAT_ARITH_BUILDER(uadd, UAddSat)
    DEF_SAT_ARITH_BUILDER(ssub, SSubSat)
    DEF_SAT_ARITH_BUILDER(usub, USubSat)
#if LLVM_VERSION_MAJOR > 11
    DEF_SAT_ARITH_BUILDER(sshl, SShlSat)
    DEF_SAT_ARITH_BUILDER(ushl, UShlSat)
#endif

#undef DEF_SAT_ARITH_BUILDER

  case Intrinsic::fshl:
  case Intrinsic::fshr: {
    IRBuilder<> IRB(&I);
    auto funnelShift = buildRuntimeCall(
        IRB,
        I.getIntrinsicID() == Intrinsic::fshl ? runtime.buildFshl
                                              : runtime.buildFshr,
        {I.getOperand(0), I.getOperand(1), I.getOperand(2)});
    registerSymbolicComputation(funnelShift, &I);
    break;
  }
#if LLVM_VERSION_MAJOR > 11
  case Intrinsic::abs: {
    // Integer absolute value

    IRBuilder<> IRB(&I);
    auto abs = buildRuntimeCall(IRB, runtime.buildAbs, I.getOperand(0));
    registerSymbolicComputation(abs, &I);
    break;
  }
#endif
  default:
    size_t nargs = I.arg_size();
    if (nargs == 0 || I.getType()->isVoidTy()) {
      return;
    }
    IRBuilder<> IRB(I.getNextNode());
    std::vector<std::pair<llvm::Value *, bool>> args;
    args.push_back({IRB.getInt64(I.getIntrinsicID()), false});
    args.push_back({getLocHash(&I), false});
    CastToIntegerResult res = castToInteger(IRB, &I);
    args.push_back({IRB.getInt1(res.valid), false});
    args.push_back({res.value, false});
    if (res.valid) {
      args.push_back(
          {IRB.getInt64(I.getType()->getPrimitiveSizeInBits()), false});
    } else {
      args.push_back({IRB.getInt64(0), false});
    }
    args.push_back({IRB.getInt64(nargs), false});
    // TODO: what if this adds too much overhead?
    for (auto &arg : I.args()) {
      CastToIntegerResult res = castToInteger(IRB, arg);
      args.push_back({arg, true});
      args.push_back({IRB.getInt1(res.valid), false});
      args.push_back({res.value, false});
    }
    auto sc = forceBuildRuntimeCall(IRB, runtime.hookIntrinsicCall, args);
    registerSymbolicComputation(sc, &I);
    break;
  }
}

void Symbolizer::handleInlineAssembly(CallInst &I) {
  DEBUG(errs() << "[Symbolizer::handleInlineAssembly] " << I << '\n');
  if (I.getType()->isVoidTy()) {
    DEBUG(errs() << "Warning: skipping over inline assembly " << I << '\n');
    return;
  }

  DEBUG(errs()
        << "Warning: losing track of symbolic expressions at inline assembly "
        << I << '\n');
}

Value *getTypeSize(IRBuilder<> &IRB, Type *T) {
  if (T->isIntOrPtrTy() || T->isFloatTy()) {
    return IRB.getInt64(T->getPrimitiveSizeInBits());
  } else {
    return IRB.getInt64(0);
  }
}

void Symbolizer::handleFunctionCall(CallBase &I, Instruction *returnPoint) {
  auto *callee = I.getCalledFunction();
  if (callee != nullptr && callee->isIntrinsic()) {
    handleIntrinsicCall(I);
    return;
  }

  IRBuilder<> IRB(returnPoint);
  IRB.CreateCall(runtime.notifyRet, getTargetPreferredInt(&I));
  IRB.SetInsertPoint(&I);
  IRB.CreateCall(runtime.notifyCall, getTargetPreferredInt(&I));

#ifdef ENABLE_TRY_ALTERNATIVE
  if (callee == nullptr)
    tryAlternative(IRB, I.getCalledOperand());
#endif

  for (Use &arg : I.args())
    IRB.CreateCall(runtime.setParameterExpression,
                   {ConstantInt::get(IRB.getInt8Ty(), arg.getOperandNo()),
                    getSymbolicExpressionOrNull(arg)});

  // @WS: Even if the called function's return value is not used,
  // it may still produce side effects through global variables or writable
  // pointer arguments (e.g., scanf). Therefore, it is essential to model the
  // function's behavior regardless of !I.user_empty. However, it is
  // preferable to do this after the function call.
  if (auto *F = I.getCalledFunction()) {
    if (F->isDeclaration() && !F->isIntrinsic() &&
        !isInterceptedFunction(*F, true) && isSuitableForHooking(*F)) {
      IRB.CreateCall(runtime.setReturnExpression,
                     ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()));
      IRB.SetInsertPoint(returnPoint);
      IntegerType *i64Ty = IRB.getInt64Ty();
      PointerType *ptrTy = IRB.getInt8Ty()->getPointerTo();

      // arg0: function address
      // arg1: return locHash
      // arg2: return value
      // arg3: return value size
      // ...: concrete arguments

      std::vector<std::pair<Value *, bool>> args;
      args.push_back({castToInteger(IRB, F).value, false});
      args.push_back({getLocHash(returnPoint), false});
      auto res = castToInteger(IRB, &I);
      args.push_back({IRB.getInt1(res.valid), false});
      args.push_back({res.value, false});
      if (res.valid) {
        args.push_back(
            {IRB.getInt64(I.getType()->getPrimitiveSizeInBits()), false});
      } else {
        args.push_back({IRB.getInt64(0), false});
      }
      args.push_back({IRB.getInt64(I.arg_size()), false});
      bool missingArg = false;
      // this part is problematic
      for (auto &arg : I.args()) {
        // this means that arg is statically constant. In this case, short
        // circuiting will not construct a SymExpr for this arg, so we create it
        // ourself
        CastToIntegerResult res = castToInteger(IRB, arg);
        if (symbolicExpressions.find(arg) == symbolicExpressions.end()) {
          auto ve = createValueExpression(arg, IRB);
          // In this case, pass the symbolic value directly to avoid
          // short-circuiting.
          // Do not write to symbolicExpressions, as it may be referenced
          // elsewhere. Writing to it here could cause a "operand does not
          // dominate usage" error, since createValueExpression inserts
          // instructions at point B, which is after the creation of 'arg' at
          // point A. symbolicExpressions[arg] might be used anywhere between A
          // and B.
          args.push_back({ve.value, false});
        } else {
          // rely on short circuiting
          args.push_back({arg, true});
        }
        args.push_back({IRB.getInt1(res.valid), false});
        args.push_back({res.value, false});
      }
      if (missingArg) {
        return;
      }

      // forceBuildRuntimeCall so that RV always has value
      auto RV = forceBuildRuntimeCall(IRB, runtime.hookFunctionCall, args);
      auto *RV2 = IRB.CreateCall(runtime.getReturnExpression);
      // RV should always be non nuil because of concreteRV
      // prioritize RV (python returned value) over RV2 (symcc-based value)
      auto *cond = IRB.CreateICmpNE(
          RV.lastInstruction, ConstantPointerNull::get(i64Ty->getPointerTo()));
      symbolicExpressions[&I] = IRB.CreateSelect(cond, RV.lastInstruction, RV2);

      // If the function is not intercepted, we need to set the return
      // expression to the one generated inside the function
    } else if (!I.user_empty()) {
      // The result of the function is used somewhere later on. Since we have
      // no way of knowing whether the function is instrumented (and thus sets
      // a proper return expression), we have to account for the possibility
      // that it's not: in that case, we'll have to treat the result as an
      // opaque concrete value. Therefore, we set the return expression to
      // null here in order to avoid accidentally using whatever is stored
      // there from the previous function call. (If the function is
      // instrumented, it will just override our null with the real
      // expression.)
      IRB.CreateCall(runtime.setReturnExpression,
                     ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()));
      IRB.SetInsertPoint(returnPoint);
      symbolicExpressions[&I] = IRB.CreateCall(runtime.getReturnExpression);
    }
  }
}

void Symbolizer::visitBinaryOperator(BinaryOperator &I) {
  DEBUG(errs() << "[Symbolizer::visitBinaryOperator] " << I << '\n');
  // Binary operators propagate into the symbolic expression.

  IRBuilder<> IRB(&I);
  SymFnT handler = runtime.binaryOperatorHandlers.at(I.getOpcode());

  // Special case: the run-time library distinguishes between "and" and "or"
  // on Boolean values and bit vectors.
  if (I.getOperand(0)->getType() == IRB.getInt1Ty()) {
    switch (I.getOpcode()) {
    case Instruction::And:
      handler = runtime.buildBoolAnd;
      break;
    case Instruction::Or:
      handler = runtime.buildBoolOr;
      break;
    case Instruction::Xor:
      handler = runtime.buildBoolXor;
      break;
    default:
      DEBUG(errs() << "Can't handle Boolean operator " << I << '\n');
      llvm_unreachable("Unknown Boolean operator");
      break;
    }
  }

  assert(handler && "Unable to handle binary operator");
  auto runtimeCall =
      buildRuntimeCall(IRB, handler, {I.getOperand(0), I.getOperand(1)});
  registerSymbolicComputation(runtimeCall, &I);
}

void Symbolizer::visitUnaryOperator(UnaryOperator &I) {
  DEBUG(errs() << "[Symbolizer::visitUnaryOperator] " << I << '\n');
  IRBuilder<> IRB(&I);
  SymFnT handler = runtime.unaryOperatorHandlers.at(I.getOpcode());

  assert(handler && "Unable to handle unary operator");
  auto runtimeCall = buildRuntimeCall(IRB, handler, I.getOperand(0));
  registerSymbolicComputation(runtimeCall, &I);
}

void Symbolizer::visitSelectInst(SelectInst &I) {
  DEBUG(errs() << "[Symbolizer::visitSelectInst] " << I << '\n');
  // Select is like the ternary operator ("?:") in C. We push the (potentially
  // negated) condition to the path constraints and copy the symbolic
  // expression over from the chosen argument.

  IRBuilder<> IRB(&I);
  if (auto *vectorType = dyn_cast<VectorType>(I.getType())) {
    handleVectorSelectInst(I, vectorType);
    return;
  }
  assert(I.getCondition()->getType() == IRB.getInt1Ty() &&
         "SelectInst has non-boolean condition");
#ifdef SYMCC_OBSESSIVE
  auto runtimeCall = forceBuildRuntimeCall(IRB, runtime.pushPathConstraint,
                                           {{I.getCondition(), true},
                                            {I.getCondition(), false},
                                            {getLocHash(&I), false}});
#else
  auto runtimeCall = buildRuntimeCall(IRB, runtime.pushPathConstraint,
                                      {{I.getCondition(), true},
                                       {I.getCondition(), false},
                                       {getLocHash(&I), false}});
#endif
  registerSymbolicComputation(runtimeCall);
  if (getSymbolicExpression(I.getTrueValue()) ||
      getSymbolicExpression(I.getFalseValue())) {
    auto *data = IRB.CreateSelect(
        I.getCondition(), getSymbolicExpressionOrNull(I.getTrueValue()),
        getSymbolicExpressionOrNull(I.getFalseValue()));
    symbolicExpressions[&I] = data;
  }
}

void Symbolizer::visitCmpInst(CmpInst &I) {
  DEBUG(errs() << "[Symbolizer::visitCmpInst] " << I << '\n');
  // ICmp is integer comparison, FCmp compares floating-point values; we
  // simply include either in the resulting expression.

  IRBuilder<> IRB(&I);
  SymFnT handler = runtime.comparisonHandlers.at(I.getPredicate());
  assert(handler && "Unable to handle icmp/fcmp variant");
  auto runtimeCall =
      buildRuntimeCall(IRB, handler, {I.getOperand(0), I.getOperand(1)});
  registerSymbolicComputation(runtimeCall, &I);
}

void Symbolizer::visitReturnInst(ReturnInst &I) {
  DEBUG(errs() << "[Symbolizer::visitReturnInst] " << I << '\n');
  // Upon return, we just store the expression for the return value.

  if (I.getReturnValue() == nullptr)
    return;

  // We can't short-circuit this call because the return expression needs to
  // be set even if it's null; otherwise we break the caller. Therefore,
  // create the call directly without registering it for short-circuit
  // processing.
  IRBuilder<> IRB(&I);
  IRB.CreateCall(runtime.setReturnExpression,
                 getSymbolicExpressionOrNull(I.getReturnValue()));
}

void Symbolizer::visitBranchInst(BranchInst &I) {
  DEBUG(errs() << "[Symbolizer::visitBranchInst] " << I << '\n');
  // Br can jump conditionally or unconditionally. We are only interested in
  // the former case, in which we push the branch condition or its negation to
  // the path constraints.

  if (I.isUnconditional())
    return;

  IRBuilder<> IRB(&I);
#ifdef SYMCC_OBSESSIVE
  auto runtimeCall = forceBuildRuntimeCall(IRB, runtime.pushPathConstraint,
                                           {{I.getCondition(), true},
                                            {I.getCondition(), false},
                                            {getLocHash(&I), false}});
#else
  auto runtimeCall = buildRuntimeCall(IRB, runtime.pushPathConstraint,
                                      {{I.getCondition(), true},
                                       {I.getCondition(), false},
                                       {getLocHash(&I), false}});
#endif
  registerSymbolicComputation(runtimeCall);
}

void Symbolizer::visitIndirectBrInst(IndirectBrInst &I) {
  DEBUG(errs() << "[Symbolizer::visitIndirectBrInst] " << I << '\n');
#ifdef ENABLE_TRY_ALTERNATIVE
  IRBuilder<> IRB(&I);
  tryAlternative(IRB, I.getAddress());
#endif
}

void Symbolizer::visitCallInst(CallInst &I) {
  DEBUG(errs() << "[Symbolizer::visitCallInst] " << I << '\n');
  if (I.isInlineAsm())
    handleInlineAssembly(I);
  else
    handleFunctionCall(I, I.getNextNode());
}

void Symbolizer::visitInvokeInst(InvokeInst &I) {
  // Invoke is like a call but additionally establishes an exception handler.
  // We can obtain the return expression only in the success case, but the
  // target block may have multiple incoming edges (i.e., our edge may be
  // critical). In this case, we split the edge and query the return
  // expression in the new block that is specific to our edge.
  auto *newBlock = SplitCriticalEdge(I.getParent(), I.getNormalDest());
  handleFunctionCall(I, newBlock != nullptr
                            ? newBlock->getFirstNonPHI()
                            : I.getNormalDest()->getFirstNonPHI());
}

void Symbolizer::visitAllocaInst(AllocaInst & /*unused*/) {
  // Nothing to do: the shadow for the newly allocated memory region will be
  // created on first write; until then, the memory contents are concrete.
}

void Symbolizer::visitLoadInst(LoadInst &I) {
  DEBUG(errs() << "[Symbolizer::visitLoadInst] " << I << '\n');
  IRBuilder<> IRB(&I);

  auto *addr = I.getPointerOperand();

#ifdef SYMCC_VERBOSE
  if (isLlvmProfileCounter(&I, addr).first) {
    // LLVM profile counters are not symbolic; they are concrete values.
    return;
  }
#endif

#ifdef ENABLE_TRY_ALTERNATIVE
  tryAlternative(IRB, addr);
#endif

  auto *dataType = I.getType();
  if (!dataType->isVectorTy()) {
    // If the type is an integer, pointer, or floating-point type, we can
    // directly read it from memory.
    auto *data = IRB.CreateCall(
        runtime.readMemory,
        {IRB.CreatePtrToInt(addr, intPtrType),
         ConstantInt::get(intPtrType, dataLayout.getTypeStoreSize(dataType)),
         IRB.getInt1(isLittleEndian(dataType) ? 1 : 0)});
    symbolicExpressions[&I] = convertBitVectorExprForType(IRB, data, dataType);
    return;
  } else if (VectorType *vectorType = dyn_cast<VectorType>(dataType)) {
    // If the type is a vector, we read the memory as a bit-vector and convert
    // it to the vector type.
    loadVectorFromMemory(&I, vectorType);
  } else {
    // this happens when you load a struct.
    std::string typeStr;
    llvm::raw_string_ostream stream(typeStr);
    dataType->print(stream);
    std::string errorMessage = "Unreachable: " + stream.str();
    report_fatal_error(errorMessage.c_str());
  }
}

void Symbolizer::visitStoreInst(StoreInst &I) {
  DEBUG(errs() << "[Symbolizer::visitStoreInst] " << I << '\n');
  IRBuilder<> IRB(&I);

  auto *addr = I.getPointerOperand();
#ifdef SYMCC_VERBOSE
  if (isLlvmProfileCounter(&I, addr).first) {
    // LLVM profile counters are not symbolic; they are concrete values.
    return;
  }
#endif

#ifdef ENABLE_TRY_ALTERNATIVE
  tryAlternative(IRB, I.getPointerOperand());
#endif

  // Make sure that the expression corresponding to the stored value is of
  // bit-vector kind. Shortcutting the runtime calls that we emit here (e.g.,
  // for floating-point values) is tricky, so instead we make sure that any
  // runtime function we call can handle null expressions.

  auto V = I.getValueOperand();
  auto maybeConversion =
      convertExprForTypeToBitVectorExpr(IRB, V, getSymbolicExpression(V));

  auto *dataType = V->getType();
  if (!dataType->isVectorTy()) {
    // If the type is an integer, pointer, or floating-point type, we can
    // directly write it to memory.
    IRB.CreateCall(
        runtime.writeMemory,
        {IRB.CreatePtrToInt(addr, intPtrType),
         ConstantInt::get(intPtrType, dataLayout.getTypeStoreSize(dataType)),
         maybeConversion ? maybeConversion->lastInstruction
                         : getSymbolicExpressionOrNull(V),
         IRB.getInt1(isLittleEndian(dataType) ? 1 : 0)});
    return;
  } else if (VectorType *vectorType = dyn_cast<VectorType>(dataType)) {
    storeVectorToMemory(&I, vectorType);
  } else {
    std::string typeStr;
    llvm::raw_string_ostream stream(typeStr);
    dataType->print(stream);
    std::string errorMessage = "Unreachable: " + stream.str();
    report_fatal_error(errorMessage.c_str());
  }
}

void Symbolizer::visitGetElementPtrInst(GetElementPtrInst &I) {
  DEBUG(errs() << "[Symbolizer::visitGetElementPtrInst] " << I << '\n');
  // GEP performs address calculations but never actually accesses memory. In
  // order to represent the result of a GEP symbolically, we start from the
  // symbolic expression of the original pointer and duplicate its
  // computations at the symbolic level.

  // If everything is compile-time concrete, we don't need to emit code.
  if (getSymbolicExpression(I.getPointerOperand()) == nullptr &&
      std::all_of(I.idx_begin(), I.idx_end(), [this](Value *index) {
        return (getSymbolicExpression(index) == nullptr);
      })) {
    return;
  }

  // If there are no indices or if they are all zero we can return early as
  // well.
  if (std::all_of(I.idx_begin(), I.idx_end(), [](Value *index) {
        auto *ci = dyn_cast<ConstantInt>(index);
        return (ci != nullptr && ci->isZero());
      })) {
    symbolicExpressions[&I] = getSymbolicExpression(I.getPointerOperand());
    return;
  }

  IRBuilder<> IRB(&I);
  SymbolicComputation symbolicComputation;
  Value *currentAddress = I.getPointerOperand();

  for (auto type_it = gep_type_begin(I), type_end = gep_type_end(I);
       type_it != type_end; ++type_it) {
    auto *index = type_it.getOperand();
    std::pair<Value *, bool> addressContribution;

    // There are two cases for the calculation:
    // 1. If the indexed type is a struct, we need to add the offset of the
    //    desired member.
    // 2. If it is an array or a pointer, compute the offset of the desired
    //    element.
    if (auto *structType = type_it.getStructTypeOrNull()) {
      // Structs can only be indexed with constants
      // (https://llvm.org/docs/LangRef.html#getelementptr-instruction).

      unsigned memberIndex = cast<ConstantInt>(index)->getZExtValue();
      unsigned memberOffset =
          dataLayout.getStructLayout(structType)->getElementOffset(memberIndex);
      addressContribution = {ConstantInt::get(intPtrType, memberOffset), true};
    } else {
      if (auto *ci = dyn_cast<ConstantInt>(index);
          ci != nullptr && ci->isZero()) {
        // Fast path: an index of zero means that no calculations are
        // performed.
        continue;
      }

      // TODO optimize? If the index is constant, we can perform the
      // multiplication ourselves instead of having the solver do it. Also, if
      // the element size is 1, we can omit the multiplication.

      unsigned elementSize =
          dataLayout.getTypeAllocSize(type_it.getIndexedType());
      if (auto indexWidth = index->getType()->getIntegerBitWidth();
          indexWidth != ptrBits) {
        symbolicComputation.merge(forceBuildRuntimeCall(
            IRB, runtime.buildZExt,
            {{index, true},
             {ConstantInt::get(IRB.getInt8Ty(), ptrBits - indexWidth),
              false}}));
        symbolicComputation.merge(forceBuildRuntimeCall(
            IRB, runtime.binaryOperatorHandlers[Instruction::Mul],
            {{symbolicComputation.lastInstruction, false},
             {ConstantInt::get(intPtrType, elementSize), true}}));
      } else {
        symbolicComputation.merge(forceBuildRuntimeCall(
            IRB, runtime.binaryOperatorHandlers[Instruction::Mul],
            {{index, true},
             {ConstantInt::get(intPtrType, elementSize), true}}));
      }

      addressContribution = {symbolicComputation.lastInstruction, false};
    }

    symbolicComputation.merge(forceBuildRuntimeCall(
        IRB, runtime.binaryOperatorHandlers[Instruction::Add],
        {addressContribution,
         {currentAddress, (currentAddress == I.getPointerOperand())}}));
    currentAddress = symbolicComputation.lastInstruction;
  }

  registerSymbolicComputation(symbolicComputation, &I);
}

void Symbolizer::visitBitCastInst(BitCastInst &I) {
  DEBUG(errs() << "[Symbolizer::visitBitCastInst] " << I << '\n');
  if (I.getSrcTy()->isIntegerTy() && I.getDestTy()->isFloatingPointTy()) {
    IRBuilder<> IRB(&I);
    auto conversion =
        buildRuntimeCall(IRB, runtime.buildBitsToFloat,
                         {{I.getOperand(0), true},
                          {IRB.getInt1(I.getDestTy()->isDoubleTy()), false}});
    registerSymbolicComputation(conversion, &I);
    return;
  }

  if (I.getSrcTy()->isFloatingPointTy() && I.getDestTy()->isIntegerTy()) {
    IRBuilder<> IRB(&I);
    auto conversion = buildRuntimeCall(IRB, runtime.buildFloatToBits,
                                       {{I.getOperand(0), true}});
    registerSymbolicComputation(conversion);
    return;
  }

  VectorType *srcVectorTy = dyn_cast<VectorType>(I.getSrcTy());
  VectorType *dstVectorTy = dyn_cast<VectorType>(I.getDestTy());
  if (srcVectorTy && (!dstVectorTy)) {
    bitcastFromVector(&I, srcVectorTy);
    return;
  } else if ((!srcVectorTy) && dstVectorTy) {
    bitcastToVector(&I, dstVectorTy);
    return;
  } else if (srcVectorTy && dstVectorTy) {
    bitcastFromVectorToVector(&I, srcVectorTy, dstVectorTy);
    return;
  }

  assert(I.getSrcTy()->isPointerTy() && I.getDestTy()->isPointerTy() &&
         "Unhandled non-pointer bit cast");
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
}

void Symbolizer::visitTruncInst(TruncInst &I) {
  DEBUG(errs() << "[Symbolizer::visitTruncInst] " << I << '\n');
  IRBuilder<> IRB(&I);

  if (getSymbolicExpression(I.getOperand(0)) == nullptr)
    return;

  SymbolicComputation symbolicComputation;
  symbolicComputation.merge(forceBuildRuntimeCall(
      IRB, runtime.buildTrunc,
      {{I.getOperand(0), true},
       {IRB.getInt8(I.getDestTy()->getIntegerBitWidth()), false}}));

  if (I.getDestTy()->isIntegerTy() &&
      I.getDestTy()->getIntegerBitWidth() == 1) {
    // convert from byte back to a bool (i1)
    symbolicComputation.merge(
        forceBuildRuntimeCall(IRB, runtime.buildBitToBool,
                              {{symbolicComputation.lastInstruction, false}}));
  }

  registerSymbolicComputation(symbolicComputation, &I);
}

void Symbolizer::visitIntToPtrInst(IntToPtrInst &I) {
  DEBUG(errs() << "[Symbolizer::visitIntToPtrInst] " << I << '\n');
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
  // TODO handle truncation and zero extension
}

void Symbolizer::visitPtrToIntInst(PtrToIntInst &I) {
  DEBUG(errs() << "[Symbolizer::visitPtrToIntInst] " << I << '\n');
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
  // TODO handle truncation and zero extension
}

void Symbolizer::visitSIToFPInst(SIToFPInst &I) {
  DEBUG(errs() << "[Symbolizer::visitSIToFPInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildIntToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false},
                        {/* is_signed */ IRB.getInt1(true), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitUIToFPInst(UIToFPInst &I) {
  DEBUG(errs() << "[Symbolizer::visitUIToFPInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildIntToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false},
                        {/* is_signed */ IRB.getInt1(false), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPExtInst(FPExtInst &I) {
  DEBUG(errs() << "[Symbolizer::visitFPExtInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildFloatToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPTruncInst(FPTruncInst &I) {
  DEBUG(errs() << "[Symbolizer::visitFPTruncInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildFloatToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPToSI(FPToSIInst &I) {
  DEBUG(errs() << "[Symbolizer::visitFPToSI] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion = buildRuntimeCall(
      IRB, runtime.buildFloatToSignedInt,
      {{I.getOperand(0), true},
       {IRB.getInt8(I.getType()->getIntegerBitWidth()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPToUI(FPToUIInst &I) {
  DEBUG(errs() << "[Symbolizer::visitFPToUI] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto conversion = buildRuntimeCall(
      IRB, runtime.buildFloatToUnsignedInt,
      {{I.getOperand(0), true},
       {IRB.getInt8(I.getType()->getIntegerBitWidth()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitCastInst(CastInst &I) {
  DEBUG(errs() << "[Symbolizer::visitCastInst] " << I << '\n');
  auto opcode = I.getOpcode();
  if (opcode != Instruction::SExt && opcode != Instruction::ZExt) {
    DEBUG(errs() << "Warning: unhandled cast instruction " << I << '\n');
    return;
  }

  IRBuilder<> IRB(&I);

  SymFnT target;

  switch (I.getOpcode()) {
  case Instruction::SExt:
    target = runtime.buildSExt;
    break;
  case Instruction::ZExt:
    target = runtime.buildZExt;
    break;
  default:
    llvm_unreachable("Unknown cast opcode");
  }

  // LLVM bitcode represents Boolean values as i1. In Z3, those are a not a
  // bit-vector sort, so trying to cast one into a bit vector of any length
  // raises an error. The run-time library provides a dedicated conversion
  // function for this case.
  if (I.getSrcTy()->getIntegerBitWidth() == 1) {

    SymbolicComputation symbolicComputation;
    symbolicComputation.merge(forceBuildRuntimeCall(IRB, runtime.buildBoolToBit,
                                                    {{I.getOperand(0), true}}));
    symbolicComputation.merge(forceBuildRuntimeCall(
        IRB, target,
        {{symbolicComputation.lastInstruction, false},
         {IRB.getInt8(I.getDestTy()->getIntegerBitWidth() - 1), false}}));

    registerSymbolicComputation(symbolicComputation, &I);

  } else {
    auto symbolicCast =
        buildRuntimeCall(IRB, target,
                         {{I.getOperand(0), true},
                          {IRB.getInt8(I.getDestTy()->getIntegerBitWidth() -
                                       I.getSrcTy()->getIntegerBitWidth()),
                           false}});
    registerSymbolicComputation(symbolicCast, &I);
  }
}

void Symbolizer::visitPHINode(PHINode &I) {
  DEBUG(errs() << "[Symbolizer::visitPHINode] " << I << '\n');
  // PHI nodes just assign values based on the origin of the last jump, so we
  // assign the corresponding symbolic expression the same way.

  phiNodes.push_back(&I); // to be finalized later, see finalizePHINodes

  IRBuilder<> IRB(&I);
  unsigned numIncomingValues = I.getNumIncomingValues();
  auto *exprPHI =
      IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), numIncomingValues);
  for (unsigned incoming = 0; incoming < numIncomingValues; incoming++) {
    exprPHI->addIncoming(
        // The null pointer will be replaced in finalizePHINodes.
        ConstantPointerNull::get(
            cast<PointerType>(IRB.getInt8Ty()->getPointerTo())),
        I.getIncomingBlock(incoming));
  }

  symbolicExpressions[&I] = exprPHI;
}

void Symbolizer::visitInsertValueInst(InsertValueInst &I) {
  DEBUG(errs() << "[Symbolizer::visitInsertValueInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto target = I.getAggregateOperand();
  auto insertedValue = I.getInsertedValueOperand();

  if (getSymbolicExpression(target) == nullptr &&
      getSymbolicExpression(insertedValue) == nullptr)
    return;

  // We may have to convert the expression to bit-vector kind...
  auto maybeConversion = convertExprForTypeToBitVectorExpr(
      IRB, insertedValue, getSymbolicExpressionOrNull(insertedValue));

  auto insert = IRB.CreateCall(
      runtime.buildInsert,
      {getSymbolicExpressionOrNull(target),
       // If we had to convert the expression, use the result of the
       // conversion.
       maybeConversion ? maybeConversion->lastInstruction
                       : getSymbolicExpressionOrNull(insertedValue),
       IRB.getInt64(aggregateMemberOffset(target->getType(), I.getIndices())),
       IRB.getInt1(isLittleEndian(insertedValue->getType()) ? 1 : 0)});
  auto insertComputation =
      SymbolicComputation(insert, insert, {Input(target, 0, insert)});

  if (!maybeConversion) {
    // If we didn't have to convert, then the inserted value is first used in
    // the insertion.
    insertComputation.inputs.push_back(Input(insertedValue, 1, insert));
  } else {
    // Otherwise, the full computation consists of the conversion followed by
    // the insertion.
    maybeConversion->merge(insertComputation);
  }

  registerSymbolicComputation(maybeConversion.value_or(insertComputation), &I);
}

void Symbolizer::visitExtractValueInst(ExtractValueInst &I) {
  DEBUG(errs() << "[Symbolizer::visitExtractValueInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto target = I.getAggregateOperand();
  auto targetExpr = getSymbolicExpression(target);
  auto resultType = I.getType();

  if (targetExpr == nullptr)
    return;

  auto extractedBits = IRB.CreateCall(
      runtime.buildExtract,
      {targetExpr,
       IRB.getInt64(aggregateMemberOffset(target->getType(), I.getIndices())),
       IRB.getInt64(dataLayout.getTypeStoreSize(resultType)),
       IRB.getInt1(isLittleEndian(resultType) ? 1 : 0)});

  Instruction *result =
      convertBitVectorExprForType(IRB, extractedBits, resultType);
  registerSymbolicComputation(
      {extractedBits, result, {{target, 0, extractedBits}}}, &I);
}

void Symbolizer::visitSwitchInst(SwitchInst &I) {
  // Switch compares a value against a set of integer constants; duplicate
  // constants are not allowed
  // (https://llvm.org/docs/LangRef.html#switch-instruction).
  IRBuilder<> IRB(&I);
  auto *condition = I.getCondition();
  auto *conditionExpr = getSymbolicExpression(condition);
  if (conditionExpr == nullptr)
    return;

  // Build a check whether we have a symbolic condition, to be used later.
  auto *haveSymbolicCondition = IRB.CreateICmpNE(
      conditionExpr, ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()));
  auto *constraintBlock = SplitBlockAndInsertIfThen(haveSymbolicCondition, &I,
                                                    /* unreachable */ false);

  // In the constraint block, we push one path constraint per case.
  IRB.SetInsertPoint(constraintBlock);
  for (auto &caseHandle : I.cases()) {
    auto *caseTaken = IRB.CreateICmpEQ(condition, caseHandle.getCaseValue());
    auto valueExpr = createValueExpression(caseHandle.getCaseValue(), IRB);
    auto *caseConstraint =
        IRB.CreateCall(runtime.comparisonHandlers[CmpInst::ICMP_EQ],
                       {conditionExpr, valueExpr.value});
    IRB.CreateCall(runtime.pushPathConstraint,
                   {caseConstraint, caseTaken, getLocHash(&I)});
  }
}

void Symbolizer::visitUnreachableInst(UnreachableInst & /*unused*/) {
  // Nothing to do here...
}

void Symbolizer::visitInstruction(Instruction &I) {
  DEBUG(errs() << "[Symbolizer::visitInstruction] " << I << '\n');
  // Some instructions are only used in the context of exception handling,
  // which we ignore for now.
  if (isa<LandingPadInst>(I) || isa<ResumeInst>(I))
    return;

  DEBUG(errs() << "Warning: unknown instruction " << I
               << "; the result will be concretized\n");
}

ValueExpression
Symbolizer::createValueExpressionForStructs(Value *V, StructType *structType,
                                            IRBuilder<> &IRB) {
  // In unoptimized code we may see structures in SSA registers. What we
  // want is a single bit-vector expression describing their contents, but
  // unfortunately we can't take the address of a register. What we do instead
  // is to build the expression recursively by iterating over the elements of
  // the structure.
  //
  // An alternative would be to change the representation of structures in
  // SSA registers to "shadow structures" that contain one expression per
  // member. However, this would put an additional burden on the handling of
  // cast instructions, because expressions would have to be converted
  // between different representations according to the type.

  if (isa<UndefValue>(V)) {
    // This is just an optimization for completely undefined structs; we
    // create an all-zeros expression without iterating over the elements.
    Value *value = IRB.CreateCall(
        runtime.buildZeroBytes,
        {ConstantInt::get(intPtrType,
                          dataLayout.getTypeStoreSize(structType))});
    return ValueExpression(value, IRB.GetInsertBlock());
  } else {
    // Iterate over the elements of the struct and concatenate the
    // corresponding expressions (along with any padding that might be
    // needed).

    auto structLayout = dataLayout.getStructLayout(structType);
    auto constantStructValue = dyn_cast<ConstantStruct>(V);
    size_t offset = 0; // The end of the expressed portion in bytes.
    Value *expr = nullptr;
    auto append = [&](Value *newExpr) {
      expr =
          expr ? IRB.CreateCall(runtime.buildConcat, {expr, newExpr}) : newExpr;
    };

    for (size_t i = 0; i < structType->getNumElements(); i++) {
      // Build an expression for any padding preceding the current element.
      if (auto padding = structLayout->getElementOffset(i) - offset;
          padding > 0) {
        append(IRB.CreateCall(runtime.buildZeroBytes,
                              {ConstantInt::get(intPtrType, padding)}));
      }

      // Build the expression for the current element. If the struct is not a
      // constant, we need to read the element with extractvalue.
      auto element = constantStructValue
                         ? constantStructValue->getAggregateElement(i)
                         : IRB.CreateExtractValue(V, i);
      auto valueExpr = createValueExpression(element, IRB);
      auto elementExpr = valueExpr.value;

      // The expression may be of a different kind than bit vector; in this
      // case, we need to convert it.
      if (auto conversion =
              convertExprForTypeToBitVectorExpr(IRB, element, elementExpr)) {
        elementExpr = conversion->lastInstruction;
      }

      // If the element is represented in little-endian byte order in memory,
      // swap the bytes.
      auto elementType = structType->getElementType(i);
      if (isLittleEndian(elementType) &&
          dataLayout.getTypeStoreSize(elementType) > 1) {
        elementExpr = IRB.CreateCall(runtime.buildBswap, {elementExpr});
      }

      append(elementExpr);

      offset = structLayout->getElementOffset(i) +
               dataLayout.getTypeStoreSize(structType->getElementType(i));
    }

    // Insert padding at the end, if any.
    if (auto finalPadding = dataLayout.getTypeStoreSize(structType) - offset;
        finalPadding > 0) {
      append(IRB.CreateCall(runtime.buildZeroBytes,
                            {ConstantInt::get(intPtrType, finalPadding)}));
    }

    return ValueExpression(expr, IRB.GetInsertBlock());
  }
}

ValueExpression Symbolizer::createValueExpressionForArrays(Value *V,
                                                           ArrayType *arrayType,
                                                           IRBuilder<> &IRB) {
  // Arrays are handled like structures, but we don't need to worry about
  // padding.
  auto *elementType = arrayType->getElementType();
  auto *constantArrayValue = dyn_cast<ConstantArray>(V);
  size_t numElements = arrayType->getNumElements();
  Value *expr = nullptr;
  auto append = [&](Value *newExpr) {
    expr =
        expr ? IRB.CreateCall(runtime.buildConcat, {expr, newExpr}) : newExpr;
  };

  for (size_t i = 0; i < numElements; i++) {
    auto element = constantArrayValue
                       ? constantArrayValue->getAggregateElement(i)
                       : IRB.CreateExtractValue(V, i);
    auto valueExpr = createValueExpression(element, IRB);
    auto elementExpr = valueExpr.value;

    if (auto conversion =
            convertExprForTypeToBitVectorExpr(IRB, element, elementExpr)) {
      elementExpr = conversion->lastInstruction;
    }

    if (isLittleEndian(elementType) &&
        dataLayout.getTypeStoreSize(elementType) > 1) {
      elementExpr = IRB.CreateCall(runtime.buildBswap, {elementExpr});
    }

    append(elementExpr);
  }
  return ValueExpression(expr, IRB.GetInsertBlock());
}

ValueExpression Symbolizer::createValueExpression(Value *V, IRBuilder<> &IRB) {
  auto *valueType = V->getType();

  if (isa<ConstantPointerNull>(V)) {
    Value *value = IRB.CreateCall(runtime.buildNullPointer, {});
    return ValueExpression(value, IRB.GetInsertBlock());
  }

  if (valueType->isIntegerTy()) {
    auto bits = valueType->getPrimitiveSizeInBits();
    if (bits == 1) {
      // Special case: LLVM uses the type i1 to represent Boolean values, but
      // for Z3 we have to create expressions of a separate sort.
      Value *value = IRB.CreateCall(runtime.buildBool, {V});
      return ValueExpression(value, IRB.GetInsertBlock());
    } else if (bits <= 64) {
      Value *value =
          IRB.CreateCall(runtime.buildInteger,
                         {IRB.CreateZExtOrBitCast(V, IRB.getInt64Ty()),
                          IRB.getInt8(valueType->getPrimitiveSizeInBits())});
      return ValueExpression(value, IRB.GetInsertBlock());
    } else {
      // Anything up to the maximum supported 128 bits. Those integers are a
      // bit tricky because the symbolic backends don't support them per se.
      // We have a special function in the run-time library that handles them,
      // usually by assembling expressions from smaller chunks.
      Value *value = IRB.CreateCall(
          runtime.buildInteger128,
          {IRB.CreateTrunc(IRB.CreateLShr(V, ConstantInt::get(valueType, 64)),
                           IRB.getInt64Ty()),
           IRB.CreateTrunc(V, IRB.getInt64Ty()), IRB.getInt8(bits)});
      return ValueExpression(value, IRB.GetInsertBlock());
    }
  }

  if (valueType->isFloatingPointTy()) {
    Value *value = IRB.CreateCall(runtime.buildFloat,
                                  {IRB.CreateFPCast(V, IRB.getDoubleTy()),
                                   IRB.getInt1(valueType->isDoubleTy())});
    return ValueExpression(value, IRB.GetInsertBlock());
  }

  if (valueType->isPointerTy()) {
    Value *value = IRB.CreateCall(
        runtime.buildInteger,
        {IRB.CreatePtrToInt(V, IRB.getInt64Ty()), IRB.getInt8(ptrBits)});
    return ValueExpression(value, IRB.GetInsertBlock());
  }

  if (auto structType = dyn_cast<StructType>(valueType)) {
    return createValueExpressionForStructs(V, structType, IRB);
  }
  if (auto *arrayType = dyn_cast<ArrayType>(valueType)) {
    return createValueExpressionForArrays(V, arrayType, IRB);
  }
  if (auto *vectorType = dyn_cast<VectorType>(valueType)) {
    return createValueExpressionForVectors(V, vectorType, IRB);
  }
  llvm_unreachable("Unhandled type for constant expression");
}

Symbolizer::SymbolicComputation Symbolizer::forceBuildRuntimeCall(
    IRBuilder<> &IRB, SymFnT function,
    ArrayRef<std::pair<Value *, bool>> args) const {
  std::vector<Value *> functionArgs;
  for (const auto &[arg, symbolic] : args) {
    functionArgs.push_back(symbolic ? getSymbolicExpressionOrNull(arg) : arg);
  }
  auto *call = IRB.CreateCall(function, functionArgs);

  std::vector<Input> inputs;
  for (unsigned i = 0; i < args.size(); i++) {
    const auto &[arg, symbolic] = args[i];
    if (symbolic)
      inputs.push_back(Input(arg, i, call));
  }

  return SymbolicComputation(call, call, inputs);
}

#ifdef ENABLE_TRY_ALTERNATIVE
void Symbolizer::tryAlternative(IRBuilder<> &IRB, Value *V) {
  auto *destExpr = getSymbolicExpression(V);
  if (destExpr != nullptr) {
    auto *concreteDestExpr = createValueExpression(V, IRB);
    auto *destAssertion =
        IRB.CreateCall(runtime.comparisonHandlers[CmpInst::ICMP_EQ],
                       {destExpr, concreteDestExpr});
    auto *pushAssertion = IRB.CreateCall(
        runtime.pushPathConstraint,
        {destAssertion, IRB.getInt1(true), getTargetPreferredInt(V)});
    registerSymbolicComputation(SymbolicComputation(
        concreteDestExpr, pushAssertion, {Input(V, 0, destAssertion)}));
  }
}
#endif

uint64_t Symbolizer::aggregateMemberOffset(Type *aggregateType,
                                           ArrayRef<unsigned> indices) const {
  uint64_t offset = 0;
  auto *indexedType = aggregateType;
  for (auto index : indices) {
    // All indices in an extractvalue instruction are constant:
    // https://llvm.org/docs/LangRef.html#extractvalue-instruction

    if (auto *structType = dyn_cast<StructType>(indexedType)) {
      offset += dataLayout.getStructLayout(structType)->getElementOffset(index);
      indexedType = structType->getElementType(index);
    } else {
      auto *arrayType = cast<ArrayType>(indexedType);
      unsigned elementSize =
          dataLayout.getTypeAllocSize(arrayType->getArrayElementType());
      offset += elementSize * index;
      indexedType = arrayType->getArrayElementType();
    }
  }

  return offset;
}

Instruction *Symbolizer::convertBitVectorExprForType(llvm::IRBuilder<> &IRB,
                                                     Instruction *I,
                                                     Type *T) const {
  Instruction *result = I;

  if (T->isFloatingPointTy()) {
    result = IRB.CreateCall(runtime.buildBitsToFloat,
                            {I, IRB.getInt1(T->isDoubleTy())});
  } else if (T->isIntegerTy() && T->getIntegerBitWidth() == 1) {
    result = IRB.CreateCall(runtime.buildTrunc,
                            {I, ConstantInt::get(IRB.getInt8Ty(), 1)});
    result = IRB.CreateCall(runtime.buildBitToBool, {result});
  }

  return result;
}

std::optional<Symbolizer::SymbolicComputation>
Symbolizer::convertExprForTypeToBitVectorExpr(IRBuilder<> &IRB, Value *V,
                                              Value *Expr) const {
  if (Expr == nullptr)
    return {};

  auto T = V->getType();

  if (T->isFloatingPointTy()) {
    auto floatBits = IRB.CreateCall(runtime.buildFloatToBits, {Expr});
    return SymbolicComputation(floatBits, floatBits, {Input(V, 0, floatBits)});
  } else if (T->isIntegerTy() && T->getIntegerBitWidth() == 1) {
    auto bitExpr = IRB.CreateCall(runtime.buildBoolToBit, {Expr});
    auto bitVectorExpr = IRB.CreateCall(runtime.buildZExt,
                                        {bitExpr, IRB.getInt8(7 /* 1 byte */)});
    return SymbolicComputation(bitExpr, bitVectorExpr, {Input(V, 0, bitExpr)});
  } else {
    return {};
  }
}

namespace hashing {

/// FNV-1a 64-bit hash
inline uint64_t hash_bytes(const void *data, size_t len) {
  const uint8_t *bytes = static_cast<const uint8_t *>(data);
  uint64_t hash = 0xcbf29ce484222325ULL;

  for (size_t i = 0; i < len; ++i) {
    hash ^= bytes[i];
    hash *= 0x100000001b3ULL;
  }

  return hash;
}

/// Boost-style hash_combine
inline uint64_t hash_combine(uint64_t a, uint64_t b) {
  return a ^ (b + 0x9e3779b97f4a7c15ULL + (a << 6) + (a >> 2));
}

/// Final pcId computation with sequential hash_combine
inline uint64_t compute_pc_id(llvm::StringRef dir, llvm::StringRef src,
                              uint64_t line, uint64_t col) {
  uint64_t h_dir = ::hashing::hash_bytes(dir.data(), dir.size());
  uint64_t h_src = ::hashing::hash_bytes(src.data(), src.size());
  uint64_t h_line = ::hashing::hash_bytes(&line, sizeof(line));
  uint64_t h_col = ::hashing::hash_bytes(&col, sizeof(col));

  uint64_t pcId = h_dir;
  pcId = ::hashing::hash_combine(pcId, h_src);
  pcId = ::hashing::hash_combine(pcId, h_line);
  pcId = ::hashing::hash_combine(pcId, h_col);

  pcId = (pcId & 0xFFFFFFFFULL) | (1ULL << 63);
  return pcId;
}
} // namespace hashing
  //
llvm::ConstantInt *Symbolizer::getLocHash(llvm::Instruction *I) {
  if (I == nullptr) {
    // print error
    llvm::errs() << "Error: getLocHash called with nullptr\n";
    std::abort();
  }
  if (auto L = I->getDebugLoc()) {
    llvm::StringRef dir = L->getDirectory();
    llvm::StringRef src = L->getFilename();
    uint64_t pcId =
        ::hashing::compute_pc_id(dir, src, L->getLine(), L->getColumn());
    return llvm::ConstantInt::get(llvm::Type::getInt64Ty(I->getContext()),
                                  pcId);
  } else {
    // TODO: should we rasie an exception?
    // open /out/symcc.err file and write the error message
    return getTargetPreferredInt(I);
  }
}
