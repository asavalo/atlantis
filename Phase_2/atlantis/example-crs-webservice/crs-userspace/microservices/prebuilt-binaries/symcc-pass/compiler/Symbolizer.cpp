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

#include <cstdint>
#include <llvm/ADT/SmallPtrSet.h>
#include <llvm/IR/Constants.h>
#include <llvm/IR/GetElementPtrTypeIterator.h>
#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/Transforms/Utils/BasicBlockUtils.h>

#include "Runtime.h"
#include <fstream>
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
  IRBuilder<> IRB(&*B.getFirstInsertionPt());
  IRB.CreateCall(runtime.notifyBasicBlock, getTargetPreferredInt(&B));
}

void Symbolizer::insertFunctionNotification(llvm::Function &F) {
  IRBuilder<> IRB(&*F.getEntryBlock().getFirstInsertionPt());
  IRB.CreateCall(runtime.notifyFunction, getTargetPreferredInt(&F));
}

void Symbolizer::finalizePHINodes() {
  SmallPtrSet<PHINode *, 32> nodesToErase;

  for (auto *phi : phiNodes) {
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

void Symbolizer::shortCircuitExpressionUses() {
  for (auto &symbolicComputation : expressionUses) {
    assert(!symbolicComputation.inputs.empty() &&
           "Symbolic computation has no inputs");

    IRBuilder<> IRB(symbolicComputation.firstInstruction);

    // Build the check whether any input expression is non-null (i.e., there
    // is a symbolic input).
    auto *nullExpression =
        ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo());
    std::vector<Value *> nullChecks;
    for (const auto &input : symbolicComputation.inputs) {
      nullChecks.push_back(
          IRB.CreateICmpEQ(nullExpression, input.getSymbolicOperand()));
    }
    auto *allConcrete = nullChecks[0];
    for (unsigned argIndex = 1; argIndex < nullChecks.size(); argIndex++) {
      allConcrete = IRB.CreateAnd(allConcrete, nullChecks[argIndex]);
    }

    // The main branch: if we don't enter here, we can short-circuit the
    // symbolic computation. Otherwise, we need to check all input expressions
    // and create an output expression.
    auto *head = symbolicComputation.firstInstruction->getParent();
    auto *slowPath = SplitBlock(head, symbolicComputation.firstInstruction);
    auto *tail = SplitBlock(slowPath,
                            symbolicComputation.lastInstruction->getNextNode());
    ReplaceInstWithInst(head->getTerminator(),
                        BranchInst::Create(tail, slowPath, allConcrete));

    // In the slow case, we need to check each input expression for null
    // (i.e., the input is concrete) and create an expression from the
    // concrete value if necessary.
    auto numUnknownConcreteness = std::count_if(
        symbolicComputation.inputs.begin(), symbolicComputation.inputs.end(),
        [&](const Input &input) {
          return (input.getSymbolicOperand() != nullExpression);
        });
    for (unsigned argIndex = 0; argIndex < symbolicComputation.inputs.size();
         argIndex++) {
      auto &argument = symbolicComputation.inputs[argIndex];
      auto *originalArgExpression = argument.getSymbolicOperand();
      auto *argCheckBlock = symbolicComputation.firstInstruction->getParent();

      // We only need a run-time check for concreteness if the argument isn't
      // known to be concrete at compile time already. However, there is one
      // exception: if the computation only has a single argument of unknown
      // concreteness, then we know that it must be symbolic since we ended up
      // in the slow path. Therefore, we can skip expression generation in
      // that case.
      bool needRuntimeCheck = originalArgExpression != nullExpression;
      if (needRuntimeCheck && (numUnknownConcreteness == 1))
        continue;

      if (needRuntimeCheck) {
        auto *argExpressionBlock = SplitBlockAndInsertIfThen(
            nullChecks[argIndex], symbolicComputation.firstInstruction,
            /* unreachable */ false);
        IRB.SetInsertPoint(argExpressionBlock);
      } else {
        IRB.SetInsertPoint(symbolicComputation.firstInstruction);
      }

      auto *newArgExpression =
          createValueExpression(argument.concreteValue, IRB);

      Value *finalArgExpression;
      if (needRuntimeCheck) {
        IRB.SetInsertPoint(symbolicComputation.firstInstruction);
        auto *argPHI = IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), 2);
        argPHI->addIncoming(originalArgExpression, argCheckBlock);
        argPHI->addIncoming(newArgExpression, newArgExpression->getParent());
        finalArgExpression = argPHI;
      } else {
        finalArgExpression = newArgExpression;
      }

      argument.replaceOperand(finalArgExpression);
    }

    // Finally, the overall result (if the computation produces one) is null
    // if we've taken the fast path and the symbolic expression computed above
    // if short-circuiting wasn't possible.
    if (!symbolicComputation.lastInstruction->use_empty()) {
      IRB.SetInsertPoint(&tail->front());
      auto *finalExpression = IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), 2);
      symbolicComputation.lastInstruction->replaceAllUsesWith(finalExpression);
      finalExpression->addIncoming(
          ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()), head);
      finalExpression->addIncoming(
          symbolicComputation.lastInstruction,
          symbolicComputation.lastInstruction->getParent());
    }
  }
}

void Symbolizer::handleIntrinsicCall(CallBase &I) {
  auto *callee = I.getCalledFunction();

  switch (callee->getIntrinsicID()) {
  case Intrinsic::dbg_value:
  case Intrinsic::is_constant:
  case Intrinsic::trap:
    // These are safe to ignore.
    break;
  case Intrinsic::memcpy: {
    IRBuilder<> IRB(&I);

    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(1));
    tryAlternative(IRB, I.getOperand(2));

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

    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(2));

    // The comment on memcpy's length parameter applies analogously.

    IRB.CreateCall(runtime.memset,
                   {I.getOperand(0),
                    getSymbolicExpressionOrNull(I.getOperand(1)),
                    IRB.CreateZExtOrTrunc(I.getOperand(2), intPtrType)});
    break;
  }
  case Intrinsic::memmove: {
    IRBuilder<> IRB(&I);

    tryAlternative(IRB, I.getOperand(0));
    tryAlternative(IRB, I.getOperand(1));
    tryAlternative(IRB, I.getOperand(2));

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
    DEBUG(errs() << "Warning: unhandled LLVM intrinsic " << callee->getName()
                 << "; the result will be concretized\n");
    break;
  }
}

void Symbolizer::handleInlineAssembly(CallInst &I) {
  if (I.getType()->isVoidTy()) {
    DEBUG(errs() << "Warning: skipping over inline assembly " << I << '\n');
    return;
  }

  DEBUG(errs()
        << "Warning: losing track of symbolic expressions at inline assembly "
        << I << '\n');
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

  if (callee == nullptr)
    tryAlternative(IRB, I.getCalledOperand());

  for (Use &arg : I.args())
    IRB.CreateCall(runtime.setParameterExpression,
                   {ConstantInt::get(IRB.getInt8Ty(), arg.getOperandNo()),
                    getSymbolicExpressionOrNull(arg)});

  if (!I.user_empty()) {
    // The result of the function is used somewhere later on. Since we have no
    // way of knowing whether the function is instrumented (and thus sets a
    // proper return expression), we have to account for the possibility that
    // it's not: in that case, we'll have to treat the result as an opaque
    // concrete value. Therefore, we set the return expression to null here in
    // order to avoid accidentally using whatever is stored there from the
    // previous function call. (If the function is instrumented, it will just
    // override our null with the real expression.)
    IRB.CreateCall(runtime.setReturnExpression,
                   ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()));
    IRB.SetInsertPoint(returnPoint);
    symbolicExpressions[&I] = IRB.CreateCall(runtime.getReturnExpression);
  }
}

void Symbolizer::visitBinaryOperator(BinaryOperator &I) {
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
  IRBuilder<> IRB(&I);
  SymFnT handler = runtime.unaryOperatorHandlers.at(I.getOpcode());

  assert(handler && "Unable to handle unary operator");
  auto runtimeCall = buildRuntimeCall(IRB, handler, I.getOperand(0));
  registerSymbolicComputation(runtimeCall, &I);
}

void Symbolizer::visitSelectInst(SelectInst &I) {
  // Select is like the ternary operator ("?:") in C. We push the (potentially
  // negated) condition to the path constraints and copy the symbolic
  // expression over from the chosen argument.

  IRBuilder<> IRB(&I);
  auto runtimeCall = buildRuntimeCall(IRB, runtime.pushPathConstraint,
                                      {{I.getCondition(), true},
                                       {I.getCondition(), false},
                                       {getTargetPreferredInt(&I), false}});
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
  // Br can jump conditionally or unconditionally. We are only interested in
  // the former case, in which we push the branch condition or its negation to
  // the path constraints.

  if (I.isUnconditional())
    return;

  IRBuilder<> IRB(&I);
  auto runtimeCall =
      buildRuntimeCall(IRB, runtime.pushPathConstraint,
                       {{I.getCondition(), true},
                        {I.getCondition(), false},
                        // ASSUME: only two successors, and sucessor of index 0
                        // is the taken block
                        {getTargetPreferredInt(I.getSuccessor((0))), false}});
  registerSymbolicComputation(runtimeCall);
}

void Symbolizer::visitIndirectBrInst(IndirectBrInst &I) {
  IRBuilder<> IRB(&I);
  tryAlternative(IRB, I.getAddress());
}

void Symbolizer::visitCallInst(CallInst &I) {
  if (I.isInlineAsm())
    handleInlineAssembly(I);
  else
    handleFunctionCall(I, I.getNextNode());
}

void Symbolizer::visitInvokeInst(InvokeInst &I) {
  // Invoke is like a call but additionally establishes an exception handler. We
  // can obtain the return expression only in the success case, but the target
  // block may have multiple incoming edges (i.e., our edge may be critical). In
  // this case, we split the edge and query the return expression in the new
  // block that is specific to our edge.
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
  IRBuilder<> IRB(&I);

  auto *addr = I.getPointerOperand();

#ifdef SYMCC_VERBOSE
  if (isLlvmProfileCounter(&I, addr).first) {
    // LLVM profile counters are not symbolic; they are concrete values.
    return;
  }
#endif
  tryAlternative(IRB, addr);

  auto *dataType = I.getType();
  auto *data = IRB.CreateCall(
      runtime.readMemory,
      {IRB.CreatePtrToInt(addr, intPtrType),
       ConstantInt::get(intPtrType, dataLayout.getTypeStoreSize(dataType)),
       IRB.getInt1(isLittleEndian(dataType) ? 1 : 0)});

  symbolicExpressions[&I] = convertBitVectorExprForType(IRB, data, dataType);
}

void Symbolizer::visitStoreInst(StoreInst &I) {
  IRBuilder<> IRB(&I);

  auto *addr = I.getPointerOperand();
#ifdef SYMCC_VERBOSE
  if (isLlvmProfileCounter(&I, addr).first) {
    // LLVM profile counters are not symbolic; they are concrete values.
    return;
  }
#endif
  tryAlternative(IRB, I.getPointerOperand());

  // Make sure that the expression corresponding to the stored value is of
  // bit-vector kind. Shortcutting the runtime calls that we emit here (e.g.,
  // for floating-point values) is tricky, so instead we make sure that any
  // runtime function we call can handle null expressions.

  auto V = I.getValueOperand();
  auto maybeConversion =
      convertExprForTypeToBitVectorExpr(IRB, V, getSymbolicExpression(V));

  IRB.CreateCall(
      runtime.writeMemory,
      {IRB.CreatePtrToInt(I.getPointerOperand(), intPtrType),
       ConstantInt::get(intPtrType, dataLayout.getTypeStoreSize(V->getType())),
       maybeConversion ? maybeConversion->lastInstruction
                       : getSymbolicExpressionOrNull(V),
       IRB.getInt1(isLittleEndian(V->getType()) ? 1 : 0)});
}

void Symbolizer::visitGetElementPtrInst(GetElementPtrInst &I) {
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

  assert(I.getSrcTy()->isPointerTy() && I.getDestTy()->isPointerTy() &&
         "Unhandled non-pointer bit cast");
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
}

void Symbolizer::visitTruncInst(TruncInst &I) {
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
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
  // TODO handle truncation and zero extension
}

void Symbolizer::visitPtrToIntInst(PtrToIntInst &I) {
  if (auto *expr = getSymbolicExpression(I.getOperand(0)))
    symbolicExpressions[&I] = expr;
  // TODO handle truncation and zero extension
}

void Symbolizer::visitSIToFPInst(SIToFPInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildIntToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false},
                        {/* is_signed */ IRB.getInt1(true), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitUIToFPInst(UIToFPInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildIntToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false},
                        {/* is_signed */ IRB.getInt1(false), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPExtInst(FPExtInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildFloatToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPTruncInst(FPTruncInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion =
      buildRuntimeCall(IRB, runtime.buildFloatToFloat,
                       {{I.getOperand(0), true},
                        {IRB.getInt1(I.getDestTy()->isDoubleTy()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPToSI(FPToSIInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion = buildRuntimeCall(
      IRB, runtime.buildFloatToSignedInt,
      {{I.getOperand(0), true},
       {IRB.getInt8(I.getType()->getIntegerBitWidth()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitFPToUI(FPToUIInst &I) {
  IRBuilder<> IRB(&I);
  auto conversion = buildRuntimeCall(
      IRB, runtime.buildFloatToUnsignedInt,
      {{I.getOperand(0), true},
       {IRB.getInt8(I.getType()->getIntegerBitWidth()), false}});
  registerSymbolicComputation(conversion, &I);
}

void Symbolizer::visitCastInst(CastInst &I) {
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
       // If we had to convert the expression, use the result of the conversion.
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
  auto *switchHeadBlock = I.getParent();
  auto *condition = I.getCondition();
  auto *conditionExpr = getSymbolicExpression(condition);
  if (conditionExpr == nullptr)
    return;

  /// Build x || y || z in the head
  Value *conditionAllInclusive = nullptr;
  assert(I.getNumCases() > 0);
  for (auto &caseHandle : I.cases()) {
    auto *thisEq = IRB.CreateCall(
        runtime.comparisonHandlers[CmpInst::ICMP_EQ],
        {conditionExpr, createValueExpression(caseHandle.getCaseValue(), IRB)});

    if (conditionAllInclusive == nullptr) {
      conditionAllInclusive = thisEq;
    } else {
      conditionAllInclusive =
          IRB.CreateCall(runtime.buildBoolOr, {conditionAllInclusive, thisEq});
    }
  }
  assert(conditionAllInclusive != nullptr);
  IRB.CreateCall(
      runtime.pushPathConstraint,
      {conditionAllInclusive, IRB.getTrue(), getTargetPreferredInt(&I)});

  // Build a check whether we have a symbolic condition, to be used later.

  // For each case x, push the conditions a != y, a != z, ..
  // These conditions must be pushend individually and not colelctively
  // (aggregated via &&) because the inversion of each condition would result in
  // N -1 different new inputs
  // TODO: Handle the default case
  for (auto &caseHandle : I.cases()) {
    // Create basic blocks for each case
    //
    //     |----A1' --- A1
    // X -------A2' --- A2
    //     |----A3' --- | --- A3
    //
    // We need these blocks due to the case outlined above (when a basic block
    // of one case is the optimized to be the merge block
    //
    BasicBlock *caseBlock = caseHandle.getCaseSuccessor();
    BasicBlock *caseBlockParent =
        BasicBlock::Create(I.getContext(), caseBlock->getName() + "_parent",
                           I.getParent()->getParent(), caseBlock);
    // to account for the case above, we need to check if caseBlock has any
    // predecessors other than the block containing the switch instruction

    /* WARNING: Don't use replaceAllUsesWith here, because it will also change
     * the phinode incoming block numbers Assuming we don
     * caseBlock->replaceAllUsesWith(caseBlockParent) here, any phinodes with
     * the incoming block as caseBlock will be changed to caseBlockParent.
     *
     *  A ----> CB ----> X [ phi(0, CB) ]
     *
     *  After replaceAllUsesWith
     *
     *  A ----> CBP ----> CB ----> X [ phi(0, CBP) ]
     *
     *  The phinode in X is incorrect. Its incoming block is not its predecssor.
     *  This materializes as a segfault when calling
     * PHINode.getIncomingValueForBlock. We only need to change I's successor to
     * caseBlockParent and nothing else There are two things in 'else':
     *  1. The phinode incoming block labels (which we discussed above)
     *  2. Other preecessors' branch labels to caseBlock
     *
     *  S ----> CB -----> ....
     *           \
     *  B -------
     *
     *  Assuming S is the switch instruction, modifying the branch label of B to
     * CBP is not incorrect, but it contradicts with our intention to create an
     * intermediate basic block that is only executed within the switch
     * statement
     */
    bool success = false;
    for (uint i = 0; i < I.getNumSuccessors(); i++) {
      if (I.getSuccessor(i) == caseBlock) {
        I.setSuccessor(i, caseBlockParent);
        success = true;
      }
    }
    assert(success);

    IRB.SetInsertPoint(caseBlockParent);
    auto *haveSymbolicCondition = IRB.CreateICmpNE(
        conditionExpr,
        ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()));
    auto *brInstruction = IRB.CreateBr(caseBlock);
    auto *symbolizableCaseBlock =
        SplitBlockAndInsertIfThen(haveSymbolicCondition, &*brInstruction,
                                  /* unreachable */ false);

    // assert assumptions
    assert(symbolizableCaseBlock->getNumSuccessors() == 1);
    auto *caseBlockParentPart2 = symbolizableCaseBlock->getSuccessor(0);

    /*
     * switch(A1,A2,..) ----> CBP(1)--------------> CBP(2) ----> CB [ phi ]
     *                              \                \           \
     *                              \---> SCB -------\       Y---\
     *                                                           X
     *
     *	 CBP(2) is the second half of the block created by
     *   SplitBlockAndInsertIfThen However, now there is no edge switch -> CB,
     *  invalidating the phinode in CB. Fix this!
     */

    // Fix the phi nodes in the case blocks
    for (auto &I : *caseBlock) {
      if (auto *phi = dyn_cast<PHINode>(&I)) {
        for (int i = 0; i < phi->getNumIncomingValues(); i++) {
          if (phi->getIncomingBlock(i) == switchHeadBlock) {
            phi->setIncomingBlock(i, caseBlockParentPart2);
          }
        }
      }
    }

    IRB.SetInsertPoint(symbolizableCaseBlock);
    // It's N^2 but who cares
    for (auto &caseHandleOther : I.cases()) {
      if (caseHandle.getCaseValue() == caseHandleOther.getCaseValue())
        continue;
      auto *caseConstraint = IRB.CreateCall(
          runtime.comparisonHandlers[CmpInst::ICMP_NE],
          {conditionExpr,
           createValueExpression(caseHandleOther.getCaseValue(), IRB)});
      IRB.CreateCall(runtime.pushPathConstraint,
                     {caseConstraint, IRB.getTrue(),
                      getTargetPreferredInt(caseHandle.getCaseSuccessor())});
    }
    // For now let's not think about the default case, it makes my head hurt....
  }
}

void Symbolizer::visitUnreachableInst(UnreachableInst & /*unused*/) {
  // Nothing to do here...
}

void Symbolizer::visitInstruction(Instruction &I) {
  // Some instructions are only used in the context of exception handling, which
  // we ignore for now.
  if (isa<LandingPadInst>(I) || isa<ResumeInst>(I))
    return;

  DEBUG(errs() << "Warning: unknown instruction " << I
               << "; the result will be concretized\n");
}

Instruction *Symbolizer::createValueExpression(Value *V, IRBuilder<> &IRB) {
  auto *valueType = V->getType();

  if (isa<ConstantPointerNull>(V)) {
    return IRB.CreateCall(runtime.buildNullPointer, {});
  }

  if (valueType->isIntegerTy()) {
    auto bits = valueType->getPrimitiveSizeInBits();
    if (bits == 1) {
      // Special case: LLVM uses the type i1 to represent Boolean values, but
      // for Z3 we have to create expressions of a separate sort.
      return IRB.CreateCall(runtime.buildBool, {V});
    } else if (bits <= 64) {
      return IRB.CreateCall(runtime.buildInteger,
                            {IRB.CreateZExtOrBitCast(V, IRB.getInt64Ty()),
                             IRB.getInt8(valueType->getPrimitiveSizeInBits())});
    } else {
      // Anything up to the maximum supported 128 bits. Those integers are a bit
      // tricky because the symbolic backends don't support them per se. We have
      // a special function in the run-time library that handles them, usually
      // by assembling expressions from smaller chunks.
      return IRB.CreateCall(
          runtime.buildInteger128,
          {IRB.CreateTrunc(IRB.CreateLShr(V, ConstantInt::get(valueType, 64)),
                           IRB.getInt64Ty()),
           IRB.CreateTrunc(V, IRB.getInt64Ty())});
    }
  }

  if (valueType->isFloatingPointTy()) {
    return IRB.CreateCall(runtime.buildFloat,
                          {IRB.CreateFPCast(V, IRB.getDoubleTy()),
                           IRB.getInt1(valueType->isDoubleTy())});
  }

  if (valueType->isPointerTy()) {
    return IRB.CreateCall(
        runtime.buildInteger,
        {IRB.CreatePtrToInt(V, IRB.getInt64Ty()), IRB.getInt8(ptrBits)});
  }

  if (auto structType = dyn_cast<StructType>(valueType)) {
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
      return IRB.CreateCall(
          runtime.buildZeroBytes,
          {ConstantInt::get(intPtrType,
                            dataLayout.getTypeStoreSize(valueType))});
    } else {
      // Iterate over the elements of the struct and concatenate the
      // corresponding expressions (along with any padding that might be
      // needed).

      auto structLayout = dataLayout.getStructLayout(structType);
      auto constantStructValue = dyn_cast<ConstantStruct>(V);
      size_t offset = 0; // The end of the expressed portion in bytes.
      Instruction *expr = nullptr;
      auto append = [&](Instruction *newExpr) {
        expr = expr ? IRB.CreateCall(runtime.buildConcat, {expr, newExpr})
                    : newExpr;
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
        auto elementExpr = createValueExpression(element, IRB);

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

      return expr;
    }
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

#ifdef SYMCC_VERBOSE
std::pair<bool, uint64_t> Symbolizer::isLlvmProfileCounter(Instruction *I,
                                                           Value *V) {
  std::string counterPrefix = "__profc_";
  uint64_t offset = 0;
  if (auto *GV = dyn_cast<GlobalVariable>(V)) {
    if (GV->getName().starts_with(counterPrefix)) {
      return std::make_pair(true, 0);
    }
    // we only care about constant GEPs because profile counters are accesssed
    // with constant indices, resulting in them to be constant GEPs instead of
    // instructions
  } else if (auto *CE = dyn_cast<ConstantExpr>(V)) {
    if (CE->getOpcode() == Instruction::GetElementPtr) {
      if (auto *GV = dyn_cast<GlobalVariable>(CE->getOperand(0))) {
        if (GV->getName().starts_with(counterPrefix)) {
          if (CE->getNumOperands() != 3) {
            DEBUG(errs() << "Error: profile counter utilizes getelementptr "
                            "with more than 3 operands "
                         << *I << '\n');
            return std::make_pair(false, 0);
          } else {
            auto *CI = dyn_cast<ConstantInt>(CE->getOperand(2));
            offset = CI->getZExtValue();
            return std::make_pair(true, offset);
          }
        }
      }
    }
  }
  return std::make_pair(false, 0);
}

std::pair<bool, uint64_t>
Symbolizer::findProfileCounterInBlock(BasicBlock &BB) {
  for (auto &I : BB) {
    if (auto *loadInst = dyn_cast<LoadInst>(&I)) {
      if (auto [isProfileCounter, offset] =
              isLlvmProfileCounter(loadInst, loadInst->getPointerOperand());
          isProfileCounter) {
        return std::make_pair(true, offset);
      }
    }
  }
  return std::make_pair(false, 0);
}

bool Symbolizer::resolveCounterOffsetForBranch(
    Value *condition, uint64_t siteId,
    std::map<uint64_t, std::pair<uint64_t, bool>> &symccIdToProfileCounterMap) {
  for (auto *U : condition->users()) {
    if (auto *branchInst = dyn_cast<BranchInst>(U)) {
      // search each of the branch destinations
      // assume there are exactly two destinations
      uint64_t profcOffset = 0;
      bool success = false;
      bool in_taken = false;
      auto [isProfileCounter, offset] =
          findProfileCounterInBlock(*branchInst->getSuccessor(0));
      if (isProfileCounter) {
        profcOffset = offset;
        success = true;
        in_taken = true;
      } else {
        auto [isProfileCounter, offset] =
            findProfileCounterInBlock(*branchInst->getSuccessor(1));
        if (isProfileCounter) {
          profcOffset = offset;
          success = true;
          in_taken = false;
        } else {
          // no profile counter found in either branch
          // unreachable, but for now we just warn and return
          DEBUG(errs() << "Error: no profile counter found in either branch of "
                          "branch instruction "
                       << *branchInst << '\n');
        }
      }
      if (success) {
        symccIdToProfileCounterMap[siteId] =
            std::make_pair(profcOffset, in_taken);
        return true;
      }
    }
  }
  return false;
}

bool Symbolizer::resolveCounterOffsetForSwitch(
    Value *condition, uint64_t siteId,
    std::map<uint64_t, std::pair<uint64_t, bool>> &symccIdToProfileCounterMap) {

  // check if condition is EQ X, constant
  if (auto *AI = dyn_cast<ICmpInst>(condition)) {
    if (auto *CV = dyn_cast<ConstantInt>(AI->getOperand(1))) {
      auto *X = AI->getOperand(0);
      for (auto *U : X->users()) {
        if (auto *switchInst = dyn_cast<SwitchInst>(U)) {
          for (auto &caseHandle : switchInst->cases()) {
            if (caseHandle.getCaseValue()->getZExtValue() ==
                CV->getZExtValue()) {
              uint64_t profcOffset = 0;
              auto [isProfileCounter, offset] =
                  findProfileCounterInBlock(*caseHandle.getCaseSuccessor());
              if (isProfileCounter) {
                symccIdToProfileCounterMap[siteId] =
                    std::make_pair(offset, true);
              } else {
                // no profile counter found in either branch
                // unreachable, but for now we just warn and return
                DEBUG(errs() << "Error: no profile counter found in switch case"
                             << *switchInst << '\n');
                return false;
              }
            }
          }
        }
      }
    }
  }
  return false;
}

bool Symbolizer::resolveCounterOffset(
    Instruction &I,
    std::map<uint64_t, std::pair<uint64_t, bool>> &symccIdToProfileCounterMap) {
  if (auto *callInst = dyn_cast<CallInst>(&I)) {
    if (auto *calledFunction = callInst->getCalledOperand()) {
      if (calledFunction == runtime.pushPathConstraint.getCallee()) {
        Value *condition = callInst->getArgOperand(1);
        if (auto *CI = dyn_cast<ConstantInt>(callInst->getArgOperand(2))) {
          uint64_t symccSiteId = CI->getZExtValue();
          return resolveCounterOffsetForBranch(condition, symccSiteId,
                                               symccIdToProfileCounterMap) ||
                 resolveCounterOffsetForSwitch(condition, symccSiteId,
                                               symccIdToProfileCounterMap);
        }
      }
    }
  }
  return false;
}

bool Symbolizer::resolveFunctionId(Instruction &I, uint64_t &funcId) {
  if (auto *CI = dyn_cast<CallInst>(&I)) {
    if (auto *calledFunction = CI->getCalledOperand()) {
      if (calledFunction == runtime.notifyFunction.getCallee()) {
        if (auto *CI_ = dyn_cast<ConstantInt>(CI->getArgOperand(0))) {
          funcId = CI_->getZExtValue();
          return true;
        }
      }
    }
  }
  return false;
}

std::string Symbolizer::getFunctionNameWithoutCollision(Function &F) {
  std::string funcName;
  if (F.getMetadata("PGOFuncName")) {
    funcName = cast<MDString>(F.getMetadata("PGOFuncName")->getOperand(0))
                   ->getString()
                   .str();

  } else {
    funcName = F.getName().str();
  }
  return funcName;
}

void Symbolizer::generateFunctionIdRecord(Function &F) {
  if (F.isDeclaration()) {
    return;
  }
  // check first instruction
  bool success = false;
  uint64_t funcId = 0;
  for (auto &I : F.getEntryBlock()) {
    if (resolveFunctionId(I, funcId)) {
      success = true;
      break;
    }
  }
  if (!success) {
    DEBUG(errs() << "Error: no function id record found in function " << F
                 << '\n');
  } else {
    auto *M = F.getParent();
    std::string globalName =
        kSymCCFuncIdPrefix + getFunctionNameWithoutCollision(F);
    auto global = dyn_cast<GlobalVariable>(M->getOrInsertGlobal(
        globalName, llvm::Type::getInt64Ty(F.getContext())));
    global->setInitializer(
        llvm::ConstantInt::get(llvm::Type::getInt64Ty(F.getContext()), funcId));
    global->setSection(kSymCCFuncIdSection);
  }
}

void Symbolizer::generateBranchIdToProfileCounterMap(Function &F) {

  if (F.isDeclaration()) {
    return;
  }

  // check if it has the PGOFuncName metadata
  std::string funcName = getFunctionNameWithoutCollision(F);
  std::map<uint64_t, std::pair<uint64_t, bool>> branchIdToProfileCounterMap;
  for (auto &BB : F) {
    for (auto &I : BB) {
      resolveCounterOffset(I, branchIdToProfileCounterMap);
    }
  }
#define PUSH_INT(x)                                                            \
  mapBytes.insert(mapBytes.end(), (uint8_t *)&x, (uint8_t *)&x + sizeof(x))

  std::vector<uint8_t> mapBytes;
  for (auto &[symccId, profcInfo] : branchIdToProfileCounterMap) {
    PUSH_INT(symccId);
    PUSH_INT(profcInfo.first);
    PUSH_INT(profcInfo.second);
  }
  auto arrayType = llvm::ArrayType::get(llvm::Type::getInt8Ty(F.getContext()),
                                        mapBytes.size());
  auto *M = F.getParent();
  std::string globalName = kSymCCBranchIdMapPrefix + funcName;
  auto global =
      dyn_cast<GlobalVariable>(M->getOrInsertGlobal(globalName, arrayType));
  global->setInitializer(
      llvm::ConstantDataArray::get(F.getContext(), mapBytes));
  global->setSection(kSymCCBranchIdMapSection);
}
#endif
