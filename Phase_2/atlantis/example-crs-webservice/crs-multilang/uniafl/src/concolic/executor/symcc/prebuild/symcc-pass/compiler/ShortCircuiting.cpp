#include "Symbolizer.h"
#include "llvm/Support/ErrorHandling.h"
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

#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

using namespace llvm;

void Symbolizer::shortCircuitExpressionUses() {

  DEBUG(errs() << "[Symbolizer::shortCircuitExpressionUses]\n");
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

    // if short circuiting is disabled (isShortCircuitingDisabled = true),
    // allConcrete should always be false
    allConcrete = IRB.CreateAnd(
        IRB.CreateNot(IRB.CreateCall(runtime.isFullTraceEnabled)), allConcrete);

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
      BasicBlock *symbolicCaseBlock = nullptr;

      bool needRuntimeCheck = originalArgExpression != nullExpression;

      // annotate source location
      if (needRuntimeCheck) {
        auto *argExpressionBlock = SplitBlockAndInsertIfThen(
            nullChecks[argIndex], symbolicComputation.firstInstruction,
            /* unreachable */ false);
        symbolicCaseBlock = SplitEdge(
            argCheckBlock, symbolicComputation.firstInstruction->getParent());
        // TODO: do we need to call notifySymbolicComputationInput ?
        IRB.SetInsertPoint(symbolicCaseBlock->getFirstInsertionPt());
        IRB.SetInsertPoint(argExpressionBlock);
      } else {
        IRB.SetInsertPoint(symbolicComputation.firstInstruction);
      }

      auto newArgExpression =
          createValueExpression(argument.concreteValue, IRB);

      if (newArgExpression.value == nullptr) {
        // We failed to build a constant symbolic expression for this argument.
        // We set newArgExpression to an LLVM null pointer. It may seem at first
        // glance to return here, but it results in incorrect behavior and is
        // highly likely to manifest as 'Instruction does not dominate all
        // uses'. Take a look at the following example:
        // clang-format off
	// %1:
        //  %1 = ... //
        //  %2 = call _sym_build_integer(%1, i8 64)
        //  br %3
        // %2:
        //  %3 = phi [%2, %1], [%expr, %0]
        //  %4 = call _sym_build_add(%2, %3)
        //  %5 = add %2, %3
        //
        //  But if we just return here
        //  %1:
        //  %1 = ... //
        //  br %3
        //  %2:
        //  %3 = %expr
        //  %4 = call _sym_build_add(%2, %3)
        //  %5 = add %2, %3
        //
        // clang-format on
        // If we take the edge %1 --> %2, the expression %expr will be used but
        // it would have never been created, triggering the 'Instruction does
        // not dominate all uses' error. We need to ensure that the
        // newArgExpression is defined in a block that actually branches to the
        // null-check continuation block.
        //
        // UPDATE: Most symcc handlers assume operand expressions to be
        // non-null. We should completely avoid this case and consider it a
        // critical error if this branch is ever reached.
        report_fatal_error(
            "Failed to create a symbolic expression for a concrete value");
      }
      ConstantInt *locHash;
      if (auto *I = dyn_cast<Instruction>(argument.concreteValue)) {
        locHash = getLocHash(I);
      } else {
        // invalid
        locHash = ConstantInt::get(IRB.getInt64Ty(), 0);
      }
      IRB.CreateCall(runtime.notifySymbolicComputationInput,
                     {newArgExpression.value, locHash, IRB.getInt1(false)});

      Value *finalArgExpression;
      if (needRuntimeCheck) {
        IRB.SetInsertPoint(symbolicComputation.firstInstruction);
        auto *argPHI = IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), 2);
        argPHI->addIncoming(originalArgExpression, symbolicCaseBlock);
        argPHI->addIncoming(newArgExpression.value, newArgExpression.incoming);
        finalArgExpression = argPHI;
      } else {
        finalArgExpression = newArgExpression.value;
      }

      argument.replaceOperand(finalArgExpression);
    }

    // Finally, the overall result (if the computation produces one) is null
    // if we've taken the fast path and the symbolic expression computed above
    // if short-circuiting wasn't possible.
    //
    // @Ws: we produce a notifySymbolicComputationOutput call here even if the
    // computation result is not used. One example is the push_path_constraint
    // call
    IRB.SetInsertPoint(&tail->front());

    if (symbolicComputation.lastInstruction->getType()->isVoidTy()) {
      // If the last instruction is void, we don't need to create a PHI node.
      continue;
    }

    auto *finalExpression = IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), 2);
    symbolicComputation.lastInstruction->replaceAllUsesWith(finalExpression);

    finalExpression->addIncoming(
        ConstantPointerNull::get(IRB.getInt8Ty()->getPointerTo()), head);
    finalExpression->addIncoming(
        symbolicComputation.lastInstruction,
        symbolicComputation.lastInstruction->getParent());
  }
}
