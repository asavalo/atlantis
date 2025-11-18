#include "Pass.h"

#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Instructions.h>

using namespace llvm;

namespace
{
  bool instrumentFunction(Function &F)
  {
    errs() << "Instrumenting function: " << F.getName() << "\n";

    if (F.getName().startswith("llvm."))
    {
      errs() << "Intrinsic function found: " << F.getName() << "\n";
      return false;
    }
    if (F.getName().startswith("logFunctionCall"))
    {
      errs() << "Skipping logFunctionCall function: " << F.getName() << "\n";
      return false;
    }
    if (F.empty())
    {
      errs() << "Function has no basic blocks: " << F.getName() << "\n";
      return false;
    }

    auto *subProgram = F.getSubprogram();
    if (!subProgram)
    {
      errs() << "Function has no debug information: " << F.getName() << "\n";
      return false;
    }

    errs() << "Inserting logFunctionEntry call at the beginning of the function: " << F.getName() << "\n";

    // func logFunctionEntry: (functionName: string, file: string, line: int) -> void
    Type *ptrType = PointerType::get(Type::getInt8Ty(F.getContext()), 0);
    Type *intType = Type::getInt32Ty(F.getContext());
    Type *voidType = Type::getVoidTy(F.getContext());
    FunctionType *funcType = FunctionType::get(voidType, {ptrType, ptrType, intType}, false);
    FunctionCallee logFunctionEntry = F.getParent()->getOrInsertFunction("logFunctionEntry", funcType);

    auto *entryBlock = &F.getEntryBlock();
    auto *firstInstruction = &*entryBlock->getFirstInsertionPt();
    IRBuilder<> Builder(firstInstruction);
    Builder.SetInsertPoint(firstInstruction);
    auto *functionName = Builder.CreateGlobalStringPtr(F.getName());
    auto *fileName = Builder.CreateGlobalStringPtr(subProgram->getFilename());
    auto *line = Builder.getInt32(subProgram->getLine());
    Builder.CreateCall(logFunctionEntry, {functionName, fileName, line});
    return true;
  }

  bool instrumentModule(Module &M)
  {
    errs() << "Instrumenting module: " << M.getName() << "\n";

    LLVMContext &Context = M.getContext();
    bool modified = false;

    // func logFunctionCall: (fileName: string, lineNumber: int, callerName: string, calleeName: string) -> void
    Type *voidType = Type::getVoidTy(Context);
    Type *ptrType = PointerType::get(Type::getInt8Ty(Context), 0);
    Type *intType = Type::getInt32Ty(Context);
    FunctionType *funcType = FunctionType::get(voidType, {ptrType, intType, ptrType, ptrType}, false);
    FunctionCallee logFunctionCall = M.getOrInsertFunction("logFunctionCall", funcType);

    for (auto &F : M)
    {
      auto functionName = F.getName();
      for (auto &BB : F)
      {
        for (auto &I : BB)
        {
          if (!&I || !isa<CallInst>(&I) || !I.getDebugLoc()) {
            continue;
          }
          if (auto *CI = dyn_cast<CallInst>(&I))
          {
            auto *callee = CI->getCalledFunction();
            if (!callee)
            {
              IRBuilder<> Builder(CI);
              Builder.SetInsertPoint(CI);
              auto *fileName = Builder.CreateGlobalStringPtr(CI->getDebugLoc().get()->getFilename());
              auto *lineNumber = Builder.getInt32(CI->getDebugLoc().getLine());
              auto *callerName = Builder.CreateGlobalStringPtr(functionName);
              auto *calleeName = Builder.CreateGlobalStringPtr("<unknown>");
              Builder.CreateCall(logFunctionCall, {fileName, lineNumber, callerName, calleeName});
              modified = true;
              continue;
            }

            auto calleeNameStr = callee->getName();
            if (calleeNameStr.startswith("llvm."))
            {
              errs() << "Intrinsic call found in function: " << functionName << "\n";
              continue;
            }

            if (calleeNameStr.startswith("logFunctionCall"))
            {
              errs() << "Preventing recursive call to logFunctionCall in function: " << functionName << "\n";
              continue;
            }

            errs() << "Instrumenting call to function: " << calleeNameStr << "\n";

            IRBuilder<> Builder(CI);
            Builder.SetInsertPoint(CI);
            auto *fileName = Builder.CreateGlobalStringPtr(CI->getDebugLoc().get()->getFilename());
            auto *lineNumber = Builder.getInt32(CI->getDebugLoc().getLine());
            auto *callerName = Builder.CreateGlobalStringPtr(functionName);
            auto *calleeName = Builder.CreateGlobalStringPtr(calleeNameStr);
            Builder.CreateCall(logFunctionCall, {fileName, lineNumber, callerName, calleeName});
            modified = true;
          }
        }
      }
    }

    return modified;
  }
} // namespace

PreservedAnalyses FunctionCallLoggerPass::run(Function &F, FunctionAnalysisManager &)
{
  return instrumentFunction(F) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
PreservedAnalyses FunctionCallLoggerPass::run(Module &M, ModuleAnalysisManager &)
{
  return instrumentModule(M) ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
