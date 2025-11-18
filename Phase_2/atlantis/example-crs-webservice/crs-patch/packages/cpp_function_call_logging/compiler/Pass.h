#ifndef PASS_H
#define PASS_H

#include <llvm/IR/PassManager.h>

class FunctionCallLoggerPass: public llvm::PassInfoMixin<FunctionCallLoggerPass> {
public:
    llvm::PreservedAnalyses run(llvm::Function &F, llvm::FunctionAnalysisManager &FAM);
    llvm::PreservedAnalyses run(llvm::Module &M, llvm::ModuleAnalysisManager &MAM);
    static bool isRequired() { return true; }
};

#endif
