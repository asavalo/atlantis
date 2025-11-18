#include "llvm/IR/PassManager.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

namespace {

class AddSanitizeAddressPass : public PassInfoMixin<AddSanitizeAddressPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &) {
    for (auto &F : M) {
      F.addFnAttr(Attribute::SanitizeAddress);
    }
    return PreservedAnalyses::none();
  }
};

} // namespace

extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, 
    "AddSanitizeAddressPass", 
    "0.1",
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM, ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "add-sanitize-address") {
            MPM.addPass(AddSanitizeAddressPass());
            return true;
          }
          return false;
        }
      );
    }
  };
}
