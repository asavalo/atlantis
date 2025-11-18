#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>

#include "Pass.h"

using namespace llvm;

PassPluginLibraryInfo getFunctionCallLoggerPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "FunctionCallLogger", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineStartEPCallback(
                [](ModulePassManager &MPM, OptimizationLevel Level) {
                  MPM.addPass(FunctionCallLoggerPass());
                });
            PB.registerVectorizerStartEPCallback(
                [](FunctionPassManager &FPM, OptimizationLevel Level) {
                  FPM.addPass(FunctionCallLoggerPass());
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK PassPluginLibraryInfo llvmGetPassPluginInfo() {
  return getFunctionCallLoggerPluginInfo();
}