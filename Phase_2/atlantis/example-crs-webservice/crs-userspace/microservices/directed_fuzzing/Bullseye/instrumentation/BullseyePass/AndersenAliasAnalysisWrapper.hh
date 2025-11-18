/* vim: set tabstop=2 shiftwidth=2 expandtab:*/

#include "AE/Core/AbstractState.h"
#include "Graphs/SVFG.h"
#include "Graphs/ICFG.h"
#include "Graphs/CallGraph.h"
#include "SVF-LLVM/LLVMUtil.h"
#include "SVF-LLVM/SVFIRBuilder.h"
#include "Util/CommandLine.h"
#include "Util/Options.h"

#include "WPA/Andersen.h"
#include "WPA/Steensgaard.h"
#include "SVF-LLVM/BasicTypes.h"
#include "SVF-LLVM/LLVMModule.h"
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/Path.h>

using namespace llvm;

extern std::string UserSpecifiedIndCall;
extern std::string AliasAnalysisOption;

namespace BULLSEYE {
  /**
   * @class AndersenAliasAnalysis
   * @brief our wrapper around SVF's AndersenAliasAnalysis to get indirect calls
   * resolved
   */
  class AndersenAliasAnalysis{/*{{{*/
    private:
      Module& Mod;

      // SVF objects
      SVF::CallGraph *callgraph;
      std::map<Function*, std::set<CallBase*>> UserSpecifiedIndCallMap;

      CallBase* findCallInstructionByLoc(Module& Mod, std::string loc_string){/*{{{*/
        // target_loc format:
        // FILENAME:LINE_NUMBER
        int colindex = loc_string.find(":");
        assert(colindex != std::string::npos && "Invalid location string");

        for(Function& F : Mod){
          for(BasicBlock& B : F){
            for(Instruction& I : B){
              const DebugLoc& D = I.getDebugLoc();
              if (D) {
                std::string dFilepath = llvm::sys::path::filename(llvm::sys::path::remove_leading_dotslash(D->getFilename())).str();
                std::string dLinenumber = std::to_string(D->getLine());
                std::string CurrentLoc = dFilepath + ":" + dLinenumber;

                if(loc_string == CurrentLoc){
                  if (auto *callInst = dyn_cast<CallBase>(&I)) {
                    return callInst;
                  }
                }
              }
            }
          }
        }

        return NULL;
      }/*}}}*/

      void BuildUserSpecifiedIndCall(){/*{{{*/
        if (UserSpecifiedIndCall.empty()) {
          return;
        }

        std::stringstream ss(UserSpecifiedIndCall);
        std::string entry;

        while (std::getline(ss, entry, ';')) {

          size_t colonPos = entry.find(':');
          size_t commaPos = entry.find(',');

          if (colonPos == std::string::npos || commaPos == std::string::npos || colonPos >= commaPos) {
            BULLSEYE_DEBUG_FAIL("Skipping malformed entry: %s", entry.c_str());
            continue;
          }

          std::string filename = entry.substr(0, colonPos);
          int lineNumber = std::stoi(entry.substr(colonPos + 1, commaPos - colonPos - 1));
          std::string functionName = entry.substr(commaPos + 1);

          functionName.erase(functionName.find_last_not_of(" \t\n\r") + 1);
          functionName.erase(0, functionName.find_first_not_of(" \t\n\r"));

          Function *targetFunc = Mod.getFunction(functionName);
          if (!targetFunc) {
            BULLSEYE_DEBUG_FAIL("Function not found for UserSpecifiedIndCall: %s, skipping entry..", functionName.c_str());
            continue;
          }

          std::string loc_string = filename + ":" + std::to_string(lineNumber);
          CallBase* callInst = findCallInstructionByLoc(Mod, loc_string);
          if (!callInst) {
            BULLSEYE_DEBUG_FAIL("CallInst not found for location: %s", loc_string.c_str());
            continue;
          }

          UserSpecifiedIndCallMap[targetFunc].insert(callInst);
          BULLSEYE_DEBUG_INFO("Mapped indirect call at %s:%d to function %s", filename.c_str(), lineNumber, functionName.c_str());
        }
      }/*}}}*/

    public:
      SVF::PAG *pag;
      /**
       * @brief builds andersen alias analysis using SVF
       */
      AndersenAliasAnalysis(Module& Mod): Mod(Mod){/*{{{*/

        SVF::LLVMModuleSet::buildSVFModule(Mod);

        SVF::SVFIRBuilder builder;
        pag = builder.build();

        if (AliasAnalysisOption == "Andersen") {
          BULLSEYE_DEBUG_INFO("Using andersen alias analysis");
          SVF::Andersen *anderPTA = SVF::AndersenWaveDiff::createAndersenWaveDiff(pag);
          callgraph = anderPTA->getCallGraph();
        }else{
          BULLSEYE_DEBUG_INFO("Using Steensgaard alias analysis");
          SVF::Steensgaard *steenPTA = SVF::Steensgaard::createSteensgaard(pag);
          callgraph = steenPTA->getCallGraph();
        }

        BuildUserSpecifiedIndCall();
      }/*}}}*/

      /**
       * @brief destructor
       */
      ~AndersenAliasAnalysis(){/*{{{*/
        SVF::AndersenWaveDiff::releaseAndersenWaveDiff();
        SVF::SVFIR::releaseSVFIR();
        SVF::LLVMModuleSet::releaseLLVMModuleSet();
      }/*}}}*/

      /**
       * @brief gets all the calls to function F, direct and indirect
       *
       * @param callSites pointer set where results will be inserted
       * @return true if at least one call is indirect, false otherwise
       */
      bool getAllCallSites(Function* F,/*{{{*/
          SmallPtrSetImpl<CallBase*> &callSites){

        const SVF::FunObjVar* fov = SVF::LLVMModuleSet::getLLVMModuleSet()->getFunObjVar(F);
        SVF::CallGraphEdge::CallInstSet csSet;
        callgraph->getAllCallSitesInvokingCallee(fov, csSet);

        bool containsIndirect = false;

        for(SVF::CallGraphEdge::CallInstSet::const_iterator cit = csSet.begin(),
            ecit = csSet.end(); cit!=ecit; ++cit){

          const Value* val = SVF::LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(*cit);
          assert(isa<CallBase>(val) && "This callsite is not a CallBase type?");

          llvm::CallBase* CB = const_cast<CallBase*>(cast<CallBase>(val));
          callSites.insert(CB);
          containsIndirect |= CB->isIndirectCall();
        }

        callSites.insert(UserSpecifiedIndCallMap[F].begin(), UserSpecifiedIndCallMap[F].end());
        return containsIndirect;
      }/*}}}*/

      /**
       * @brief gets all the functions the call site CB could call
       *
       * @param CB call site to resolve
       * @param functionsOfCallSites pointer set where results will be inserted
       */
      void getAllCalledFunctionsOfCallSite(const CallBase* CB,/*{{{*/
          SmallPtrSetImpl<Function*> &functionsOfCallSite){

        Function* directCallFunction = CB->getCalledFunction();
        if (directCallFunction) {
          if (!directCallFunction->isIntrinsic() &&
              !directCallFunction->isDeclaration()) {
            functionsOfCallSite.insert(directCallFunction);
          }
          return;
        }

        // get the node from the pag
        SVF::CallICFGNode* CallNode = SVF::LLVMModuleSet::getLLVMModuleSet()->getCallICFGNode(CB);

        // then consult the CallGraph about it
        SVF::CallGraph::FunctionSet callees;
        callgraph->getCallees(CallNode, callees);

        // now "translate" to llvm's values
        for(const SVF::FunObjVar* fov : callees){
          const Value* val = SVF::LLVMModuleSet::getLLVMModuleSet()->getLLVMValue(fov);
          assert(isa<Function>(val) && "This Value is not a Function type?");

          llvm::Function* F = const_cast<Function*>(cast<Function>(val));
          if (!F->isDeclaration() && !F->isIntrinsic()) {
            functionsOfCallSite.insert(F);
          }
        }

      }/*}}}*/

  };/*}}}*/
}; // BULLSEYE namespace
