#include "BullseyeUtils.hh"
#include "AndersenAliasAnalysisWrapper.hh"
#include "Util/Options.h"
#include "Util/CommandLine.h"

#include <llvm/ADT/SmallSet.h>
#include <llvm/IR/BasicBlock.h>
#include <llvm/IR/CFG.h>
#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Passes/PassBuilder.h>
#include <llvm/Passes/PassPlugin.h>
#include <string>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <functional>

using namespace llvm;

#define MAX_LANDMARKS_SIZE 64
#define MAX_POST_ANALYSIS_DEPTH 10

std::unordered_set<std::string> landmarkSet;
std::unordered_map<std::string, double> distanceMap;

std::string UserSpecifiedIndCall;
std::string OutputDir;
std::string AliasAnalysisOption;
static std::string TargetLoc;
static int ContextMaxDepth = 2;

namespace {
class Bullseye : public PassInfoMixin<Bullseye> {
  public:
    typedef std::unordered_map<Function*,
            std::pair<std::shared_ptr<DominatorTree>,
            std::shared_ptr<LoopInfoBase<BasicBlock, Loop>>>> LoopInfoMapType;

    LoopInfoMapType loopInfoMap;
    BULLSEYE::AndersenAliasAnalysis* AAA;

    void parse_args() {
      const char* userIndCallEnv = std::getenv("BULLSEYE_USER_SPECIFIED_IND_CALL");
      const char* targetLocEnv = std::getenv("BULLSEYE_TARGET_LOC");
      const char* contextEnv = std::getenv("BULLSEYE_CONTEXT_MAX_DEPTH");
      const char* aliasAnalysisOptionEnv = std::getenv("BULLSEYE_ALIAS_ANALYSIS");
      const char* AnderTimeoutEnv = std::getenv("BULLSEYE_ANDER_TIMEOUT");

      // Parse UserSpecifiedIndCall
      if (userIndCallEnv != nullptr) {
        UserSpecifiedIndCall = std::string(userIndCallEnv);
        BULLSEYE_DEBUG_INFO("BULLSEYE_USER_SPECIFIED_IND_CALL: %s.", UserSpecifiedIndCall.c_str());
      } else {
        UserSpecifiedIndCall = "";
        BULLSEYE_DEBUG_INFO("BULLSEYE_USER_SPECIFIED_IND_CALL not set, default empty.");
      }

      // Parse AliasAnalysisOption
      if (aliasAnalysisOptionEnv != nullptr) {
        AliasAnalysisOption = std::string(aliasAnalysisOptionEnv);
        BULLSEYE_DEBUG_INFO("BULLSEYE_ALIAS_ANALYSIS: %s.", AliasAnalysisOption.c_str());
      } else {
        AliasAnalysisOption = "Andersen";
        BULLSEYE_DEBUG_INFO("BULLSEYE_ALIAS_ANALYSIS not set, default is Andersen.");
      }

      // Parse AnderTimeoutEnv
      if (AnderTimeoutEnv != nullptr) {
        std::string AnderTimeoutString(AnderTimeoutEnv);
        if (!(const_cast<Option<u32_t>&>(SVF::Options::AnderTimeLimit).parseAndSetValue(AnderTimeoutString))) {
          BULLSEYE_DEBUG_FAIL("Error: Invalid BULLSEYE_ANDER_TIMEOUT value, must be an integer.");
          exit(1);
        }
        BULLSEYE_DEBUG_INFO("BULLSEYE_ANDER_TIMEOUT: %s.", AnderTimeoutString.c_str());
      } else {
        BULLSEYE_DEBUG_INFO("BULLSEYE_ANDER_TIMEOUT not set, not setting a timeout");
      }

      // Parse TargetLoc (Required)
      if (targetLocEnv != nullptr) {
        TargetLoc = std::string(targetLocEnv);
        BULLSEYE_DEBUG_INFO("BULLSEYE_TARGET_LOC: %s", TargetLoc.c_str());
      } else {
        BULLSEYE_DEBUG_FAIL("BULLSEYE_TARGET_LOC is required but not set!");
        exit(1); // Or handle error as needed
      }

      // Parse ContextMaxDepth
      if (contextEnv != nullptr) {
        std::istringstream iss(contextEnv);
        if (!(iss >> ContextMaxDepth)) {
          BULLSEYE_DEBUG_FAIL("Error: Invalid BULLSEYE_CONTEXT_MAX_DEPTH value, must be an integer.");
          exit(1);
        }
        BULLSEYE_DEBUG_INFO("BULLSEYE_CONTEXT_MAX_DEPTH: %d.", ContextMaxDepth);
      } else {
        BULLSEYE_DEBUG_INFO("BULLSEYE_CONTEXT_MAX_DEPTH not set, using default value: %d", ContextMaxDepth);
      }

      BULLSEYE::initOutputDirFromEnv();
    }

    bool doInitialization(llvm::Module &M) {/*{{{*/
      // run the alias analysis
      BULLSEYE_DEBUG_INFO("Starting alias analysis");
      AAA = new BULLSEYE::AndersenAliasAnalysis(M);
      BULLSEYE_DEBUG_INFO("Starting loop analysis");
      buildLoopAnalysis(M);
      return false;
    }/*}}}*/

    bool doFinalization(llvm::Module &M) {/*{{{*/
      delete AAA;

      // delete the loop analysis
      for (auto &F: M){
        if (F.isDeclaration()) continue;
        loopInfoMap[&F].first.reset();
        loopInfoMap[&F].second.reset();
      }

      return false;
    }/*}}}*/

    void buildLoopAnalysis(Module &M){/*{{{*/
      for (auto &F: M){
        if (F.isDeclaration()) continue;

        auto DT = std::make_shared<DominatorTree>();
        DT->recalculate(F);

        auto loopInfo = std::make_shared<LoopInfoBase<BasicBlock, Loop>>();
        loopInfo->releaseMemory();
        loopInfo->analyze(*DT);
        loopInfoMap.insert({&F, {DT, loopInfo}});
      }
    }/*}}}*/

    Loop* getLoopFor(BasicBlock* BB1){/*{{{*/
      return loopInfoMap[BB1->getParent()].second->getLoopFor(BB1);
    }/*}}}*/

    Loop* getCommonLoop(BasicBlock* BB1, BasicBlock* BB2){/*{{{*/
      Loop* BB1Loop = getLoopFor(BB1);
      Loop* BB2Loop = getLoopFor(BB2);
      if (BB1Loop && BB1Loop == BB2Loop)
        return BB1Loop;
      return nullptr;
    }/*}}}*/

    // find the target basic block given the target location string
    BasicBlock* findTargetBB(Module& Mod, std::string target_loc){/*{{{*/
      // target_loc format:
      // FILENAME:LINE_NUMBER
      int colindex = target_loc.find(":");
      assert(colindex != std::string::npos && "Invalid target location string");

      std::string target_file = target_loc.substr(0,colindex);
      std::string target_ln = target_loc.substr(colindex+1);
      int target_lnnum = std::stoi(target_ln);

      // now search for the instructions with the provided line number in the module
      int delta = 15;
      std::string closestLoc = "";
      BasicBlock* closestBB = NULL;
      for(Function& F : Mod){
        for(BasicBlock& B : F){
          for(Instruction& I : B){
            const DebugLoc& D = I.getDebugLoc();
            if (D) {
              std::string dFilepath = llvm::sys::path::filename(llvm::sys::path::remove_leading_dotslash(D->getFilename())).str();
              std::string dLinenumber = std::to_string(D->getLine());
              int dLinenum = std::stoi(dLinenumber);
              std::string CurrentLoc = dFilepath + ":" + dLinenumber;

              if(target_loc == CurrentLoc){
                return &B;

              }else{
                // check maybe it is closer to what we already have
                if(target_file == dFilepath){
                  int cdelta = abs(dLinenum - target_lnnum);
                  if (cdelta < delta) {
                    closestLoc = CurrentLoc;
                    closestBB = &B;
                    delta = cdelta;
                  }
                }
              }
            }
          }
        }
      }

      if(!closestBB){
        BULLSEYE_DEBUG_FAIL("Could not find target location or anything close to it");
        exit(3);
      }

      BULLSEYE_DEBUG_WARN("Bullseye was not able to find exact target match BB with %s", target_loc.c_str());
      BULLSEYE_DEBUG_WARN("Using BB at closest line: %s", closestLoc.c_str());
      return closestBB;
    }/*}}}*/

    bool startCentralityAnalysis(Module& Mod, BasicBlock* targetBB){/*{{{*/
      // Struct to hash our calling context (without std::unary_function)
      struct ContextItemHash {
        std::size_t operator()(const std::deque<Instruction*>& k) const {
          return hash_combine_range(k.begin(), k.end());
        }
      };
      struct ContextItemEqual {
        bool operator()(const std::deque<Instruction*>& a,
            const std::deque<Instruction*>& b) const {
          // deque can handle comparing element by element in c++20
          return a == b;
        }
      };/*}}}*/

      // Structs to hash and compare visited nodes in our graphs
      // Basically a node is a basic block linked to a certain context
      struct VisistedItemHash {/*{{{*/
        std::size_t operator()(const std::pair<BasicBlock*, std::deque<Instruction*>>& k) const {
          return hash_combine(std::get<0>(k),
              hash_combine_range(std::get<1>(k).begin(), std::get<1>(k).end()));
        }
      };
      struct VisistedItemEqual {
        bool operator()(const std::pair<BasicBlock*, std::deque<Instruction*>>& a,
            const std::pair<BasicBlock*, std::deque<Instruction*>>& b) const {
          return std::get<0>(a) == std::get<0>(b) &&
            std::get<1>(a) == std::get<1>(b);
        }
      };/*}}}*/

      // A worklist item is 3 parts as we traverse up the inter-procedural cfg:
      //   - A basic block that we are now at while traversing up.
      //   - A queue of CallSite instructions donating the context.
      //   - The current distance from target
      typedef std::tuple<BasicBlock*, std::deque<Instruction*>, uint32_t> WorklistItem;

      // The visited set keeps track of whether we seen this block in this context
      // it deliberately ignores the distance, we check for it separately
      typedef std::unordered_set<std::pair<BasicBlock*, std::deque<Instruction*>>,
              VisistedItemHash,
              VisistedItemEqual> VisitedSet;

      std::queue<WorklistItem> worklist;
      VisitedSet visited;

      std::set<std::string> loopErrors;

      std::set<GlobalVariable*> glbVars;

      // Resultant output variables:
      // - 2D map: BasicBlock -> context -> Shortest distance of BB on path to
      //   target on this context
      std::unordered_map<BasicBlock*, std::unordered_map<std::deque<Instruction*>,
        uint32_t, ContextItemHash, ContextItemEqual>> OnPathContextsBB;
      // - Map: BasicBlock -> target reachable blocks starting from key BB
      std::unordered_map<BasicBlock*, std::set<BasicBlock*>> targetReachableBlocks;
      // - bool: whether we successfully tracked a path all the way to main function
      bool mainFunctionEntryReached = false;

      // start by adding target location in worklist
      std::deque<Instruction*> initialContext;
      initialContext.push_back(targetBB->getTerminator());
      worklist.push({targetBB, initialContext, 0});

      targetReachableBlocks[targetBB] = {targetBB};
      BULLSEYE::setBBLocationToTarget(targetBB,
          BULLSEYE::BBLocationToTarget::Target);

      std::set<BasicBlock*> landmarkIndCandidates;
      std::set<CallBase*> loopCallsLandmarkCandidates;

      uint32_t log_timer = 0;

      while(!worklist.empty()){
        auto CurrentWorklistItem = worklist.front();
        worklist.pop();

        BasicBlock* currentBB = get<0>(CurrentWorklistItem);
        std::deque<Instruction*>& currentContext = get<1>(CurrentWorklistItem);
        uint32_t currentDistance = get<2>(CurrentWorklistItem);

        auto addToReachableBlocks = [&](BasicBlock* newBlock){
          uint32_t size_before = targetReachableBlocks[newBlock].size();
          targetReachableBlocks[newBlock].insert(newBlock);
          targetReachableBlocks[newBlock].insert(targetReachableBlocks[currentBB].begin(), targetReachableBlocks[currentBB].end());
          uint32_t size_after = targetReachableBlocks[newBlock].size();
          return size_before != size_after;
        };

        // lambda to add items to worklist if:
        //   - we have not seen them
        //   - we have seen them with higher distance.
        //   - we have seen them with lower distance but with less targetReachableBlocks set
        auto maybeAddToWorklist = [&](BasicBlock* newBlock, std::deque<Instruction*>& newContext){/*{{{*/
          uint32_t newDistance = currentDistance+1;

          bool seenWithLowerDistance = false;
          if (visited.count({newBlock, newContext})){
            if (OnPathContextsBB[newBlock][newContext] <= newDistance){
              seenWithLowerDistance = true;
            }
          }else{
            OnPathContextsBB[newBlock][newContext] = UINT32_MAX;
          }

          bool addedNewReachables = addToReachableBlocks(newBlock);

          if(seenWithLowerDistance && !addedNewReachables){
            return;
          }

          worklist.push({newBlock, newContext, newDistance});
        };/*}}}*/

        bool addedNewReachables = addToReachableBlocks(currentBB);

        if (visited.count({currentBB, currentContext})){
          if (OnPathContextsBB[currentBB][currentContext] <= currentDistance){
            if(!addedNewReachables){
              continue;
            }
          }
        }

        visited.insert({currentBB, currentContext});

        log_timer++;
        if (log_timer % 1000 == 0) {
          BULLSEYE_DEBUG_INFO("Visited %lu blocks so far...", visited.size());
        }

        // set the BB distance on path for this context
        if (OnPathContextsBB[currentBB][currentContext] > currentDistance)
          OnPathContextsBB[currentBB][currentContext] = currentDistance;

        // check if we reached main top
        Function* func = currentBB->getParent();
        if (func->getName() == "main" || func->getName() == "LLVMFuzzerTestOneInput") {
          BasicBlock& mainEntry = func->getEntryBlock();
          if(currentBB == &mainEntry){
            mainFunctionEntryReached = true;
          }
        }

        // iterate the successors of the current block
        // and mark them as outside the path of target (in current context) if not visited
        // Guilty until proven innocent kind of thing
        for(BasicBlock* spB : successors(currentBB)){
          if(!visited.count({spB, currentContext})){
            OnPathContextsBB[spB][currentContext] = UINT32_MAX;
          }
        }

        // mark current block as pretarget
        // this check is to not overwrite Target
        // location in case we loop into it
        if (BULLSEYE::getBBLocationToTarget(currentBB) ==
              BULLSEYE::BBLocationToTarget::External) {
          BULLSEYE::setBBLocationToTarget(currentBB,
              BULLSEYE::BBLocationToTarget::PreTarget);
        }

        // now traverse predecessors
        bool have_preds = false;
        for(BasicBlock* pB : predecessors(currentBB)){
          have_preds = true;

          // ignore loops backward edges
          if(Loop* commonLoop = getCommonLoop(currentBB, pB)){
            if(commonLoop->isLoopSimplifyForm()){
              BasicBlock* lpHeader = commonLoop->getHeader();
              assert(lpHeader && "We have loop with no header block");

              // check if this is a backward edge
              if(lpHeader == currentBB
                  && commonLoop->isLoopLatch(pB)){

                // we only ignore backward edges if we dont have any of the loop
                // successor blocks been visited, i.e. we came into this loop
                // from a different context.
                if(!std::any_of(successors(lpHeader).begin(), successors(lpHeader).end(),
                      [&](BasicBlock* hdrSucc){
                      return visited.count({hdrSucc, currentContext}) && !commonLoop->contains(hdrSucc);
                      })){
                  continue;
                }
              }
            }else{
              std::string errLoc = BULLSEYE::getDebugLocString(currentBB).c_str();
              if(!loopErrors.count(errLoc)){
                BULLSEYE_DEBUG_WARN("Loop at %s is not in simplified form", errLoc.c_str());
                loopErrors.insert(errLoc);
              }
            }
          }

          // traverse up
          std::deque<Instruction*> newContext(currentContext.size());
          std::copy(currentContext.begin(), currentContext.end(), newContext.begin());
          maybeAddToWorklist(pB, newContext);
        }

        for (auto &II: *currentBB) {
          for (auto uu: II.operand_values()) {
            if (GlobalVariable* gv = dyn_cast_or_null<GlobalVariable>(uu)) {
              glbVars.insert(gv);
            }
          }
        }

        if(!have_preds){
          // block does not have predecessors, we jump inter-procedurally
          SmallPtrSet<CallBase*, 32> resolvedCallSites;
          AAA->getAllCallSites(currentBB->getParent(), resolvedCallSites);

          for(CallBase* CB : resolvedCallSites){
            BasicBlock* Bi = CB->getParent();

            // The idea here is that we add other indirect calls target function as landmarks
            // Two common patterns we look for here:
            // func1:
            // while(commands_are_coming){
            //   parse_commands(cmmd)
            // }
            //
            // parse_commands(cmd){
            //   indirect_call_to_target()
            // }
            //
            // This way we capture a bug that is only triggerable if maybe one
            // command is executed before the target location is triggered.
            //
            // The other pattern is similar but the loop is hoisted in the same function where indirect call happens:
            //
            // while(commands_are_coming){
            //   indirect_call_to_target(cmmd)
            // }
            //
            if (getLoopFor(CB->getParent())) {
              loopCallsLandmarkCandidates.insert(CB);

              if(CB->isIndirectCall()){
                // pattern 2
                SmallPtrSet<Function*, 32> possibleCalls;
                AAA->getAllCalledFunctionsOfCallSite(CB, possibleCalls);
                for(auto cFF : possibleCalls){
                  landmarkIndCandidates.insert(&cFF->getEntryBlock());
                }
              }else{
                // pattern 1
                Instruction* lastContext = currentContext.back();
                if(CallBase* lcCB = dyn_cast<CallBase>(lastContext)){
                  if(lcCB->isIndirectCall()){
                    SmallPtrSet<Function*, 32> possibleCalls;
                    AAA->getAllCalledFunctionsOfCallSite(lcCB, possibleCalls);
                    for(auto cFF : possibleCalls){
                      landmarkIndCandidates.insert(&cFF->getEntryBlock());
                    }
                  }
                }
              }
            }

            std::deque<Instruction*> newContext(currentContext.size());
            std::copy(currentContext.begin(), currentContext.end(), newContext.begin());

            // keep context manageable
            if (newContext.size() >= ContextMaxDepth) {
              newContext.pop_front();
            }
            newContext.push_back(CB);

            maybeAddToWorklist(Bi, newContext);
          }
        }
      }// end of algorithm

      BULLSEYE_DEBUG_INFO("Done with main Bullseye traversal");

      std::set<BasicBlock*> landmarkCandidates;

      // During analysis, if we found a successor basic block to be outside a
      // path to target, we judge its predecessor block (frontier block) as
      // either a hard constraint or soft constraint, depending on the other
      // successors of the predecessor basic block
      auto setConstraintTypeOnFrontierBlocks = [&](BasicBlock* outB, bool alwaysOut){/*{{{*/
        for(BasicBlock* pB : predecessors(outB)){
          if(BULLSEYE::getBBLocationToTarget(pB) !=
              BULLSEYE::BBLocationToTarget::PreTarget){
            // if block is not a preTarget, it cannot be a soft/hard constraint
            continue;
          }

          if(pB->getUniqueSuccessor()){
            // if block has a single successor, it cannot be a constraint
            continue;
          }

          BULLSEYE::ConstraintType ct = BULLSEYE::getConstraintType(pB);
          if(ct != BULLSEYE::ConstraintType::NotAConstraint){
            // we have set this one before!
            continue;
          }

          if (alwaysOut){
            // OutB is always outside the path to target, pB is hard constraint
            ct = BULLSEYE::HardConstraint;

            // we demote pB to not a constraint *if* we find out all successors of pB block
            // are out. This could happen if we start the context from a call
            // within a block that ends with a branch. All successors will be out
            // but the call block itself is in
            if(std::all_of(successors(pB).begin(), successors(pB).end(),
                  [](BasicBlock* succ){
                  return BULLSEYE::getBBLocationToTarget(succ) > BULLSEYE::BBLocationToTarget::Target;
                  })){
              ct = BULLSEYE::ConstraintType::NotAConstraint;
              return;
            }
          }else{
            // OutB is sometimes outside the path to target, pB is soft constraint
            ct = BULLSEYE::ConstraintType::SoftConstraint;

            // promot to a hard constraint if the block has exactly two
            // successors and one of them is outside our path (switch statement
            // with *some* reaching cases is still soft constraint)
            std::vector<BasicBlock*> pBSucc =
              std::vector<BasicBlock*>(successors(pB).begin(), successors(pB).end());

            if(pBSucc.size() == 2){
              if(std::any_of(pBSucc.begin(), pBSucc.end(),
                    [](BasicBlock* succ){
                    return BULLSEYE::getBBLocationToTarget(succ) > BULLSEYE::BBLocationToTarget::Target;
                    })){
                ct = BULLSEYE::ConstraintType::HardConstraint;
              }
            }
          }

          landmarkCandidates.insert(pB);
          BULLSEYE::setConstraintType(pB, ct);
        }
      };/*}}}*/

      // now, we set keep track of shortest distance of each block to the target
      // block across all contexts as well as setting the constraint type
      // for some of the blocks on path to the target
      std::unordered_map<BasicBlock*, uint32_t> shortestDistancesToTarget;
      for(auto const&[currentBB, OnPathContexts]: OnPathContextsBB){
        bool alwaysIn = true; // in all contexts, this basic block is on path
        bool alwaysOut = true; // in all contexts, this basic block is OUT of path

        if(BULLSEYE::getBBLocationToTarget(currentBB) ==
            BULLSEYE::BBLocationToTarget::Target){
          shortestDistancesToTarget[currentBB] = 0;
          continue;
        }

        shortestDistancesToTarget[currentBB] = UINT32_MAX;
        for(auto const&[currentContext, contextDistance] : OnPathContexts){
          bool onPath = contextDistance != UINT32_MAX ? true : false;

          alwaysIn &= onPath;
          alwaysOut &= !onPath;

          if (contextDistance < shortestDistancesToTarget[currentBB])
            shortestDistancesToTarget[currentBB] = contextDistance;
        }

        if (alwaysIn) {
          continue;
        }

        setConstraintTypeOnFrontierBlocks(currentBB, alwaysOut && !getLoopFor(currentBB));
      }

      BULLSEYE_DEBUG_INFO("Done with setting constraints on visitied blocks");

      for(BasicBlock* lmcBB: landmarkCandidates){
        if(BULLSEYE::getConstraintType(lmcBB) != BULLSEYE::ConstraintType::SoftConstraint){
          continue;
        }

        for (auto lmBB : successors(lmcBB)) {
          if (BULLSEYE::getBBLocationToTarget(lmBB) == BULLSEYE::BBLocationToTarget::PreTarget) {
            BULLSEYE::setLandmark(lmBB);
            if(BULLSEYE::getLandmarkCount() >= MAX_LANDMARKS_SIZE){
              break;
            }
          }
        }

        if (BULLSEYE::getLandmarkCount() >= MAX_LANDMARKS_SIZE) {
          break;
        }
      }

      BULLSEYE_DEBUG_INFO("Added SoftConstraint landmark candidates. So far we have %lu landmarks", BULLSEYE::getLandmarkCount());

      while(BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE && !landmarkIndCandidates.empty()){
        BasicBlock* newCandidate = *landmarkIndCandidates.begin();
        landmarkIndCandidates.erase(newCandidate);
        if(!BULLSEYE::isLandmark(newCandidate)){
          BULLSEYE::setLandmark(newCandidate);
        }
      }

      BULLSEYE_DEBUG_INFO("Added Indirect calls landmark candidates. So far we have %lu landmarks", BULLSEYE::getLandmarkCount());

      // finally, we are able to calculate the centrality for each block
      for(auto const&[currentBB, targetReachingBlocks]: targetReachableBlocks){

        if(BULLSEYE::getBBLocationToTarget(currentBB) == BULLSEYE::BBLocationToTarget::Target){
          // target has max centrality
          BULLSEYE::setBBDistance(currentBB, 1);
          continue;
        }

        double reachable_nodes = 0;
        double total_nodes = 0;
        double shortestDistancesSum = 0;
        for (auto reachingBlock : targetReachingBlocks) {
          assert(BULLSEYE::getBBLocationToTarget(reachingBlock) == BULLSEYE::BBLocationToTarget::PreTarget ||
              BULLSEYE::getBBLocationToTarget(reachingBlock) == BULLSEYE::BBLocationToTarget::Target);
          assert(shortestDistancesToTarget[reachingBlock] < UINT32_MAX);

          reachable_nodes++;
          shortestDistancesSum += shortestDistancesToTarget[reachingBlock];
          total_nodes++;

          if(std::any_of(successors(reachingBlock).begin(),
                successors(reachingBlock).end(),
                [](BasicBlock* succ){
                return BULLSEYE::getBBLocationToTarget(succ) > BULLSEYE::BBLocationToTarget::Target;
                })){
            // increment unreaching nodes
            // ideally, we should increase this number by the actual number of
            // nodes that do not reach the target which are successors of this
            // block. However, first, finding those will take extra expensive
            // analysis, and second it will make the ratio very small
            // deminishing the impact of our centrality metric
            total_nodes++;
          }
        }

        double reachableBlockCentrality = (reachable_nodes-1) / shortestDistancesSum;
        double reachabiliyRatio = (reachable_nodes-1) / (total_nodes-1);
        double totalBlockCentrality = reachableBlockCentrality * reachabiliyRatio;
        BULLSEYE::setBBDistance(currentBB, totalBlockCentrality);
      }

      BULLSEYE_DEBUG_INFO("Done with setting blocks distances");

      // if there is more space for landmarks, we add entry blocks of functions
      // that we did not find in our analysis, but access the same global variable
      // and could end up reaching any target-reaching function
      if(BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE){
        std::set<Function*> gvFuncs;
        for (GlobalVariable* gv: glbVars) {
          for (auto gvUser : gv->users()) {
            if(Instruction* ui = dyn_cast_or_null<Instruction>(gvUser)){
              Function* fui = ui->getParent()->getParent();
              BasicBlock* fuiEntry = &fui->getEntryBlock();
              if (BULLSEYE::getBBLocationToTarget(fuiEntry) > BULLSEYE::BBLocationToTarget::Target) {
                gvFuncs.insert(fui);
              }
            }
          }
        }

        BULLSEYE_DEBUG_INFO("Looking into %lu functions which use GVs.", gvFuncs.size());

        while (!gvFuncs.empty() && BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE) {
          std::queue<Function*> workListQ;
          std::set<Function*> visitedFunctions;

          Function* landmarkFunction = gvFuncs.extract(gvFuncs.begin()).value();
          workListQ.push(landmarkFunction);
          bool addedFuncitonAsLandMark = false;
          uint32_t currentDepth = 0;
          while (!workListQ.empty()) {
            Function* currentFunction = workListQ.front();
            workListQ.pop();

            visitedFunctions.insert(currentFunction);

            SmallPtrSet<CallBase*, 32> resolvedCallSites;
            AAA->getAllCallSites(currentFunction, resolvedCallSites);
            for (CallBase* CB: resolvedCallSites){
              Function* newFunction = CB->getParent()->getParent();
              BasicBlock* newFuncEntry = &newFunction->getEntryBlock();
              if (BULLSEYE::getBBLocationToTarget(newFuncEntry) == BULLSEYE::BBLocationToTarget::PreTarget &&
                  BULLSEYE::getBBLocationToTarget(CB->getParent()) > BULLSEYE::BBLocationToTarget::Target) {
                BULLSEYE::setLandmark(&landmarkFunction->getEntryBlock());
                BULLSEYE_DEBUG_INFO("[GV] Adding function %s as landmark!", BULLSEYE::getLLVMValueStr(landmarkFunction).c_str());
                addedFuncitonAsLandMark = true;
                break;

              }else{
                if(!visitedFunctions.count(newFunction) && currentDepth < MAX_POST_ANALYSIS_DEPTH){
                  workListQ.push(newFunction);
                  currentDepth++;
                }
              }
            }

            if(addedFuncitonAsLandMark)
              break;
          }
        }
      }

      BULLSEYE_DEBUG_INFO("Added global variable landmark candidates. So far we have %lu landmarks", BULLSEYE::getLandmarkCount());

      // if there is more space for landmarks, we add blocks with high
      // divergence in centrality
      if(BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE){
        std::vector<std::pair<std::pair<BasicBlock*, BasicBlock*>, double>> candidateLandmarks;
        for(auto const&[currentBB, targetReachingBlocks]: targetReachableBlocks){
          std::pair<BasicBlock*, BasicBlock*> divergentPair;
          double maxDivergence = 0;
          for ( auto child1: successors(currentBB)) {
            if(BULLSEYE::getBBLocationToTarget(child1) != BULLSEYE::BBLocationToTarget::PreTarget)
              continue;

            double d1 = BULLSEYE::getBBDistance(child1);
            if(d1 <= 0)
              continue;

            for ( auto child2: successors(currentBB)) {
              if(child2 == child1)
                continue;
              if(BULLSEYE::getBBLocationToTarget(child2) != BULLSEYE::BBLocationToTarget::PreTarget)
                continue;

              double d2 = BULLSEYE::getBBDistance(child2);
              if(d2 <= 0)
                continue;

              double diff = d2-d1;
              if(diff > maxDivergence){
                maxDivergence = diff;
                divergentPair = {child1, child2};
              }
            }
          }

          if(maxDivergence){
            candidateLandmarks.push_back({divergentPair, maxDivergence});
          }
        }

        std::sort(candidateLandmarks.begin(), candidateLandmarks.end(), [](auto &left, auto &right) {
            return left.second < right.second;
            });

        while(BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE && !candidateLandmarks.empty()){
          std::pair<BasicBlock*, BasicBlock*> newCandidatePair = candidateLandmarks.back().first;
          candidateLandmarks.pop_back();
          if(!BULLSEYE::isLandmark(newCandidatePair.first)){
            BULLSEYE::setLandmark(newCandidatePair.first);
          }
          if(BULLSEYE::getLandmarkCount() < MAX_LANDMARKS_SIZE && !BULLSEYE::isLandmark(newCandidatePair.second)){
            BULLSEYE::setLandmark(newCandidatePair.second);
          }
        }
      }

      BULLSEYE_DEBUG_INFO("Added high divergance landmark candidates. So far we have %lu landmarks", BULLSEYE::getLandmarkCount());

      // the idea here is that since our analysis will always take the greatest
      // centrality value while executing the binary, we can same on some
      // instrumentations that is dominated by a node with higher centrality
      // as that instrumentation will always not be taken
      std::set<BasicBlock*> markedForDistanceRemoval;
      for (auto &F: Mod){
        if (F.isDeclaration()) continue;
        if(BULLSEYE::getBBLocationToTarget(&F.getEntryBlock()) != BULLSEYE::BBLocationToTarget::PreTarget){
          continue;
        }

        auto DT = loopInfoMap[&F].first.get();
        for (auto node = GraphTraits<DominatorTree *>::nodes_begin(DT);
            node != GraphTraits<DominatorTree *>::nodes_end(DT); ++node) {
          BasicBlock *cBB = node->getBlock();

          if(BULLSEYE::getBBLocationToTarget(cBB) != BULLSEYE::BBLocationToTarget::PreTarget){
            continue;
          }

          if(!node->getIDom()){
            // this is a root node, always set the distance here
            continue;
          }

          BasicBlock *pBB = node->getIDom()->getBlock();
          double cBBDistance = BULLSEYE::getBBDistance(cBB);
          double pBBDistance = BULLSEYE::getBBDistance(pBB);

          if(pBBDistance >= cBBDistance){
            // set the distance as high as parent, so set higher standard for children
            BULLSEYE::setBBDistance(cBB, pBBDistance);
            markedForDistanceRemoval.insert(cBB);
          }
        }
      }
      BULLSEYE_DEBUG_INFO("Done with dom tree optimization");

      for(BasicBlock* rBB: markedForDistanceRemoval){
        BULLSEYE::setBBDistance(rBB, 0);
      }

      BULLSEYE::writeAnalysisOutputToJson();
      return mainFunctionEntryReached;
    }/*}}}*/

    PreservedAnalyses run(Module &M, ModuleAnalysisManager &MAM) {
      parse_args();

      BULLSEYE_DEBUG_INFO("Starting Bullseye analysis with target location: %s", TargetLoc.c_str());
      BULLSEYE_DEBUG_INFO("Only run this pass with linked and complete bitcode files.");
      BULLSEYE_DEBUG_INFO("Use tools such as https://github.com/travitch/whole-program-llvm to get whole bitcode files.");
      BULLSEYE_DEBUG_INFO("Also, for optimal results, run the bc through -loop-simplify pass before this pass.");
      BULLSEYE_DEBUG_INFO("i.e. opt -loop-simplify -o output-bc-ready.bc < input-whole-linked.bc");

      BasicBlock* targetBB = findTargetBB(M, TargetLoc);

      // Initialize
      doInitialization(M);

      BULLSEYE_DEBUG_INFO("Found target location");
      BULLSEYE_DEBUG_INFO("Starting interprocedural static analysis with max depth: %d", ContextMaxDepth);

      if(!startCentralityAnalysis(M, targetBB)){
        BULLSEYE_DEBUG_FAIL("Failed to complete centrality analysis with target location: %s", TargetLoc.c_str());
        exit(2);
      }

      BULLSEYE_DEBUG_SUCCESS("Target centrality analysis complete");

      // Finalize
      doFinalization(M);

      // This pass doesn't modify the IR, so we preserve all analyses
      return PreservedAnalyses::all();
    }
};


} // end anonymous namespace

// New pass manager registration
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return {
    LLVM_PLUGIN_API_VERSION, "Bullseye", LLVM_VERSION_STRING,
    [](PassBuilder &PB) {
      PB.registerPipelineParsingCallback(
        [](StringRef Name, ModulePassManager &MPM,
           ArrayRef<PassBuilder::PipelineElement>) {
          if (Name == "bullseye") {
            MPM.addPass(Bullseye());
            return true;
          }
          return false;
        });

      // Register as a pass to run before full optimization
      PB.registerPipelineStartEPCallback(
        [](ModulePassManager &MPM, OptimizationLevel Level) {
          MPM.addPass(Bullseye());
        });
    }
  };
}
