#include <llvm/IR/DebugInfoMetadata.h>
#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/Path.h>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <fstream>
#include <unordered_map>
#include <unordered_set>

#include "json.hpp"

#define PRINTF_DEBUG(MARK) std::fprintf(stderr, "[BULLSEYE] [" MARK "] [%s] In function (%s): ", BULLSEYE::get_time_now().c_str(), __FUNCTION__)
#define BULLSEYE_DEBUG_SUCCESS(...) {PRINTF_DEBUG("+"); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n");}
#define BULLSEYE_DEBUG_INFO(...) {PRINTF_DEBUG("I"); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n");}
#define BULLSEYE_DEBUG_WARN(...) {PRINTF_DEBUG("W"); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n");}
#define BULLSEYE_DEBUG_FAIL(...) {PRINTF_DEBUG("-"); std::fprintf(stderr, __VA_ARGS__); std::fprintf(stderr, "\n");}

#define BULLSEYE_CONSTRAINT_MDNODE_KEY "bullseye-constraint-mark"
#define BULLSEYE_BB_LOCATION_TO_TARGET_MDNODE_KEY "bullseye-location-mark"

extern std::string OutputDir;
extern std::unordered_set<std::string> landmarkSet;
extern std::unordered_map<std::string, double> distanceMap;

namespace BULLSEYE {
  // enum for types of constraints
  enum ConstraintType{
    NotAConstraint = 0,
    SoftConstraint = 1, // Constraints that may or may not lead to target but does alter the context
    HardConstraint = 2, // Constraints that must be satisfied to hit the target
  };

  // enum for basic blocks location to the target
  enum BBLocationToTarget {
    PreTarget = -2,       // BBs that proceeds hitting a target
    Target = -1,
    External = 0,    // BBs that are outside any path from or to a target (default enum value)
    PostTarget = 1,      // BBs that are after a target
  };

  inline const std::string get_time_now(){
    // https://stackoverflow.com/a/35157784/9416167
    // get current time
    auto now = std::chrono::system_clock::now();

    // get number of milliseconds for the current second
    // (remainder after division into seconds)
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;

    // convert to std::time_t in order to convert to std::tm (broken time)
    auto timer = std::chrono::system_clock::to_time_t(now);

    // convert to broken time
    std::tm bt = *std::localtime(&timer);

    std::ostringstream oss;

    oss << std::put_time(&bt, "%H:%M:%S"); // HH:MM:SS
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();

    return oss.str();
  }

  inline void initOutputDirFromEnv() {
    const char* outputDirEnv = std::getenv("BULLSEYE_OUTPUT_DIR");

    // Check environment variable
    if (outputDirEnv != nullptr) {
      OutputDir = std::string(outputDirEnv);
      BULLSEYE_DEBUG_INFO("BULLSEYE_OUTPUT_DIR: %s", OutputDir.c_str());
    } else {
      BULLSEYE_DEBUG_FAIL("BULLSEYE_OUTPUT_DIR is required but not set!");
      exit(1);
    }

    // Check if directory exists
    if (!std::filesystem::exists(OutputDir)) {
      BULLSEYE_DEBUG_FAIL("Directory does not exist: %s", OutputDir.c_str());
      exit(1);
    }
  }

  inline void writeAnalysisOutputToJson() {
    namespace fs = std::filesystem;
    fs::path outDir(OutputDir);

    // Serialize landmarks
    nlohmann::json landmarkJson = nlohmann::json::array();
    for (const auto& entry : landmarkSet) {
      landmarkJson.push_back(entry);
    }

    // Serialize distances
    nlohmann::json distanceJson;
    for (const auto& [loc, dist] : distanceMap) {
      distanceJson[loc] = dist;
    }

    // Write to files
    std::ofstream landmarkFile(outDir / "landmarks.json");
    if (!landmarkFile) {
      BULLSEYE_DEBUG_FAIL("Failed to write landmarks.json");
      exit(1);
    }

    landmarkFile << landmarkJson.dump(4);

    std::ofstream distanceFile(outDir / "distance.json");
    if (!distanceFile){
      BULLSEYE_DEBUG_FAIL("Failed to write distance.json");
      exit(1);
    }

    distanceFile << distanceJson.dump(4);
  }

  inline void loadAnalysisOutputFromJson() {
    namespace fs = std::filesystem;
    fs::path outDir(OutputDir);

    // ---- Load landmarks.json ----
    std::ifstream landmarkFile(outDir / "landmarks.json");
    if (!landmarkFile) {
      BULLSEYE_DEBUG_FAIL("Failed to open landmarks.json for reading");
      exit(1);
    }

    nlohmann::json landmarkJson;
    landmarkFile >> landmarkJson;

    if (!landmarkJson.is_array()) {
      BULLSEYE_DEBUG_FAIL("Invalid format in landmarks.json (expected array)");
      exit(1);
    }

    landmarkSet.clear();
    for (const auto& entry : landmarkJson) {
      if (entry.is_string()) {
        landmarkSet.insert(entry.get<std::string>());
      }
    }

    // ---- Load distance.json ----
    std::ifstream distanceFile(outDir / "distance.json");
    if (!distanceFile) {
      BULLSEYE_DEBUG_FAIL("Failed to open distance.json for reading");
      exit(1);
    }

    nlohmann::json distanceJson;
    distanceFile >> distanceJson;

    if (!distanceJson.is_object()) {
      BULLSEYE_DEBUG_FAIL("Invalid format in distance.json (expected object)");
      exit(1);
    }

    distanceMap.clear();
    for (auto it = distanceJson.begin(); it != distanceJson.end(); ++it) {
      if (it.value().is_number()) {
        distanceMap[it.key()] = it.value().get<double>();
      }
    }
  }

  inline std::string getLocString(llvm::BasicBlock* BB) {
    if (!BB) return "";

    llvm::Instruction* term = BB->getTerminator();
    if (!term) return "";

    llvm::DebugLoc DL = term->getDebugLoc();
    if (!DL) return "";

    std::ostringstream oss;
    oss << DL->getFilename().str() << ":" << DL.getLine();
    return oss.str();
  }

  inline void setLandmark(llvm::BasicBlock* BB) {
    std::string loc = getLocString(BB);
    if (!loc.empty()) {
      landmarkSet.insert(loc);
    }
  }

  inline bool isLandmark(llvm::BasicBlock* BB) {
    std::string loc = getLocString(BB);
    return !loc.empty() && landmarkSet.count(loc) > 0;
  }

  inline uint64_t getLandmarkCount() {
    return landmarkSet.size();
  }

  inline BBLocationToTarget getBBLocationToTarget(llvm::Instruction* I){
    if(llvm::MDNode* N = I->getMetadata(BULLSEYE_BB_LOCATION_TO_TARGET_MDNODE_KEY)){
      std::string str_value = llvm::cast<llvm::MDString>(N->getOperand(0))->getString().str();
      return static_cast<BBLocationToTarget>(std::atoi(str_value.c_str()));
    }
    return External;
  }

  inline BBLocationToTarget getBBLocationToTarget(llvm::BasicBlock* BB){
    return getBBLocationToTarget(BB->getTerminator());
  }

  inline void setBBLocationToTarget(llvm::Instruction* I, BBLocationToTarget bbLoc){
    llvm::LLVMContext& C = I->getContext();
    llvm::MDNode* N = llvm::MDNode::get(C, llvm::MDString::get(C, std::to_string(bbLoc)));
    I->setMetadata(BULLSEYE_BB_LOCATION_TO_TARGET_MDNODE_KEY, N);
  }

  inline void setBBLocationToTarget(llvm::BasicBlock* BB, BBLocationToTarget bbLoc){
    setBBLocationToTarget(BB->getTerminator(), bbLoc);
  }

  inline void setBBDistance(llvm::BasicBlock* BB, double distance) {
    std::string loc = getLocString(BB);
    if (loc.empty()) {
      return;
    }

    if (distance == 0.0) {
      distanceMap.erase(loc);  // Remove if zero
    } else {
      distanceMap[loc] = distance;
    }
  }

  inline double getBBDistance(llvm::BasicBlock* BB) {
    std::string loc = getLocString(BB);
    auto it = distanceMap.find(loc);
    if (it == distanceMap.end()) {
      return 0.0;
    }
    return it->second;
  }

  inline void setConstraintType(llvm::Instruction* I, ConstraintType ct){
    llvm::LLVMContext& C = I->getContext();
    llvm::MDNode* N = llvm::MDNode::get(C, llvm::MDString::get(C, std::to_string(ct)));
    I->setMetadata(BULLSEYE_CONSTRAINT_MDNODE_KEY, N);
  }

  inline ConstraintType getConstraintType(llvm::Instruction* I){
    if(llvm::MDNode* N = I->getMetadata(BULLSEYE_CONSTRAINT_MDNODE_KEY)){
      std::string str_value = llvm::cast<llvm::MDString>(N->getOperand(0))->getString().str();
      return static_cast<ConstraintType>(std::atoi(str_value.c_str()));
    }
    return NotAConstraint;
  }

  inline void setConstraintType(llvm::BasicBlock* BB, ConstraintType ct){
    setConstraintType(BB->getTerminator(), ct);
  }

  inline ConstraintType getConstraintType(llvm::BasicBlock* BB){
    return getConstraintType(BB->getTerminator());
  }

  inline std::string getConstraintTypeStr(llvm::Instruction* I){
    ConstraintType ct = getConstraintType(I);
    switch (ct) {
      case HardConstraint:
        return "HC";
      case SoftConstraint:
        return "SC";
      case NotAConstraint:
        return "NC";
    }
    return ""; // Added to avoid compiler warning
  }

  inline std::string getConstraintTypeStr(llvm::BasicBlock* BB){
    return getConstraintTypeStr(BB->getTerminator());
  }

  inline std::string getLLVMValueStr(const llvm::Value* V){
    std::string str;
    llvm::raw_string_ostream rawstr(str);
    if(V){
      if(const llvm::Function* F = llvm::dyn_cast<llvm::Function>(V))
        rawstr << " " << F->getName() << " ";
      else
        rawstr << " " << *V << " ";
    }
    return rawstr.str();
  }

  inline std::string getLLVMValueStr(llvm::Value* V){
    std::string str;
    llvm::raw_string_ostream rawstr(str);
    if(V){
      if(llvm::Function* F = llvm::dyn_cast<llvm::Function>(V))
        rawstr << " " << F->getName() << " ";
      else
        rawstr << " " << *V << " ";
    }
    return rawstr.str();
  }

  inline std::string getDebugLocString(llvm::Instruction* I){
    std::string locString = getLLVMValueStr(I);

    // do better if we can
    const llvm::DebugLoc& D = I->getDebugLoc();
    if (D) {
      std::string dDir = D->getDirectory().str();
      std::string dFilename = D->getFilename().str();
      std::string dLinenumber = std::to_string(D->getLine());
      locString = dDir + "/" + dFilename + ":" + dLinenumber;
    }
    return locString;
  }

  inline std::string getDebugLocString(llvm::BasicBlock* B){
    std::string locString = getLLVMValueStr(B);

    // do better if we can
    llvm::Instruction* I = B->getTerminator();
    const llvm::DebugLoc& D = I->getDebugLoc();
    if (D) {
      std::string dDir = D->getDirectory().str();
      std::string dFilename = D->getFilename().str();
      std::string dLinenumber = std::to_string(D->getLine());
      std::string dColnumber = std::to_string(D.getCol());
      locString = dDir + "/" + dFilename + ":" + dLinenumber + ":" + dColnumber;
    }
    return locString;
  }
}
