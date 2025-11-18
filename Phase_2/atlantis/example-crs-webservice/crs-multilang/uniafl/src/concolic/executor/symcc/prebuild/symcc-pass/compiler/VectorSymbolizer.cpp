#include "Symbolizer.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include <optional>

using namespace llvm;
#ifndef NDEBUG
#define DEBUG(X)                                                               \
  do {                                                                         \
    X;                                                                         \
  } while (false)
#else
#define DEBUG(X) ((void)0)
#endif

// Vector constants must be symbolized as bit-vectors even when vectorization
// symbolization is disabled, because insert/extractelement instructions operate
// on individual scalar elements and still require access to the original vector
// as a constant operand. Without constant BV representations, short circuiting
// vector operands would fail as there is no 'concrete case'.
ValueExpression
Symbolizer::createValueExpressionForVectors(Value *V, VectorType *vectorType,
                                            IRBuilder<> &IRB) {

  // Vectors are handled like arrays, but we need to take care of the
  // padding between the elements.
  auto *elementType = vectorType->getElementType();
  ElementCount elementCount = vectorType->getElementCount();
  if (elementCount.isScalable()) {
    // not implemented yet
    report_fatal_error("Scalable vectors are not supported yet");
    return ValueExpression(nullptr, nullptr);
  } else {
    auto *constantVectorValue = dyn_cast<ConstantDataVector>(V);
    size_t elementSizeInBits = elementType->getPrimitiveSizeInBits();
    size_t elementCount = vectorType->getElementCount().getKnownMinValue();
    Value *symArray = constructEmptyVector(IRB, elementType, elementCount);
    FixedVectorType *fixedVectorType = dyn_cast<FixedVectorType>(vectorType);
    size_t numElements = fixedVectorType->getNumElements();
    for (size_t i = 0; i < numElements; i++) {
      auto element = constantVectorValue
                         ? constantVectorValue->getElementAsConstant(i)
                         : IRB.CreateExtractElement(V, i);
      auto valueExpr = createValueExpression(element, IRB);
      auto elementExpr = valueExpr.value;

      // don't convert FP to bits
      symArray = IRB.CreateCall(runtime.buildInsertElement,
                                {symArray, elementExpr, IRB.getInt64(i)});
    }
    return ValueExpression(symArray, IRB.GetInsertBlock());
  }
}

void Symbolizer::handleVectorSelectInst(SelectInst &I, VectorType *vectorType) {
#ifdef SYMBOLIZE_VECTORS
  if ((!getSymbolicExpression(I.getTrueValue())) &&
      (!getSymbolicExpression(I.getFalseValue())) &&
      (!getSymbolicExpression(I.getCondition()))) {
    return;
  }
  if (auto *fixedVectorType = dyn_cast<FixedVectorType>(vectorType)) {
    handleFixedVectorSelectInst(I, fixedVectorType);
  } else if (auto *scalableVectorType =
                 dyn_cast<ScalableVectorType>(vectorType)) {
    handleScalableVectorSelectInst(I, scalableVectorType);
  } else {
    llvm_unreachable("Unknown vector type");
  }
#else
  return;
#endif
}

void Symbolizer::handleFixedVectorSelectInst(SelectInst &I,
                                             FixedVectorType *vectorType) {
#ifdef SYMBOLIZE_VECTORS
  IRBuilder<> IRB(&I);
  auto *elementType = vectorType->getElementType();
  auto elementSize = elementType->getPrimitiveSizeInBits() / 8;
  assert(elementType == IRB.getInt1Ty() && elementSize == 1 &&
         "SelectInst condition is a vector whose elements are not boolean");
  auto elementCount = vectorType->getElementCount();
  assert(elementCount.isFixed() &&
         "SelectInst condition is a vector whose element count is not fixed");
  auto numElements = elementCount.getFixedValue();
  auto *conditionArray = IRB.CreateAlloca(
      IRB.getInt8Ty(), IRB.getInt32(numElements), "conditionArray");
  for (size_t i = 0; i < numElements; ++i) {
    auto *conditionElement = IRB.CreateExtractElement(
        I.getCondition(), IRB.getInt32(i), "conditionElement");
    auto *storeCondition = IRB.CreateStore(
        IRB.CreateBitCast(conditionElement, IRB.getInt8Ty()),
        IRB.CreateGEP(IRB.getInt8Ty(), conditionArray, {IRB.getInt32(i)}),
        true);
    storeCondition->setMetadata(LLVMContext::MD_alias_scope,
                                MDNode::get(IRB.getContext(), {}));
  }
  auto elementSizeInBits = elementType->getPrimitiveSizeInBits();
  auto result = buildRuntimeCall(IRB, runtime.buildVectorSelect,
                                 {
                                     {I.getCondition(), true},
                                     {conditionArray, false},
                                     {I.getTrueValue(), true},
                                     {I.getFalseValue(), true},
                                     {IRB.getInt8(numElements), false},
                                     {IRB.getInt8(elementSizeInBits), false},
                                 });
  registerSymbolicComputation(result, &I);
#else
  return;
#endif
}

void Symbolizer::handleScalableVectorSelectInst(
    SelectInst &I, ScalableVectorType *vectorType) {
  llvm_unreachable("not implemented yet");
}

void Symbolizer::visitExtractElementInst(ExtractElementInst &I) {
  DEBUG(errs() << "[Symbolizer::visitExtractValueInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  auto target = I.getOperand(0);
  Value *index = IRB.CreateZExtOrBitCast(I.getIndexOperand(), IRB.getInt64Ty());
  auto extracted = buildRuntimeCall(IRB, runtime.buildExtractElement,
                                    {
                                        {target, true},
                                        {index, false},
                                    });
  if (!extracted.has_value()) {
    // This implies extraction of constant vector. No need to continue
    return;
  }
  Type *elementType = I.getType();
  // We don't need bitsToFloat conversion here
  registerSymbolicComputation(extracted, &I);
}

void Symbolizer::visitInsertElementInst(InsertElementInst &I) {
  DEBUG(errs() << "[Symbolizer::visitInsertValueInst] " << I << '\n');
  IRBuilder<> IRB(&I);
  Value *target = I.getOperand(0);
  VectorType *vectorType = dyn_cast<VectorType>(target->getType());
  Value *element = I.getOperand(1);
  // TODO: should we make this symbolic? Right now, it's concrete
  Value *index = IRB.CreateZExtOrBitCast(I.getOperand(2), IRB.getInt64Ty());
  auto newVector = buildRuntimeCall(IRB, runtime.buildInsertElement,
                                    {
                                        {target, true},
                                        {element, true},
                                        {index, false},
                                    });
  registerSymbolicComputation(newVector, &I);
}

void Symbolizer::visitShuffleVectorInst(ShuffleVectorInst &I) {
  // shufflevector is scalarized, so no need to implement instrumentation
  return;
}

Value *Symbolizer::constructEmptyVector(IRBuilder<> &IRB, Type *elementType,
                                        size_t elemCnt) {
  Value *symArray;
  uint64_t elementSizeInBits = elementType->getPrimitiveSizeInBits();
  if (elementType->isIntegerTy()) {
    // If the vector is a constant integer vector, we can create a symbolic
    // array directly.
    symArray = IRB.CreateCall(
        runtime.buildSymbolicArrayInt,
        {IRB.getInt64(elemCnt), IRB.getInt64(elementSizeInBits)});
  } else if (elementType->isFloatingPointTy()) {
    // For other types, we need to create a symbolic array of bytes.
    symArray = IRB.CreateCall(
        runtime.buildSymbolicArrayFP,
        {IRB.getInt64(elemCnt), IRB.getInt1(elementType->isDoubleTy())});
  } else {
    report_fatal_error("Unsupported vector type for symbolic expression");
  }
  return symArray;
}

void Symbolizer::loadVectorFromMemory(LoadInst *LI, VectorType *vectorType) {

  // need to set insertion point to be after the load instruction
  IRBuilder<> IRB(LI->getNextNode());
  auto *elementType = vectorType->getElementType();
  ElementCount elementCount = vectorType->getElementCount();
  // must be integer value because we are calling _sym_read_memory
  Value *memoryBase = LI->getPointerOperand();

  if (elementCount.isScalable()) {
    // not implemented yet
    report_fatal_error("Scalable vectors are not supported yet");
  } else {
    size_t elementSizeInBits = elementType->getPrimitiveSizeInBits();
    size_t elementCountInt = elementCount.getKnownMinValue();
    Value *symArray = constructEmptyVector(IRB, elementType, elementCountInt);

    Type *analagousArrayTy =
        ArrayType::get(vectorType->getElementType(), elementCountInt);
    for (size_t i = 0; i < elementCountInt; i++) {
      Instruction *elementExpr = nullptr;
      Value *addr = nullptr;
      switch (elementSizeInBits) {
      case 1: {
        Value *byteOffset = IRB.getInt64(i / 8);
        Value *bitOffset = IRB.getInt64(7 - i % 8);
        addr = IRB.CreatePtrToInt(
            IRB.CreateGEP(IRB.getInt8Ty(), memoryBase, byteOffset),
            IRB.getInt64Ty());
        elementExpr = IRB.CreateCall(runtime.readMemory,
                                     {addr, IRB.getInt64(1), IRB.getInt1(0)});

        elementExpr = IRB.CreateCall(runtime.extractHelper,
                                     {elementExpr, bitOffset, bitOffset});
        break;
      }
      case 8:
      case 16:
      case 32:
      case 64: {
        Value *offset = IRB.getInt64(i * (elementSizeInBits / 8));
        addr = IRB.CreatePtrToInt(
            IRB.CreateGEP(IRB.getInt8Ty(), memoryBase, offset),
            IRB.getInt64Ty());
        elementExpr =
            IRB.CreateCall(runtime.readMemory,
                           {addr, IRB.getInt64(elementSizeInBits / 8),
                            IRB.getInt1(isLittleEndian(elementType) ? 1 : 0)});
        if (elementType->isFloatingPointTy()) {
          // we need conversion here to match store vector
          elementExpr = IRB.CreateCall(
              runtime.buildBitsToFloat,
              {elementExpr, IRB.getInt1(elementType->isDoubleTy())});
        }
        break;
      }
      default: {
        std::string errorMessage =
            "Unsupported element size: " + std::to_string(elementSizeInBits);
        report_fatal_error(errorMessage.c_str());
        break;
      }
      }

      // Add element to the symbolic array
      // TODO: need to short circuit this path. If elementExpr is nullptr,
      // the return value will also be nullptr

      Value *cond = IRB.CreateICmpEQ(
          elementExpr, Constant::getNullValue(elementExpr->getType()));
      CallInst *updateInst = IRB.CreateCall(
          runtime.buildInsertElement, {symArray, elementExpr, IRB.getInt64(i)});
      Instruction *thenBlockInsertionPt =
          SplitBlockAndInsertIfThen(cond, updateInst, false);

      // Insert the short circuted path
      IRB.SetInsertPoint(thenBlockInsertionPt);
      // we use this instead of IRB.CreateExtractElement to ensure this
      // instruction is located within the basic block of thenBlockInsertionPt
      ValueExpression elementConcrete = createValueExpression(
          IRB.CreateExtractElement(LI, IRB.getInt64(i)), IRB);

      // Convert elementExpr into a phinode
      IRB.SetInsertPoint(updateInst);
      PHINode *newArg = IRB.CreatePHI(IRB.getInt8Ty()->getPointerTo(), 2);
      newArg->addIncoming(elementConcrete.value, elementConcrete.incoming);
      newArg->addIncoming(elementExpr, elementExpr->getParent());
      updateInst->setArgOperand(1, newArg);
      symArray = updateInst;

      // after dealing with everything, set the insertion point
      // to the next block
      IRB.SetInsertPoint(updateInst->getNextNode());
    }

    // Register the symbolic expression for the entire vector load. But DON't
    // create a symbolic computation entry.
    symbolicExpressions[LI] = symArray;
  }
}

void Symbolizer::storeVectorToMemory(StoreInst *SI, VectorType *vectorType) {
  IRBuilder<> IRB(SI);
  auto *elementType = vectorType->getElementType();
  ElementCount elementCount = vectorType->getElementCount();
  // must be integer value because we are calling _sym_write_memory
  Value *memoryBase = SI->getPointerOperand();
  Value *vectorExpr = symbolicExpressions[SI->getValueOperand()];
  // NOTE: return if vectorExpr is nullptr. Short circuiting does not handle
  // memory loads/stores because they are not treated as symbolic computations.
  if (vectorExpr == nullptr) {
    return;
  }
  if (elementCount.isScalable()) {
    // not implemented yet
    report_fatal_error("Scalable vectors are not supported yet");
  } else {
    size_t elementSizeInBits = elementType->getPrimitiveSizeInBits();
    size_t elementCountInt = elementCount.getKnownMinValue();
    for (size_t i = 0; i < elementCountInt; i++) {
      Value *elementExpr;
      Value *addr;
      // vectorExpr may be nullptr (i.e. return value of a function)
      // do we need to short circuit this?
      elementExpr = IRB.CreateCall(runtime.buildExtractElement,
                                   {vectorExpr, IRB.getInt64(i)});
      switch (elementSizeInBits) {
      case 1: {
        Value *byteOffset = IRB.getInt64(i / 8);
        Value *bitOffset = IRB.getInt64(i % 8);
        Value *temp;
        addr = IRB.CreatePtrToInt(
            IRB.CreateGEP(IRB.getInt8Ty(), memoryBase, byteOffset),
            IRB.getInt64Ty());
        // TODO: symbols are managed in byte-granularity, so if the byte read is
        // not symbolic, we need to force it to be symbolic, with something
        // similar to short circuiting
        temp = IRB.CreateCall(runtime.readMemory,
                              {addr, IRB.getInt64(1), IRB.getInt1(0)});
        switch (i % 8) {
        case 0: {
          temp = IRB.CreateCall(runtime.extractHelper, {
                                                           temp,
                                                           IRB.getInt64(6),
                                                           IRB.getInt64(0),

                                                       });
          temp = IRB.CreateCall(runtime.buildConcat, {
                                                         elementExpr,
                                                         temp,
                                                     });
          break;
        }
        case 7: {
          temp = IRB.CreateCall(runtime.extractHelper, {
                                                           temp,
                                                           IRB.getInt64(7),
                                                           IRB.getInt64(1),
                                                       });
          temp = IRB.CreateCall(runtime.buildConcat, {temp, elementExpr});
          break;
        }
        default: {
          Value *pt1 = IRB.CreateCall(runtime.extractHelper,
                                      {
                                          temp,
                                          IRB.getInt64(7),
                                          IRB.getInt64(8 - (i % 8)),
                                      });
          Value *pt2 = IRB.CreateCall(runtime.extractHelper,
                                      {
                                          temp,
                                          IRB.getInt64(6 - (i % 8)),
                                          IRB.getInt64(0),
                                      });
          temp = IRB.CreateCall(runtime.buildConcat, {pt1, elementExpr});
          temp = IRB.CreateCall(runtime.buildConcat, {temp, pt2});
          break;
        }
        }
        IRB.CreateCall(runtime.writeMemory,
                       {addr, IRB.getInt64(1), temp, IRB.getInt1(0)});
        break;
      }
      case 8:
      case 16:
      case 32:
      case 64: {
        Value *offset = IRB.getInt64(i * (elementSizeInBits / 8));
        addr = IRB.CreatePtrToInt(
            IRB.CreateGEP(IRB.getInt8Ty(), memoryBase, offset),
            IRB.getInt64Ty());
        if (elementType->isFloatingPointTy()) {
          elementExpr = IRB.CreateCall(runtime.buildFloatToBits, {elementExpr});
        }
        IRB.CreateCall(runtime.writeMemory,
                       {addr, IRB.getInt64(elementSizeInBits / 8), elementExpr,
                        IRB.getInt1(isLittleEndian(elementType) ? 1 : 0)});
        break;
      }
      default: {
        std::string errorMessage =
            "Unsupported element size: " + std::to_string(elementSizeInBits);
        report_fatal_error(errorMessage.c_str());
        break;
      }
      }

      // Write the element to memory
      IRB.CreateCall(runtime.writeMemory,
                     {addr, IRB.getInt64(elementSizeInBits / 8), elementExpr,
                      IRB.getInt1(isLittleEndian(elementType) ? 1 : 0)});
    }
  }
}

void Symbolizer::bitcastToVector(BitCastInst *I, VectorType *vectorType) {
  Function *F = I->getFunction();
  IRBuilder<> IRB(&F->getEntryBlock(), F->getEntryBlock().begin());
  Value *ptr = IRB.CreateAlloca(vectorType);
  IRB.SetInsertPoint(I);
  IRB.CreateCall(
      runtime.writeMemory,
      {IRB.CreatePtrToInt(ptr, IRB.getInt64Ty()),
       IRB.getInt64(I->getType()->getPrimitiveSizeInBits() / 8),
       symbolicExpressions[I->getOperand(0)],
       IRB.getInt1(isLittleEndian(vectorType->getElementType()) ? 1 : 0)});
  LoadInst *LI = IRB.CreateLoad(vectorType, ptr, true);
  loadVectorFromMemory(LI, vectorType);
  symbolicExpressions[I] = symbolicExpressions[LI];
}

void Symbolizer::bitcastFromVector(BitCastInst *I, VectorType *vectorType) {
  Function *F = I->getFunction();
  IRBuilder<> IRB(&F->getEntryBlock(), F->getEntryBlock().begin());
  Value *ptr = IRB.CreateAlloca(vectorType);
  IRB.SetInsertPoint(I);
  StoreInst *SI = IRB.CreateStore(I->getOperand(0), ptr, true);
  storeVectorToMemory(SI, vectorType);
  Value *expr = IRB.CreateCall(
      runtime.readMemory,
      {IRB.CreatePtrToInt(ptr, IRB.getInt64Ty()),
       IRB.getInt64(I->getType()->getPrimitiveSizeInBits() / 8),
       IRB.getInt1(isLittleEndian(vectorType->getElementType()) ? 1 : 0)});
  symbolicExpressions[I] = expr;
}

void Symbolizer::bitcastFromVectorToVector(BitCastInst *I, VectorType *srcType,
                                           VectorType *dstType) {
  // TODO: remove this function. scalarizer will take care of bitcast btwn
  // vector and scalar
  Function *F = I->getFunction();
  IRBuilder<> IRB(&F->getEntryBlock(), F->getEntryBlock().begin());
  Value *ptr = IRB.CreateAlloca(srcType);
  IRB.SetInsertPoint(I);
  StoreInst *SI = IRB.CreateStore(I->getOperand(0), ptr, true);
  storeVectorToMemory(SI, srcType);
  LoadInst *LI = IRB.CreateLoad(dstType, ptr, true);
  loadVectorFromMemory(LI, dstType);
  symbolicExpressions[I] = symbolicExpressions[LI];
}
