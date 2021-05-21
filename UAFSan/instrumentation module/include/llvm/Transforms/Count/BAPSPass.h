//
// Created by a on 5/3/20.
//

#ifndef LLVM_BAPSPASS_H
#define LLVM_BAPSPASS_H

#include "algorithm"
#include "cstdarg"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/FoldingSet.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/CallingConv.h"
#include "llvm/IR/Constant.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GetElementPtrTypeIterator.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Compiler.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/ManagedStatic.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include <llvm/Analysis/LoopInfo.h>
#include <llvm/Analysis/TargetLibraryInfo.h>
#include <llvm/IR/Dominators.h>
#include <llvm/IR/IRBuilder.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/Transforms/Utils/ModuleUtils.h>
#include <map>

#include "llvm-c/Target.h"
#include "llvm-c/TargetMachine.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"

#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/ADT/StringMap.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/Dominators.h"

#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"

#include "llvm/Analysis/TargetFolder.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/Support/SpecialCaseList.h"

#include <queue>

using namespace llvm;

namespace llvm {
struct BAPS : public ModulePass {
private:
  bool DEBUG;
  const DataLayout *DL;
  const TargetLibraryInfo *TLI;
  LLVMContext *C;
  SmallString<64> BlacklistFile; // we need to implement t it later

  Function *m_baps_access_shadow_metadata;
  Function *m_baps_pointer_dereference_check;

  Function *m_baps_print_shadow_metadata;
  Function *m_baps_store_malloc_back_trace;
  Function *m_baps_store_free_back_trace;
  Function *m_baps_store_use_back_trace;
  Function *m_baps_store_backtrace_metadata;
  Function *m_baps_print_malloc_back_trace;
  Function *m_baps_print_free_back_trace;
  Function *m_baps_print_use_back_trace;
  Function *m_baps_abort;
  Function *m_get_unique_id;

  Function *m_baps_allocate_shadow_stack_space;
  Function *m_baps_deallocate_shadow_stack_space;

  Function *m_baps_shadow_stack_pointer_load_obj;
  Function *m_baps_shadow_stack_pointer_load_size;
  Function *m_baps_shadow_stack_pointer_load_unique_id;

  Function *m_baps_shadow_stack_pointer_store_obj;
  Function *m_baps_shadow_stack_pointer_store_size;
  Function *m_baps_shadow_stack_pointer_store_unique_id;

  Function *m_baps_shadow_stack_store_return_metadata;
  Function *m_baps_shadow_stack_store_null_return_metadata;
  Function *m_baps_propagate_shadow_stack_pointer_metadata;

  Function *m_baps_introspect_metadata;
  Function *m_baps_copy_metadata;

  Function *m_baps_store_trie_pointer_metadata;
  Function *m_baps_load_trie_pointer_metadata_obj;
  Function *m_baps_load_trie_pointer_metadata_size;
  Function *m_baps_load_trie_pointer_metadata_unique_id;

  Function *m_baps_malloc_shadow_metadata;
  Function *m_baps_free_shadow_metadata;

  /**
   * Some pointer types, such as void pointer type, size_t pointer type
   */

  Type *m_void_ptr_type;
  Type *m_size_t_ptr_type;

  ConstantPointerNull *m_void_null_ptr;
  ConstantPointerNull *m_size_t_null_ptr;

  Type *m_unique_id_type;

  Constant *m_constant_two;
  Constant *m_constant_one;
  Constant *m_constant_zero;

  Constant *m_constant_int32ty_two;
  Constant *m_constant_int32ty_one;
  Constant *m_constant_int32ty_zero;
  Constant *m_constant_int64ty_two;
  Constant *m_constant_int64ty_one;
  Constant *m_constant_int64ty_zero;

  DominatorTreeWrapperPass *m_dominator_tree;

  /* Book-keeping structures for identifying original instructions in
   * the program, pointers and their corresponding begin, end and unique_id
   */

  std::map<Value *, Value *> m_pointer_begin;
  std::map<Value *, Value *> m_pointer_end;
  std::map<Value *, Value *> m_pointer_obj_id;
  std::map<Value *, Value *> m_pointer_obj_addr;
  std::map<Value *, int> m_inst_present_in_original;
  std::map<Value *, int> m_global_variables;
  /**
   * m_func_can_transform records all functions that can be transformed
   */
  StringMap<bool> m_func_can_transform;
  /**
   * m_func_to_transform records all functions that need to be transformed
   * because they have pointer arguments or pointer return types,
   * and defines all functions that need to be transformed in the module.
   */
  StringMap<bool> m_func_to_transform;
  /**
   * m_func_transformed records all functions that have been transformed
   */
  StringMap<bool> m_func_transformed;
  StringMap<Value *> m_func_global_lock;
  /* Map of all functions defined by baps */
  StringMap<bool> m_func_defined_by_baps;
  StringMap<bool> m_func_wrapped_by_baps;

  /**
   *  Identify whether the LLVM-generated bitcode is suitable for 64-bit
   * machines
   */
  bool m_machine_is_64_bit;

  /**
   * Most of the features are implemented for BAPS functionality.
   */
  void declareCheckManipulationFunctions(Module &module);

  void declareMetadataManipulationFunctions(Module &module);

  void declareShadowStackManipulateFunctions(Module &module);

  void declareAuxiliaryManipulationFunctions(Module &module);

  void declareDiagInfoFunctions(Module &module);

  bool runOnModule(Module &module);

  void initializeBAPSVariables(Module &module);

  void identifyMachineEnvironment(const Module &module);

  void identifyAndRenameMainFunction(Module &module);

  void renameWrappedFunctions(Module &module);

  std::string getRenamedFunctionName(const std::string &str);

  void renameFunctionName(Function *function, Module &module, bool isExternal);

  bool isFuncDefByBAPS(const std::string &str);

  bool hasPtrRetArgType(Function *function);

  void identifyFunctionToTransform(Module &module);

  void identifyAndHandleGlobalVariables(Module &module);

  void handleGlobalVariables(Module &module);

  void identifyGlobalVariables(Module &module);

  void obtainGlobalVariablesScope(GlobalVariable *globalVariable, Value *&begin,
                                  Value *&end);

  void handleGlobalStructTypeInitializer(Module &module,
                                         GlobalVariable *globalVariable);

  void handleGlobalSequentialTypeInitializer(Module &module,
                                             GlobalVariable *globalVariable);

  void insertMetadataStores(Value *pointer, Value *obj_addr, Value *size,
                            Value *obj_id, Instruction *insert_at);

  Instruction *getGlobalInitInst(Module &module);

  bool isTargetFunction(Function *function);

  void identifyOriginalInst(Function *function);

  Value *castToVoidPtr(Value *operand, Instruction *insert_at);

  bool isAllocaPresent(Function *function);

  void identifyPtrAndPropagateIt(Function *function);

  void introduceDereferenceCheck(Function *function);

  void introduceLoadInstCheck(Instruction *inst,
                              std::map<Value *, int> &bbCheckOptMap);

  void introduceStoreInstCheck(Instruction *inst,
                               std::map<Value *, int> &bbCheckOptMap);

  void introduceCallInstCheck(Instruction *inst,
                              std::map<Value *, int> &bbCheckOptMap);

  bool optimizeLoadInstPtrVariableCheck(Instruction *inst);

  bool optimizeStoreInstPtrVariableCheck(Instruction *inst);

  bool optimizeBasicBlockCheck(Instruction *inst,
                               std::map<Value *, int> &bbOptMap);

  Value *getPointerLoadOrStore(Instruction *inst);

  bool checkArgsHasPtrType(Argument *argument);

  bool checkPtrsInStructType(StructType *structType);

  void associateBaseBound(Value *pointerOperand, Value *begin, Value *end);

  void disassociateBaseBound(Value *pointerOperand);

  void associateObjIdAndAddr(Value *pointerOperand, Value *unique_id, Value *obj_addr);

  void disassociateObjIdAndAddr(Value *pointerOperand);

  void introduceShadowStackLoads(Value *value, Instruction *insertAt,
                                 int argCount);

  void introduceShadowStackStores(Value *value, Instruction *insertAt,
                                  int argCount);

  void introduceShadowStackAllocation(CallInst *callInst);

  void introduceShadowStackDeallocation(CallInst *callInst,
                                        Instruction *insertAt);

  void iterateCallSiteIntroduceShadowStackStores(CallInst *callInst);

  void getLocalObjId(Function *function, Value *&unique_id);

  void freeLocalObjId(Function *function, Value *&unique_id);

  void addMemoryAllocationCall(Function *function, Value *&unique_id,
                               Instruction *insertAt);

  /* Specific LLVM instruction handlers in the bitcode */
  void handleAlloca(AllocaInst *allocaInst);

  void handleLoad(LoadInst *loadInst);

  void insertMetadataLoads(LoadInst *loadInst);

  void handleGEP(GetElementPtrInst *getElementPtrInst);

  void handleBitCast(BitCastInst *bitCastInst);

  void handlePHINode(PHINode *phiNode);

  void handlePHINodeAgain(PHINode *phiNode);

  void handleCall(CallInst *callInst);

  void handleMemcpy(CallInst *callInst);

  void handleSelect(SelectInst *selectInst);

  void handleIntToPtr(IntToPtrInst *intToPtrInst);

  void handleRetInst(ReturnInst *returnInst);

  void handleExtractElement(ExtractElementInst *extractElementInst);

  void handleExtractValue(ExtractValueInst *extractValueInst);

  void handleStore(StoreInst *storeInst);

  void handleInvoke(InvokeInst *invokeInst);

  void propagateMetadata(Value *pointerOperand, Instruction *inst);

  Value *getAssociatedObjId(Value *pointerOperand);

  Value* getAssociatedObjAddr(Value*pointerOperand);

  void getConstantExprBaseBound(Constant *constant, Value *&begin, Value *&end);

  bool checkObjAddrMetadataPresent(Value *inst);

  bool checkUniqueIdMetadataPresent(Value *inst);

  Instruction *getNextInstruction(Instruction *instruction);

  int getNumOfPtrArgsAndReturn(CallInst *callInst);

  bool checkLoadStoreSourceIsGEP(Instruction *loadOrStoreInst,
                                 Value *gepSource);

public:
  static char ID;

  BAPS() : ModulePass(ID) { DEBUG = true; }

  StringRef getPassName() const { return "BAPS"; }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<TargetLibraryInfoWrapperPass>();
  }
  void handleFunctionWithPtrArgs(Function *function);
  void handleFunctionBodyAgain(Function *function);
  void handleFunctionBody(Function *function);
};

ModulePass *createBAPSPass();
} // namespace llvm

#endif // LLVM_BAPSPASS_H
