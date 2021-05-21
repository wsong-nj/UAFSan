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
#include "llvm/Transforms/Count/BAPSPass.h"
#include <queue>

using namespace llvm;

#define DEBUG_MSG(err) err

char BAPS::ID = 0;

bool BAPS::runOnModule(Module &module) {
  //  DEBUG_MSG(errs() << getPassName() << '\n');
  /**
   * Introduces function declarations related to BAPS
   */
  declareCheckManipulationFunctions(module);
  declareShadowStackManipulateFunctions(module);
  declareMetadataManipulationFunctions(module);
  declareAuxiliaryManipulationFunctions(module);
  declareDiagInfoFunctions(module);

  /**
   * Identify Machine Environment
   */
  identifyMachineEnvironment(module);

  /**
   * Initialize BAPS variables
   */
  initializeBAPSVariables(module);

  /**
   * The name of the main function is renamed with baps_pseudo_main
   */
  identifyAndRenameMainFunction(module);

  /**
   * Identify Functions need to transform
   */
  identifyFunctionToTransform(module);

  /**
   * Identify and Handle Global Variables
   */
  identifyAndHandleGlobalVariables(module);

  /**
   * Find the instructions we are interested in and instrument the code
   */
  for (Module::iterator fi = module.begin(); fi != module.end(); ++fi) {
    Function *function = dyn_cast<Function>(fi);
    assert(function && "function ptr is null?");

    if (!isTargetFunction(function)) {
      continue;
    }
    identifyOriginalInst(function);
    identifyPtrAndPropagateIt(function);
    introduceDereferenceCheck(function);
  }
  /**
   * Rename Wrapped Functions
   */
  renameWrappedFunctions(module);

  //  DEBUG_MSG(errs() << getPassName() << '\n');
  return true;
}

void BAPS::identifyMachineEnvironment(const Module &module) {
  C = &module.getContext();
  DL = &module.getDataLayout();
  TLI = &getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();
  IRBuilder<> IRB(*C);
  if (DL->getPointerSize() == 8) {
    m_machine_is_64_bit = true;
  } else {
    m_machine_is_64_bit = false;
  }
}

void BAPS::declareCheckManipulationFunctions(Module &module) {
  Type *VoidType = Type::getVoidTy(module.getContext());
  Type *VoidPtrType =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  Type *SizeType = Type::getInt64Ty(module.getContext());
  Type *Int32Type = Type::getInt32Ty(module.getContext());
  Type *PtrVoidPtrType = PointerType::getUnqual(VoidPtrType);
  module.getOrInsertFunction("baps_access_shadow_metadata", SizeType,
                             VoidPtrType);
  module.getOrInsertFunction("baps_pointer_dereference_check", VoidType,
                             VoidPtrType, SizeType, VoidPtrType);

  module.getOrInsertFunction("baps_print_shadow_metadata", VoidType,
                             VoidPtrType, SizeType);
  module.getOrInsertFunction("baps_store_malloc_back_trace", VoidType,
                             SizeType);
  module.getOrInsertFunction("baps_store_free_back_trace", VoidType, SizeType);
  module.getOrInsertFunction("baps_store_use_back_trace", VoidType, SizeType);
  module.getOrInsertFunction("baps_store_backtrace_metadata", VoidType,
                             SizeType, Int32Type);
  module.getOrInsertFunction("baps_print_malloc_back_trace", VoidType,
                             SizeType);
  module.getOrInsertFunction("baps_print_free_back_trace", VoidType, SizeType);
  module.getOrInsertFunction("baps_print_use_back_trace", VoidType, SizeType);

  module.getOrInsertFunction("baps_abort", VoidType);
}

void BAPS::declareShadowStackManipulateFunctions(Module &module) {
  Type *VoidType = Type::getVoidTy(module.getContext());
  Type *VoidPtrType =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  Type *SizeType = Type::getInt64Ty(module.getContext());
  Type *Int32Type = Type::getInt32Ty(module.getContext());
  module.getOrInsertFunction("baps_allocate_shadow_stack_space", VoidType,
                             Int32Type);
  module.getOrInsertFunction("baps_deallocate_shadow_stack_space", VoidType);
  /**
   * load from shadow stack
   */
  module.getOrInsertFunction("baps_shadow_stack_pointer_load_obj", VoidPtrType,
                             Int32Type);
  module.getOrInsertFunction("baps_shadow_stack_pointer_load_size", SizeType,
                             Int32Type);
  module.getOrInsertFunction("baps_shadow_stack_pointer_load_unique_id",
                             SizeType, Int32Type);
  /**
   * store into shadow stack
   */
  module.getOrInsertFunction("baps_shadow_stack_pointer_store_obj", VoidType,
                             VoidPtrType, Int32Type);
  module.getOrInsertFunction("baps_shadow_stack_pointer_store_size", VoidType,
                             SizeType, Int32Type);
  module.getOrInsertFunction("baps_shadow_stack_pointer_store_unique_id",
                             VoidType, SizeType, Int32Type);
  /**
   * store callee function returned metadata
   */
  module.getOrInsertFunction("baps_shadow_stack_store_return_metadata",
                             VoidType, VoidPtrType, SizeType, SizeType);
  //    module.getOrInsertFunction("baps_shadow_stack_store_null_return_metadata",
  //    VoidType, VoidType);
  module.getOrInsertFunction("baps_shadow_stack_store_null_return_metadata",
                             VoidType);
  module.getOrInsertFunction("baps_propagate_shadow_stack_pointer_metadata",
                             VoidType, Int32Type, Int32Type);
}

void BAPS::declareMetadataManipulationFunctions(Module &module) {
  Type *VoidType = Type::getVoidTy(module.getContext());
  Type *VoidPtrType =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  Type *SizeType = Type::getInt64Ty(module.getContext());
  Type *Int32Type = Type::getInt32Ty(module.getContext());
  Type *PtrVoidPtrType = PointerType::getUnqual(VoidPtrType);
  module.getOrInsertFunction("baps_introspect_metadata", VoidType, VoidPtrType,
                             SizeType, SizeType);
  module.getOrInsertFunction("baps_copy_metadata", VoidType, VoidPtrType,
                             VoidPtrType, SizeType);

  module.getOrInsertFunction("baps_store_trie_pointer_metadata", VoidType,
                             VoidPtrType, VoidPtrType, SizeType, SizeType);
  module.getOrInsertFunction("baps_load_trie_pointer_metadata_obj", VoidPtrType,
                             VoidPtrType);
  module.getOrInsertFunction("baps_load_trie_pointer_metadata_size", SizeType,
                             VoidPtrType);
  module.getOrInsertFunction("baps_load_trie_pointer_metadata_unique_id",
                             SizeType, VoidPtrType);

  module.getOrInsertFunction("baps_malloc_shadow_metadata", VoidType,
                             VoidPtrType, SizeType);
  module.getOrInsertFunction("baps_free_shadow_metadata", VoidType, VoidPtrType,
                             SizeType);
}

void BAPS::declareAuxiliaryManipulationFunctions(Module &module) {
  Type *VoidType = Type::getVoidTy(module.getContext());
  Type *VoidPtrType =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  Type *SizeType = Type::getInt64Ty(module.getContext());
  Type *Int32Type = Type::getInt32Ty(module.getContext());
  Type *PtrVoidPtrType = PointerType::getUnqual(VoidPtrType);
  module.getOrInsertFunction("baps_init", VoidType);
  module.getOrInsertFunction("generateUniqueID", SizeType);
}

void BAPS::declareDiagInfoFunctions(Module &module) {}

/**
 * function name: initializeBAPSVariables()
 *
 * Description:
 * This function is used to initialize all the Function * m_'s that will be
 * inserted by BAPS
 *
 * Input:
 * module: Input module that will has either the function definitions or
 * declaritions for the BAPS functions
 */
void BAPS::initializeBAPSVariables(Module &module) {
  m_baps_access_shadow_metadata =
      module.getFunction("baps_access_shadow_metadata");
  assert(m_baps_access_shadow_metadata &&
         "baps_access_shadow_metadata function type null ?");
  m_baps_pointer_dereference_check =
      module.getFunction("baps_pointer_dereference_check");
  assert(m_baps_pointer_dereference_check &&
         "baps_pointer_dereference_check function type null ?");

  m_baps_print_shadow_metadata =
      module.getFunction("baps_print_shadow_metadata");
  assert(m_baps_print_shadow_metadata &&
         "baps_print_shadow_metadata function type null ?");
  m_baps_store_malloc_back_trace =
      module.getFunction("baps_store_malloc_back_trace");
  assert(m_baps_store_malloc_back_trace &&
         "baps_store_malloc_back_trace function type null ?");
  m_baps_store_free_back_trace =
      module.getFunction("baps_store_free_back_trace");
  assert(m_baps_store_free_back_trace &&
         "baps_store_free_back_trace function type null ?");
  m_baps_store_use_back_trace = module.getFunction("baps_store_use_back_trace");
  assert(m_baps_store_use_back_trace &&
         "baps_store_use_back_trace function type null ?");
  m_baps_store_backtrace_metadata =
      module.getFunction("baps_store_backtrace_metadata");
  assert(m_baps_store_backtrace_metadata &&
         "baps_store_backtrace_metadata function type null ?");
  m_baps_print_malloc_back_trace =
      module.getFunction("baps_print_malloc_back_trace");
  assert(m_baps_print_malloc_back_trace &&
         "baps_print_malloc_back_trace function type null ?");
  m_baps_print_free_back_trace =
      module.getFunction("baps_print_free_back_trace");
  assert(m_baps_print_free_back_trace &&
         "baps_print_free_back_trace function type null ?");
  m_baps_print_use_back_trace = module.getFunction("baps_print_use_back_trace");
  assert(m_baps_print_use_back_trace &&
         "baps_print_use_back_trace function type null ?");
  m_baps_abort = module.getFunction("baps_abort");
  assert(m_baps_abort && "baps_abort function type null ?");
  m_get_unique_id = module.getFunction("generateUniqueID");
  assert(m_get_unique_id && "generateUniqueID function type null ?");

  m_baps_allocate_shadow_stack_space =
      module.getFunction("baps_allocate_shadow_stack_space");
  assert(m_baps_allocate_shadow_stack_space &&
         "baps_allocate_shadow_stack_space function type null ?");
  m_baps_deallocate_shadow_stack_space =
      module.getFunction("baps_deallocate_shadow_stack_space");
  assert(m_baps_deallocate_shadow_stack_space &&
         "baps_deallocate_shadow_stack_space function type null ?");

  m_baps_shadow_stack_pointer_load_obj =
      module.getFunction("baps_shadow_stack_pointer_load_obj");
  assert(m_baps_shadow_stack_pointer_load_obj &&
         "baps_shadow_stack_pointer_load_obj function type null ?");
  m_baps_shadow_stack_pointer_load_size =
      module.getFunction("baps_shadow_stack_pointer_load_size");
  assert(m_baps_shadow_stack_pointer_load_size &&
         "baps_shadow_stack_pointer_load_size function type null ?");
  m_baps_shadow_stack_pointer_load_unique_id =
      module.getFunction("baps_shadow_stack_pointer_load_unique_id");
  assert(m_baps_shadow_stack_pointer_load_unique_id &&
         "baps_shadow_stack_pointer_load_unique_id function type null ?");

  m_baps_shadow_stack_pointer_store_obj =
      module.getFunction("baps_shadow_stack_pointer_store_obj");
  assert(m_baps_shadow_stack_pointer_store_obj &&
         "baps_shadow_stack_pointer_store_obj function type null ?");
  m_baps_shadow_stack_pointer_store_size =
      module.getFunction("baps_shadow_stack_pointer_store_size");
  assert(m_baps_shadow_stack_pointer_store_size &&
         "baps_shadow_stack_pointer_store_size function type null ?");
  m_baps_shadow_stack_pointer_store_unique_id =
      module.getFunction("baps_shadow_stack_pointer_store_unique_id");
  assert(m_baps_shadow_stack_pointer_store_unique_id &&
         "baps_shadow_stack_pointer_store_unique_id function type null ?");

  m_baps_shadow_stack_store_return_metadata =
      module.getFunction("baps_shadow_stack_store_return_metadata");
  assert(m_baps_shadow_stack_store_return_metadata &&
         "baps_shadow_stack_store_return_metadata function type null ?");
  m_baps_shadow_stack_store_null_return_metadata =
      module.getFunction("baps_shadow_stack_store_null_return_metadata");
  assert(m_baps_shadow_stack_store_null_return_metadata &&
         "baps_shadow_stack_store_null_return_metadata function type null ?");
  m_baps_propagate_shadow_stack_pointer_metadata =
      module.getFunction("baps_propagate_shadow_stack_pointer_metadata");
  assert(m_baps_propagate_shadow_stack_pointer_metadata &&
         "baps_propagate_shadow_stack_pointer_metadata function type null ?");

  m_baps_introspect_metadata = module.getFunction("baps_introspect_metadata");
  assert(m_baps_introspect_metadata &&
         "baps_introspect_metadata function type null ?");
  m_baps_copy_metadata = module.getFunction("baps_copy_metadata");
  assert(m_baps_copy_metadata && "baps_copy_metadata function type null ?");

  m_baps_store_trie_pointer_metadata =
      module.getFunction("baps_store_trie_pointer_metadata");
  assert(m_baps_store_trie_pointer_metadata &&
         "baps_store_trie_pointer_metadata function type null ?");
  m_baps_load_trie_pointer_metadata_obj =
      module.getFunction("baps_load_trie_pointer_metadata_obj");
  assert(m_baps_load_trie_pointer_metadata_obj &&
         "baps_load_trie_pointer_metadata_obj function type null ?");
  m_baps_load_trie_pointer_metadata_size =
      module.getFunction("baps_load_trie_pointer_metadata_size");
  assert(m_baps_load_trie_pointer_metadata_size &&
         "baps_load_trie_pointer_metadata_size function type null ?");
  m_baps_load_trie_pointer_metadata_unique_id =
      module.getFunction("baps_load_trie_pointer_metadata_unique_id");
  assert(m_baps_load_trie_pointer_metadata_unique_id &&
         "baps_load_trie_pointer_metadata_unique_id function type null ?");

  m_baps_malloc_shadow_metadata =
      module.getFunction("baps_malloc_shadow_metadata");
  assert(m_baps_malloc_shadow_metadata &&
         "baps_malloc_shadow_metadata function type null ?");
  m_baps_free_shadow_metadata = module.getFunction("baps_free_shadow_metadata");
  assert(m_baps_free_shadow_metadata &&
         "baps_free_shadow_metadata function type null ?");

  if (m_machine_is_64_bit) {
    m_unique_id_type = Type::getInt64Ty(module.getContext());
  } else {
    m_unique_id_type = Type::getInt32Ty(module.getContext());
  }

  size_t infer_bound;
  if (m_machine_is_64_bit) {
    infer_bound = (size_t)pow(2, 48);
  } else {
    infer_bound = (size_t)(2147483647);
  }
  ConstantInt *infinite_bound;
  if (m_machine_is_64_bit) {
    ConstantInt::get(Type::getInt64Ty(module.getContext()), infer_bound, false);
  } else {
    ConstantInt::get(Type::getInt32Ty(module.getContext()), infer_bound, false);
  }

  m_void_ptr_type =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  PointerType *VoidPtrType =
      PointerType::getUnqual(Type::getInt8Ty(module.getContext()));
  m_void_null_ptr = ConstantPointerNull::get(VoidPtrType);
  PointerType *SizePtrType = nullptr;
  if (m_machine_is_64_bit) {
    SizePtrType = PointerType::getUnqual(Type::getInt64Ty(module.getContext()));
  } else {
    SizePtrType = PointerType::getUnqual(Type::getInt32Ty(module.getContext()));
  }
  m_size_t_ptr_type = SizePtrType;
  m_size_t_null_ptr = ConstantPointerNull::get(SizePtrType);

  m_constant_int32ty_two =
      ConstantInt::get(Type::getInt32Ty(module.getContext()), 2);
  m_constant_int32ty_one =
      ConstantInt::get(Type::getInt32Ty(module.getContext()), 1);
  m_constant_int32ty_zero =
      ConstantInt::get(Type::getInt32Ty(module.getContext()), 0);

  m_constant_int64ty_two =
      ConstantInt::get(Type::getInt64Ty(module.getContext()), 2);
  m_constant_int64ty_one =
      ConstantInt::get(Type::getInt64Ty(module.getContext()), 1);
  m_constant_int64ty_zero =
      ConstantInt::get(Type::getInt64Ty(module.getContext()), 0);

  if (m_machine_is_64_bit) {
    m_constant_two = m_constant_int64ty_two;
    m_constant_one = m_constant_int64ty_one;
    m_constant_zero = m_constant_int64ty_zero;
  } else {
    m_constant_two = m_constant_int32ty_two;
    m_constant_one = m_constant_int32ty_one;
    m_constant_zero = m_constant_int32ty_zero;
  }
}

/**
 * identifyAndRenameMainFunction()
 * This method renames the function "main" in the module as pseudo_main
 * @param module Input module with the function main,
 * and module with any function named "main" is changed to "pseudo_main"
 */
void BAPS::identifyAndRenameMainFunction(Module &module) {
  Function *mainFunc = module.getFunction("main");
  /**
   * if the module doesn't has "main", we just return
   */
  if (!mainFunc) {
    return;
  }
  //    DEBUG_MSG(errs() << "we found main function in the program \n");
  Type *returnType = mainFunc->getReturnType();
  const FunctionType *funcType = mainFunc->getFunctionType();
  std::vector<Type *> params;
  SmallVector<AttributeSet, 8> param_attributes_vec;
  const AttributeList &pal = mainFunc->getAttributes();
  for (Function::arg_iterator i = mainFunc->arg_begin(),
                              e = mainFunc->arg_end();
       i != e; ++i) {
    params.push_back(i->getType());
  }
  FunctionType *newFuncType =
      FunctionType::get(returnType, params, funcType->isVarArg());
  Function *newFunc = nullptr;
  newFunc =
      Function::Create(newFuncType, mainFunc->getLinkage(), "baps_pseudo_main");
  newFunc->copyAttributesFrom(mainFunc);
  newFunc->setAttributes(pal);
  mainFunc->getParent()->getFunctionList().push_back(newFunc);
  newFunc->getBasicBlockList().splice(newFunc->begin(),
                                      mainFunc->getBasicBlockList());
  Function::arg_iterator newFunArgI = newFunc->arg_begin();
  for (Function::arg_iterator argI = mainFunc->arg_begin(),
                              argEnd = mainFunc->arg_end();
       argI != argEnd; ++argI) {
    argI->replaceAllUsesWith(newFunArgI);
    newFunArgI->takeName(argI);
    ++newFunArgI;
  }
  mainFunc->removeFromParent();
}

void BAPS::renameWrappedFunctions(Module &module) {
  bool change = false;
  do {
    change = false;
    for (Module::iterator fi = module.begin(), fe = module.end(); fi != fe;
         ++fi) {
      Function *function = dyn_cast<Function>(fi);
      if (m_func_transformed.count(function->getName()) ||
          isFuncDefByBAPS(function->getName())) {
        continue;
      }
      m_func_transformed[function->getName()] = true;
      m_func_transformed[getRenamedFunctionName(function->getName())] = true;
      bool isExternal = function->isDeclaration();
      renameFunctionName(function, module, isExternal);
      change = true;
      break;
    }
  } while (change);
}

std::string BAPS::getRenamedFunctionName(const std::string &str) {
  if (str == "_Znwm" || str == "_Znam") {
    return "__baps_new";
  }

  if (str == "_ZdlPv" || str == "_ZdaPv") {
    return "__baps_delete";
  }

  return "__baps_" + str;
}

void BAPS::renameFunctionName(Function *function, Module &module,
                              bool isExternal) {

  if (!m_func_wrapped_by_baps.count(function->getName())) {
    return;
  }

  if (function->getName() == "baps_pseudo_main") {
    return;
  }

  Type *returnType = function->getReturnType();
  const FunctionType *functionType = function->getFunctionType();
  std::vector<Type *> params;

  SmallVector<AttributeSet, 8> paramAttributes;
  const AttributeList &pal = function->getAttributes();
  for (Function::arg_iterator i = function->arg_begin(),
                              e = function->arg_end();
       i != e; ++i) {
    params.push_back(i->getType());
  }
  FunctionType *newFuncType =
      FunctionType::get(returnType, params, functionType->isVarArg());
  Function *newFunc = nullptr;
  newFunc = Function::Create(newFuncType, function->getLinkage(),
                             getRenamedFunctionName(function->getName()));
  newFunc->copyAttributesFrom(function);
  newFunc->setAttributes(pal);
  function->getParent()->getFunctionList().push_back(newFunc);
  if (!isExternal) {
    newFunc->getBasicBlockList().splice(newFunc->begin(),
                                        function->getBasicBlockList());
    Function::arg_iterator arg_begin2 = newFunc->arg_begin();
    for (Function::arg_iterator arg_begin = function->arg_begin(),
                                arg_end = function->arg_end();
         arg_begin != arg_end; ++arg_begin) {
      arg_begin->replaceAllUsesWith(arg_begin2);
      arg_begin2->takeName(arg_begin);
      ++arg_begin2;
    }
  }
  function->replaceAllUsesWith(newFunc);
  function->removeFromParent();
}

/**
 * identifyFunctionToTransform()
 * This function traverses the module and identifies the functions that need to
 * be transformed by BAPS
 * @param module
 */

void BAPS::identifyFunctionToTransform(Module &module) {
  for (Module::iterator fi = module.begin(), fe = module.end(); fi != fe;
       ++fi) {
    Function *function = dyn_cast<Function>(fi);
    assert(function && "is not a function type");

    if (!function->isDeclaration()) {
      if (isFuncDefByBAPS(function->getName())) {
        continue;
      }
      /**
       * m_func_can_transform contains all the functions that can be transfromed
       */
      m_func_can_transform[function->getName()] = true;
      if (hasPtrRetArgType(function)) {
        m_func_to_transform[function->getName()] = true;
      }
    }
  }
}

bool BAPS::isFuncDefByBAPS(const std::string &str) {
  if (m_func_defined_by_baps.size() == 0) {
    m_func_wrapped_by_baps["tmpfile"] = true;
    m_func_wrapped_by_baps["fopen"] = true;
    m_func_wrapped_by_baps["fdopen"] = true;
    m_func_wrapped_by_baps["popen"] = true;
    m_func_wrapped_by_baps["readdir"] = true;
    m_func_wrapped_by_baps["opendir"] = true;
    m_func_wrapped_by_baps["getcwd"] = true;
    m_func_wrapped_by_baps["strpbrk"] = true;
    //    m_func_wrapped_by_baps["gets"] = true;
    m_func_wrapped_by_baps["fgets"] = true;
    m_func_wrapped_by_baps["memchr"] = true;
    m_func_wrapped_by_baps["rindex"] = true;
    m_func_wrapped_by_baps["strtoul"] = true;
    m_func_wrapped_by_baps["strtod"] = true;
    m_func_wrapped_by_baps["strtol"] = true;
    m_func_wrapped_by_baps["strchr"] = true;
    m_func_wrapped_by_baps["strrchr"] = true;
    m_func_wrapped_by_baps["strcpy"] = true;
    m_func_wrapped_by_baps["strtok"] = true;
    m_func_wrapped_by_baps["strdup"] = true;
    m_func_wrapped_by_baps["strcat"] = true;
    m_func_wrapped_by_baps["strncat"] = true;
    m_func_wrapped_by_baps["strncpy"] = true;
    m_func_wrapped_by_baps["strstr"] = true;
    m_func_wrapped_by_baps["signal"] = true;

    m_func_wrapped_by_baps["realloc"] = true;
    m_func_wrapped_by_baps["calloc"] = true;
    m_func_wrapped_by_baps["malloc"] = true;
    m_func_wrapped_by_baps["mmap"] = true;
    m_func_wrapped_by_baps["free"] = true;
    m_func_wrapped_by_baps["_Znwm"] = true;
    m_func_wrapped_by_baps["_ZdlPv"] = true;
    m_func_wrapped_by_baps["_ZdaPv"] = true;
    m_func_wrapped_by_baps["_Znam"] = true;

    m_func_wrapped_by_baps["localtime"] = true;
    m_func_wrapped_by_baps["ctime"] = true;
    m_func_wrapped_by_baps["getenv"] = true;
    m_func_wrapped_by_baps["strerror"] = true;
    m_func_wrapped_by_baps["__errno_location"] = true;
    m_func_wrapped_by_baps["__ctype_b_loc"] = true;
    m_func_wrapped_by_baps["__ctype_toupper_loc"] = true;
    m_func_wrapped_by_baps["__ctype_tolower_loc"] = true;

    m_func_defined_by_baps["puts"] = true;
    m_func_defined_by_baps["generateUniqueID"] = true;
    m_func_defined_by_baps["baps_allocate_shadow_stack_space"] = true;
    m_func_defined_by_baps["baps_deallocate_shadow_stack_space"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_load_size"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_store_size"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_load_obj"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_store_obj"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_load_unique_id"] = true;
    m_func_defined_by_baps["baps_shadow_stack_pointer_store_unique_id"] = true;
    m_func_defined_by_baps["baps_shadow_stack_store_return_metadata"] = true;
    m_func_defined_by_baps["baps_shadow_stack_store_null_return_metadata"] =
        true;
    m_func_defined_by_baps["baps_propagate_shadow_stack_pointer_metadata"] =
        true;
    m_func_defined_by_baps["baps_store_back_trace_handler"] = true;
    m_func_defined_by_baps["baps_store_malloc_back_trace_handler"] = true;
    m_func_defined_by_baps["baps_store_free_back_trace_handler"] = true;

    m_func_defined_by_baps["baps_store_use_back_trace_handler"] = true;
    m_func_defined_by_baps["baps_print_back_trace_handler"] = true;
    m_func_defined_by_baps["baps_print_malloc_back_trace_handler"] = true;

    m_func_defined_by_baps["baps_print_free_back_trace_handler"] = true;

    m_func_defined_by_baps["baps_print_use_back_trace_handler"] = true;
    m_func_defined_by_baps["baps_print_current_back_trace"] = true;
    m_func_defined_by_baps["baps_printf"] = true;
    m_func_defined_by_baps["baps_init"] = true;
    m_func_defined_by_baps["baps_global_init"] = true;
    m_func_defined_by_baps["baps_trie_pointer_metadata_secondary_allocate"] =
        true;
    m_func_defined_by_baps["baps_trie_shadow_metadata_secondary_allocate"] =
        true;
    m_func_defined_by_baps["baps_trie_backtrace_metadata_secondary_allocate"] =
        true;
    m_func_defined_by_baps["baps_store_trie_pointer_metadata"] = true;
    m_func_defined_by_baps["baps_load_trie_pointer_metadata"] = true;
    m_func_defined_by_baps["baps_load_trie_pointer_metadata_begin"] = true;
    m_func_defined_by_baps["baps_load_trie_pointer_metadata_end"] = true;
    m_func_defined_by_baps["baps_load_trie_pointer_metadata_unique_id"] = true;
    m_func_defined_by_baps["baps_malloc_shadow_metadata"] = true;
    m_func_defined_by_baps["baps_free_shadow_metadata"] = true;
    m_func_defined_by_baps["baps_copy_metadata"] = true;
    m_func_defined_by_baps["baps_introspect_metadata"] = true;

    m_func_defined_by_baps["baps_access_shadow_metadata"] = true;
    m_func_defined_by_baps["baps_print_shadow_metadata"] = true;

    m_func_defined_by_baps["baps_store_malloc_back_trace"] = true;
    m_func_defined_by_baps["baps_store_free_back_trace"] = true;
    m_func_defined_by_baps["baps_store_use_back_trace"] = true;
    m_func_defined_by_baps["baps_store_backtrace_metadata"] = true;
    m_func_defined_by_baps["baps_print_malloc_back_trace"] = true;

    m_func_defined_by_baps["baps_print_free_back_trace"] = true;
    m_func_defined_by_baps["baps_print_use_back_trace"] = true;
    m_func_defined_by_baps["baps_abort"] = true;
    m_func_defined_by_baps["baps_pointer_dereference_check"] = true;

    m_func_defined_by_baps["baps_safe_malloc"] = true;
    m_func_defined_by_baps["baps_safe_free"] = true;
    m_func_defined_by_baps["baps_safe_calloc"] = true;
    m_func_defined_by_baps["baps_safe_realloc"] = true;
    m_func_defined_by_baps["baps_safe_mmap"] = true;
    m_func_defined_by_baps["baps_safe_munmap"] = true;

    m_func_defined_by_baps["__baps_malloc"] = true;
    m_func_defined_by_baps["__baps_free"] = true;
    m_func_defined_by_baps["__baps_calloc"] = true;
    m_func_defined_by_baps["__baps_realloc"] = true;
    m_func_defined_by_baps["__baps_mmap"] = true;
    m_func_defined_by_baps["__baps_new"] = true;
    m_func_defined_by_baps["__baps_delete"] = true;
    m_func_defined_by_baps["__baps_new_array"] = true;
    m_func_defined_by_baps["__baps_delete_array"] = true;
    m_func_defined_by_baps["__baps_new_array"] = true;

    m_func_defined_by_baps["__assert_fail"] = true;
    m_func_defined_by_baps["assert"] = true;
    m_func_defined_by_baps["__strspn_c2"] = true;
    m_func_defined_by_baps["__strcspn_c2"] = true;
    m_func_defined_by_baps["__strtol_internal"] = true;
    m_func_defined_by_baps["__stroul_internal"] = true;
    m_func_defined_by_baps["ioctl"] = true;
    m_func_defined_by_baps["error"] = true;
    m_func_defined_by_baps["__strtod_internal"] = true;
    m_func_defined_by_baps["__strtoul_internal"] = true;

    m_func_defined_by_baps["fflush_unlocked"] = true;
    m_func_defined_by_baps["full_write"] = true;
    m_func_defined_by_baps["safe_read"] = true;
    m_func_defined_by_baps["_IO_getc"] = true;
    m_func_defined_by_baps["_IO_putc"] = true;
    m_func_defined_by_baps["__xstat"] = true;

    m_func_defined_by_baps["select"] = true;
    m_func_defined_by_baps["_setjmp"] = true;
    m_func_defined_by_baps["longjmp"] = true;
    m_func_defined_by_baps["fork"] = true;
    m_func_defined_by_baps["pipe"] = true;
    m_func_defined_by_baps["dup2"] = true;
    m_func_defined_by_baps["execv"] = true;
    m_func_defined_by_baps["compare_pic_by_pic_num_desc"] = true;

    m_func_defined_by_baps["wprintf"] = true;
    m_func_defined_by_baps["vfprintf"] = true;
    m_func_defined_by_baps["vsprintf"] = true;
    m_func_defined_by_baps["fprintf"] = true;
    m_func_defined_by_baps["printf"] = true;
    m_func_defined_by_baps["sprintf"] = true;
    m_func_defined_by_baps["snprintf"] = true;

    m_func_defined_by_baps["scanf"] = true;
    m_func_defined_by_baps["fscanf"] = true;
    m_func_defined_by_baps["sscanf"] = true;

    m_func_defined_by_baps["asprintf"] = true;
    m_func_defined_by_baps["vasprintf"] = true;
    m_func_defined_by_baps["__fpending"] = true;
    m_func_defined_by_baps["fcntl"] = true;

    m_func_defined_by_baps["vsnprintf"] = true;
    m_func_defined_by_baps["fwrite_unlocked"] = true;
    m_func_defined_by_baps["__overflow"] = true;
    m_func_defined_by_baps["__uflow"] = true;
    m_func_defined_by_baps["execlp"] = true;
    m_func_defined_by_baps["execl"] = true;
    m_func_defined_by_baps["waitpid"] = true;
    m_func_defined_by_baps["dup"] = true;
    m_func_defined_by_baps["setuid"] = true;

    m_func_defined_by_baps["_exit"] = true;
    m_func_defined_by_baps["funlockfile"] = true;
    m_func_defined_by_baps["flockfile"] = true;

    m_func_defined_by_baps["__option_is_short"] = true;
  }

  if (m_func_defined_by_baps.count(str) > 0) {
    return true;
  }

  if (str.find("llvm.") == 0) {
    return true;
  }

  if (str.find("isoc99") != std::string::npos) {
    return true;
  }
  if (str.find("__cxx_global_var_init") == 0) {
    return true;
  }
  if (str.find("_GLOBAL__I_a") == 0) {
    return true;
  }
  if (str.find("_GLOBAL__sub_I_main") == 0) {
    return true;
  }
  if (str.find("__GLOBAL__") == 0) {
    return true;
  }
  return false;
}

/**
 * hasPtrRetArgType()
 * This function checks whether the function has a return pointer type
 * or whether the argument contains a pointer type.
 * @param function
 * @return
 */
bool BAPS::hasPtrRetArgType(Function *function) {
  const Type *returnType = function->getReturnType();
  if (isa<PointerType>(returnType)) {
    return true;
  }
  for (Function::arg_iterator arg_i = function->arg_begin(),
                              arg_e = function->arg_end();
       arg_i != arg_e; ++arg_i) {
    if (isa<PointerType>(arg_i->getType())) {
      return true;
    }
  }
  return false;
}

/**
 * identifyAndHandleGlobalVariables()
 * This function is used to identify and handle global variables that exist in
 * the program
 * @param module
 */
void BAPS::identifyAndHandleGlobalVariables(Module &module) {
  /**
   * At First, we need to identify global variables that exist in the program
   */
  identifyGlobalVariables(module);
  /**
   * Next, we need to handle global variables
   */
  handleGlobalVariables(module);
}

/**
 * identifyGlobalVariables()
 * This function is used to identify global variables
 * @param module
 */
void BAPS::identifyGlobalVariables(Module &module) {
  for (Module::global_iterator gi = module.global_begin(),
                               ge = module.global_end();
       gi != ge; ++gi) {
    GlobalVariable *globalVariable = dyn_cast<GlobalVariable>(gi);
    if (globalVariable) {
      if (m_global_variables.count(globalVariable)) {
        continue;
      }
      m_global_variables[globalVariable] = 1;
    }
  }
}

/**
 * handleGlobalVariables()
 * This function is used to handle global variables that exist in the program.
 * @param module
 */
void BAPS::handleGlobalVariables(Module &module) {
  for (Module::global_iterator gi = module.global_begin(),
                               ge = module.global_end();
       gi != ge; ++gi) {
    GlobalVariable *globalVariable = dyn_cast<GlobalVariable>(gi);

    if (!globalVariable) {
      continue;
    }

    if (!m_global_variables.count(globalVariable)) {
      continue;
    }

    if (globalVariable->getSection() == "llvm.metadata") {
      continue;
    }

    if (globalVariable->getName() == "llvm.global_ctors") {
      continue;
    }

    if (globalVariable->isDeclaration()) {
      continue;
    }

    if (!globalVariable->hasInitializer()) {
      continue;
    }

    /**
     * for now, globalVariable has its initializer, i.e., it's not declaration
     */

    Constant *initializer =
        dyn_cast<Constant>(globalVariable->getInitializer());

    if (initializer) {
      Value *value = globalVariable;
      associateObjIdAndAddr(value, m_constant_one, globalVariable);
    }

    if (initializer && !isa<CompositeType>(initializer->getType())) {
      //      DEBUG_MSG(errs() << "!CompositeType initializer:" <<
      //      *globalVariable
      //                       << "\n\n");
      Type *initializerType = initializer->getType();
      if (!isa<PointerType>(initializerType)) {
        Constant *constant = dyn_cast<Constant>(initializer);
        Value *obj_addr = globalVariable;
        Value *obj_size = m_constant_one;
        Value *obj_id = m_constant_one;

//        Instruction *insertAt = getGlobalInitInst(module);
//        insertMetadataStores(obj_addr, obj_addr, obj_size, obj_id, insertAt);
        associateObjIdAndAddr(globalVariable, obj_id, obj_addr);
        continue;
      }
      if (isa<PointerType>(initializerType)) {
        Constant *constant = dyn_cast<Constant>(initializer);
        Value *obj_addr = globalVariable;
        Value *obj_size = m_constant_one;
        Value *obj_id = m_constant_one;

        if (isa<ConstantPointerNull>(constant)) {
          obj_id = m_constant_zero;
        } else {
          obj_id = m_constant_one;
        }

//        Instruction *insertAt = getGlobalInitInst(module);
//        insertMetadataStores(obj_addr, obj_addr, obj_size, obj_id, insertAt);
        associateObjIdAndAddr(globalVariable, obj_id, obj_addr);
        continue;
      }
    }

    if (initializer && isa<CompositeType>(initializer->getType())) {

      if (isa<StructType>(initializer->getType())) {
        handleGlobalStructTypeInitializer(module, globalVariable);
        continue;
      }

      if (isa<SequentialType>(initializer->getType())) {
        handleGlobalSequentialTypeInitializer(module, globalVariable);
        continue;
      }
    }

    ConstantArray *constantArray = dyn_cast<ConstantArray>(initializer);
    if (!constantArray) {
      continue;
    }
  }
}
/**
 * obtainGlobalVariablesScope()
 * this function is used to obtain global variable's begin and end
 * @param globalVariable
 * @param begin
 * @param end
 */
void BAPS::obtainGlobalVariablesScope(GlobalVariable *globalVariable,
                                      Value *&begin, Value *&end) {
  if (!isa<GlobalVariable>(globalVariable)) {
    DEBUG_MSG(errs() << "globalVariable argument is not GlobalVariable?");
    return;
  }

  Constant *initializer = dyn_cast<Constant>(globalVariable->getInitializer());

  //  if (isa<PointerType>(initializer->getType())) {
  //    if (isa<GlobalVariable>(initializer)) {
  //      GlobalVariable *globalVariableInitializer =
  //          dyn_cast<GlobalVariable>(initializer);
  //      obtainGlobalVariablesScope(globalVariableInitializer, begin, end);
  //    } else {
  //      begin = &*globalVariable;
  //      end = &*globalVariable;
  //      return;
  //    }
  //  } else {
  begin = &*globalVariable;
  end = &*globalVariable;
  //  }
}

/**
 * handleGlobalStructTypeInitializer()
 * This performs the initialization of metadata for the pointers in the global
 * segment, which have an initialization value of non-zero.
 * @param module
 * @param globalVariable
 */
void BAPS::handleGlobalStructTypeInitializer(Module &module,
                                             GlobalVariable *globalVariable) {
  Constant *initializer = dyn_cast<Constant>(globalVariable->getInitializer());
  if (initializer->isNullValue()) {
    return;
  }
  StructType *structType =
      dyn_cast<StructType>(globalVariable->getInitializer()->getType());
  if (!structType) {
    return;
  }
  //    DEBUG_MSG(errs() << "globalVariable has non null StructType initializer"
  //    << *globalVariable << "\n");
}

/**
 * handleGlobalSequentialTypeInitializer()
 * This performs the initialization of metadata for the pointers in the global
 * segment, which have an initialization value of non-zero.
 * @param module
 * @param globalVariable
 */
void BAPS::handleGlobalSequentialTypeInitializer(
    Module &module, GlobalVariable *globalVariable) {
  const SequentialType *sequentialType =
      dyn_cast<SequentialType>(globalVariable->getInitializer()->getType());
  assert(sequentialType && "sequentialType is null?");
  const Constant *initializer = globalVariable->getInitializer();
  if (initializer->isNullValue()) {
    return;
  } else {
    //    DEBUG_MSG(errs() << "globalVariable has non null initializer for
    //    SequentialType "
    //                     << *globalVariable << "\n");
  }
}

void BAPS::insertMetadataStores(Value *pointer, Value *obj_addr, Value *size,
                                Value *obj_id, Instruction *insert_at) {
  Value *pointer_cast;
  Value *obj_cast;
  pointer_cast = castToVoidPtr(pointer, insert_at);
  obj_cast = castToVoidPtr(obj_addr, insert_at);
  SmallVector<Value *, 8> args;
  args.push_back(pointer_cast);
  args.push_back(obj_cast);
  args.push_back(size);
  args.push_back(obj_id);
  CallInst::Create(m_baps_store_trie_pointer_metadata, args, "", insert_at);
}

Instruction *BAPS::getGlobalInitInst(Module &module) {
  Function *global_init = module.getFunction("baps_global_init");
  Instruction *terminatorInst = nullptr;
  for (Function::iterator bi = global_init->begin(), be = global_init->end();
       bi != be; ++bi) {
    for (BasicBlock::iterator ii = bi->begin(), ie = bi->end(); ii != ie;
         ++ii) {
      if (isa<TerminatorInst>(ii)) {
        terminatorInst = dyn_cast<TerminatorInst>(ii);
        return terminatorInst;
      }
    }
  }
  assert(terminatorInst && "global init does not have return inst");
  return terminatorInst;
}

/**
 * isTargetFunction()
 * this function is used to identify function of interest,
 * i.e., function with definition but not function defined by BAPS
 * @param function
 * @return
 */
bool BAPS::isTargetFunction(Function *function) {
  if (isFuncDefByBAPS(function->getName())) {
    return false;
  }
  if (function->isDeclaration()) {
    return false;
  }
  return true;
}

/**
 * identifyOriginalInst()
 * Traverses the instructions in the function to identify the IR instructions in
 * the original program. In this process, it is also possible to identify the
 * pointers in the original program.
 * @param function
 */
void BAPS::identifyOriginalInst(Function *function) {
  /**
   * iterating basic block
   */
  for (Function::iterator bi = function->begin(), be = function->end();
       bi != be; ++bi) {
    /**
     * iterating each Instruction in each basic block
     */
    //    DEBUG_MSG(errs() << *bi << "\n");
    for (BasicBlock::iterator ii = bi->begin(), ie = bi->end(); ii != ie;
         ++ii) {
      Value *inst = dyn_cast<Value>(ii);
      if (!m_inst_present_in_original.count(inst)) {
        m_inst_present_in_original[inst] = 1;
      } else {
        assert(m_present_in_original &&
               "present in original map already has the inst?");
      }
    }
  }
}

/**
 * castToVoidPtr()
 * This function introduces a bitcast instruction in the IR when an input
 * operand that is a pointer type is not of type i8*. This is required as all
 * the handlers take i8*s type
 * @param operand
 * @param insert_at
 * @return
 */
Value *BAPS::castToVoidPtr(Value *operand, Instruction *insert_at) {
  Value *voidTypePtr;
  voidTypePtr =
      new BitCastInst(operand, m_void_ptr_type, "voidTypePtr", insert_at);
  //    DEBUG_MSG(errs() << "castToVoidPtr: " << operand << "\n");
  //    DEBUG_MSG(errs() << "insert_at: " << *insert_at << "\n");
  //    DEBUG_MSG(errs() << "BitCastInst: " << *voidTypePtr << "\n");
  return voidTypePtr;
}

/**
 * isAllocaPresent
 * This function checks for alloca instruction in internal functions.
 * The function's role is to determine whether we need to assign an unique id to
 * the function
 * @param function
 * @return
 */
bool BAPS::isAllocaPresent(Function *function) {
  /**
   * iterating basic block
   */
  for (Function::iterator bi = function->begin(), be = function->end();
       bi != be; ++bi) {
    /**
     * iterating each Instruction in each basic block
     */
    for (BasicBlock::iterator ii = bi->begin(), ie = bi->end(); ii != ie;
         ++ii) {
      Instruction *allocaInst = dyn_cast<Instruction>(ii);
      if (isa<AllocaInst>(allocaInst) &&
          m_inst_present_in_original.count(allocaInst)) {
        return true;
      }
    }
  }
  return false;
}

/**
 * identifyPtrAndPropagateIt()
 * @param function
 */
void BAPS::identifyPtrAndPropagateIt(Function *function) {
  /**
   * We first need to deal with the arguments of the function.
   * If the argument is a pointer type, it needs special
   * treatment; otherwise, it only needs to be ignored.
   */
  handleFunctionWithPtrArgs(function);

  /**
   * We need to allocate the stack address to unique_id in the function
   * so that all variables on the stack and pointers to variables
   * on the stack have this unique_id
   */

  //  Value *unique_id = nullptr;
  //  getLocalObjId(function, unique_id);
  //  if (unique_id == nullptr) {
  //    assert(0 && "function unique_id null for the function");
  //  }

  /**
   * we need to use worklist algorithm twice, because we need to handle loops.
   */
  handleFunctionBody(function);
  handleFunctionBodyAgain(function);
  //  freeLocalObjId(function, unique_id);
}
void BAPS::handleFunctionBody(Function *function) {
  /* WorkList Algorithm for propagating the unique_id.
   * Each basic block is visited only once. We start by
   * visiting the current basic block, then push all the
   * successors of the current basic block on to the
   * queue if it has not been visited
   */
  {
    std::set<BasicBlock *> bb_visited;
    std::queue<BasicBlock *> bb_worklist;
    Function::iterator bb_begin = function->begin();

    BasicBlock *bb = dyn_cast<BasicBlock>(bb_begin);
    assert(bb && "bb is not a basic block ?");
    bb_worklist.push(bb);

    while (bb_worklist.size() != 0) {
      bb = bb_worklist.front();
      assert(bb && "bb is not a basic block ?");

      bb_worklist.pop();

      if (bb_visited.count(bb)) {
        /**
         * this basic block has been visited
         */
        continue;
      }
      /**
       * if here implies basic block bb is not visited, insert the basic block
       * into bb_visited
       */

      bb_visited.insert(bb);
      /**
       * Iterating over the successors and adding the successors to the work
       * list, i.e., bb_worklist
       */

      for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se;
           ++si) {
        BasicBlock *next_bb = *si;
        assert(next_bb && "it is not a basic block?");
        bb_worklist.push(next_bb);
      }

      for (BasicBlock::iterator ib = bb->begin(), ie = bb->end(); ib != ie;
           ++ib) {
        Value *value = dyn_cast<Value>(ib);
        Instruction *inst = dyn_cast<Instruction>(ib);
        /**
         * if the instruction is not present in original program, do nothing
         */
        if (!m_inst_present_in_original.count(value)) {
          continue;
        }
        /**
         * All instructions have been defined here as
         * Assertions have been in the inserted in the specific cases
         */
        switch (inst->getOpcode()) {
        case Instruction::Alloca: {
          AllocaInst *allocaInst = dyn_cast<AllocaInst>(inst);
          assert(allocaInst && "it is not an AllocaInst?");
          handleAlloca(allocaInst);
          break;
        };

        case Instruction::Load: {
          LoadInst *loadInst = dyn_cast<LoadInst>(inst);
          assert(loadInst && "it is not an LoadInst?");
          handleLoad(loadInst);
          break;
        }

        case Instruction::GetElementPtr: {
          GetElementPtrInst *getElementPtrInst =
              dyn_cast<GetElementPtrInst>(inst);
          assert(getElementPtrInst && "it is not a getElementPtrInst?");
          handleGEP(getElementPtrInst);
          break;
        }

        case Instruction::BitCast: {
          BitCastInst *bitCastInst = dyn_cast<BitCastInst>(inst);
          assert(bitCastInst && "it is not a bitCastInst?");
          handleBitCast(bitCastInst);
          break;
        }

        case Instruction::PHI: {
          PHINode *phiNode = dyn_cast<PHINode>(inst);
          assert(phiNode && "it is not a PHINode?");
          handlePHINode(phiNode);
          break;
        }
        case Instruction::Call: {
          CallInst *callInst = dyn_cast<CallInst>(inst);
          assert(callInst && "it is not a CallInst?");
          handleCall(callInst);
          break;
        }

        case Instruction::Select: {
          SelectInst *selectInst = dyn_cast<SelectInst>(inst);
          assert(selectInst && "it is not a SelectInst?");
          handleSelect(selectInst);
          break;
        }
        case Instruction::Store: {
          StoreInst *storeInst = dyn_cast<StoreInst>(inst);
          assert(storeInst && "it is not a StoreInst?");
          // handleStore(storeInst);
          break;
        }

        case Instruction::IntToPtr: {
          IntToPtrInst *intToPtrInst = dyn_cast<IntToPtrInst>(inst);
          assert(intToPtrInst && "it is not a IntToPtrInst?");
          handleIntToPtr(intToPtrInst);
          break;
        }
        case Instruction::Ret: {
          ReturnInst *returnInst = dyn_cast<ReturnInst>(inst);
          assert(returnInst && "it is not a ReturnInst?");
          handleRetInst(returnInst);
          break;
        }

        case Instruction::ExtractElement: {
          ExtractElementInst *extractElementInst =
              dyn_cast<ExtractElementInst>(inst);
          assert(extractElementInst && "it is not a ExtractElementInst?");
          handleExtractElement(extractElementInst);
          break;
        }

        case Instruction::ExtractValue: {
          ExtractValueInst *extractValueInst = dyn_cast<ExtractValueInst>(inst);
          assert(extractElementInst && "it is not a ExtractElementInst?");
          handleExtractValue(extractValueInst);
          break;
        }
        case Instruction::Invoke: {
          InvokeInst *invokeInst = dyn_cast<InvokeInst>(inst);
          assert(invokeInst && "it is not a InvokeInst?");
          break;
        }

        default: {
          if (isa<PointerType>(value->getType())) {
            DEBUG_MSG(errs() << "default: " << *inst << "\n");
          }
        }
        }
      }
    }
  }
}
void BAPS::handleFunctionBodyAgain(Function *function) {
  /* WorkList Algorithm for propagating the unique_id.
   * Each basic block is visited only once. We start by
   * visiting the current basic block, then push all the
   * successors of the current basic block on to the
   * queue if it has not been visited
   */
  {
    std::set<BasicBlock *> bb_visited;
    std::queue<BasicBlock *> bb_worklist;
    Function::iterator bb_begin = function->begin();

    BasicBlock *bb = dyn_cast<BasicBlock>(bb_begin);
    assert(bb && "bb is not a basic block ?");
    bb_worklist.push(bb);

    while (bb_worklist.size() != 0) {
      bb = bb_worklist.front();
      assert(bb && "bb is not a basic block ?");

      bb_worklist.pop();

      if (bb_visited.count(bb)) {
        /**
         * this basic block has been visited
         */
        continue;
      }
      /**
       * if here implies basic block bb is not visited, insert the basic block
       * into bb_visited
       */

      bb_visited.insert(bb);
      /**
       * Iterating over the successors and adding the successors to the work
       * list, i.e., bb_worklist
       */

      for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se;
           ++si) {
        BasicBlock *next_bb = *si;
        assert(next_bb && "it is not a basic block?");
        bb_worklist.push(next_bb);
        //                DEBUG_MSG(errs() << *next_bb << "\n");
      }

      for (BasicBlock::iterator ib = bb->begin(), ie = bb->end(); ib != ie;
           ++ib) {
        Value *value = dyn_cast<Value>(ib);
        Instruction *inst = dyn_cast<Instruction>(ib);
        /**
         * if the instruction is not present in original program, do nothing
         */
        if (!m_inst_present_in_original.count(value)) {
          continue;
        }
        /**
         * All instructions have been defined here as
         * Assertions have been in the inserted in the specific cases
         */

        switch (inst->getOpcode()) {
        case Instruction::Alloca: {
          AllocaInst *allocaInst = dyn_cast<AllocaInst>(inst);
          assert(allocaInst && "it is not an AllocaInst?");
          //          handleAlloca(allocaInst);
          break;
        };

        case Instruction::Load: {
          LoadInst *loadInst = dyn_cast<LoadInst>(inst);
          assert(loadInst && "it is not an LoadInst?");
          //                        handleLoad(loadInst);
          break;
        }

        case Instruction::GetElementPtr: {
          GetElementPtrInst *getElementPtrInst =
              dyn_cast<GetElementPtrInst>(inst);
          assert(getElementPtrInst && "it is not a getElementPtrInst?");
          handleGEP(getElementPtrInst);
          break;
        }

        case Instruction::BitCast: {
          BitCastInst *bitCastInst = dyn_cast<BitCastInst>(inst);
          assert(bitCastInst && "it is not a bitCastInst?");
          handleBitCast(bitCastInst);
          break;
        }

        case Instruction::PHI: {
          PHINode *phiNode = dyn_cast<PHINode>(inst);
          assert(phiNode && "it is not a PHINode?");
          handlePHINodeAgain(phiNode);
          break;
        }
        case Instruction::Call: {
          CallInst *callInst = dyn_cast<CallInst>(inst);
          assert(callInst && "it is not a CallInst?");
          //                        handleCall(callInst);
          break;
        }

        case Instruction::Select: {
          SelectInst *selectInst = dyn_cast<SelectInst>(inst);
          assert(selectInst && "it is not a SelectInst?");
          //                        handleSelect(selectInst);
          break;
        }
        case Instruction::Store: {
          StoreInst *storeInst = dyn_cast<StoreInst>(inst);
          assert(storeInst && "it is not a StoreInst?");
          handleStore(storeInst);
          break;
        }

        case Instruction::IntToPtr: {
          IntToPtrInst *intToPtrInst = dyn_cast<IntToPtrInst>(inst);
          assert(intToPtrInst && "it is not a IntToPtrInst?");
          //                        handleIntToPtr(intToPtrInst);
          break;
        }
        case Instruction::Ret: {
          ReturnInst *returnInst = dyn_cast<ReturnInst>(inst);
          assert(returnInst && "it is not a ReturnInst?");
          //                        handleRetInst(returnInst);
          break;
        }

        case Instruction::ExtractElement: {
          ExtractElementInst *extractElementInst =
              dyn_cast<ExtractElementInst>(inst);
          assert(extractElementInst && "it is not a ExtractElementInst?");
          //                        handleExtractElement(extractElementInst);
          break;
        }

        case Instruction::ExtractValue: {
          ExtractValueInst *extractValueInst = dyn_cast<ExtractValueInst>(inst);
          assert(extractElementInst && "it is not a ExtractElementInst?");
          //                        handleExtractValue(extractValueInst);
          break;
        }

        case Instruction::Invoke: {
          InvokeInst *invokeInst = dyn_cast<InvokeInst>(inst);
          assert(invokeInst && "it is not a InvokeInst?");
          break;
        }

        default: {

          if (isa<PointerType>(value->getType())) {
            //                            DEBUG_MSG(errs() << "default:" <<
            //                            "\n"); DEBUG_MSG(errs() << *inst <<
            //                            "\n");
            assert(0 && " Generating Pointer and not being handled");
          }
        }
        }
      }
    }
  }
}
/**
 * handleFunctionWithPtrArgs()
 * @param function
 */
void BAPS::handleFunctionWithPtrArgs(Function *function) {
  int argCount = 0;
  StringRef functionName = function->getName();
  if (m_func_to_transform.count(functionName) > 0) {
    for (Function::arg_iterator ai = function->arg_begin(),
                                ae = function->arg_end();
         ai != ae; ++ai) {
      /**
       * we only need to handle arguments with pointer type, and ignore other
       * types' arguments.
       */
      if (!isa<PointerType>(ai->getType())) {
        continue;
      }
      /**
       * argument is a pointer, so we need to increment the argCount
       */
      ++argCount;
      Argument *argument = dyn_cast<Argument>(ai);
      Value *argumentValue = argument;
      Instruction *firstInst = &*(function->begin()->begin());
      /* we may need to think about what to do about [byval] attributes */
      if (argument->hasByValAttr()) {
        //      if (checkArgsHasPtrType(argument)) {
        //      }
        associateObjIdAndAddr(argumentValue, m_constant_one, m_constant_one);
      } else {
        introduceShadowStackLoads(argument, firstInst, argCount);
      }
    }
  }
}

/**
 * handleAlloca()
 * @param allocaInst
 * @param unique_id
 */

void BAPS::handleAlloca(AllocaInst *allocaInst) {

  /**
   * associate each stack variable a unique_id
   */

  //    DEBUG_MSG(errs() << *allocaInst << " " << *unique_id << "\n");
  Value *value = allocaInst;
  associateObjIdAndAddr(value, m_constant_two, value);
}

/**
 * handleLoad()
 * handleLoad takes a loadInst if the load is through a pointer
 * which is a global then inserts unique_id for that global
 * Also if the loaded value is a pointer then loads the unique_id
 * for for the pointer from the shadow space
 * @param loadInst
 */
void BAPS::handleLoad(LoadInst *loadInst) {
  Type *type = loadInst->getType();
  if (!isa<VectorType>(type) && !isa<PointerType>(type)) {
    return;
  }
  if (isa<PointerType>(loadInst->getType())) {
    //    DEBUG_MSG(errs() << *loadInst << "\n");
    insertMetadataLoads(loadInst);
    return;
  }
  if (isa<VectorType>(loadInst->getType())) {
    assert(loadInst->getType() &&
           "handleLoad for VectorType has not well handled");
  }
}

void BAPS::handleGEP(GetElementPtrInst *getElementPtrInst) {

  Value *pointerOperand = getElementPtrInst->getPointerOperand();

  assert(0 && "we encounter GEP Inst");
  propagateMetadata(pointerOperand, getElementPtrInst);
}

void BAPS::handleBitCast(BitCastInst *bitCastInst) {

  Value *pointerOperand = bitCastInst->getOperand(0);

  propagateMetadata(pointerOperand, bitCastInst);
}

/**
 * propagateMetadata()
 * This function propagates the metadata from the source to the destination
 * in the map for pointer arithmetic operations~(gep) and ~(bitcasts).
 * @param pointerOperand
 * @param inst
 * @param flag
 */

void BAPS::propagateMetadata(Value *pointerOperand, Instruction *inst) {
  assert(0 && "we encounter propagateMetadata funciton call");

  if (checkUniqueIdMetadataPresent(inst)) {
    return;
  }

  if (isa<ConstantPointerNull>(pointerOperand)) {
    Value *value = inst;
    associateObjIdAndAddr(value, m_constant_zero, m_void_null_ptr);
    return;
  }

  if (checkUniqueIdMetadataPresent(pointerOperand)) {

    Value *obj_id = getAssociatedObjId(pointerOperand);
    Value *obj_addr = getAssociatedObjAddr(pointerOperand);
    Value *value = inst;
    associateObjIdAndAddr(value, obj_id, obj_addr);

  } else if (isa<Constant>(pointerOperand)) {
    Value *value = inst;
    associateObjIdAndAddr(value, m_constant_one, pointerOperand);
  }
}

/**
 * handlePHINode()
 * This function creates a PHINode for the metadata in the bitcode of the
 * pointer PHINode. It is important to note that this function only creates a
 * PHINode and does not populate the incoming values.
 * @param phiNode
 */

void BAPS::handlePHINode(PHINode *phiNode) {
  Type *type = phiNode->getType();
  if (!isa<PointerType>(type)) {
    return;
  }

  unsigned numIncomingValues = phiNode->getNumIncomingValues();
  //    DEBUG_MSG(errs() << "phinode in function " <<
  //    phiNode->getParent()->getParent()->getName() << " \n"); DEBUG_MSG(errs()
  //    << "phinodeInst in function " << *phiNode << " \n"); DEBUG_MSG(errs() <<
  //    "getNumIncomingValues in function " << numIncomingValues << " \n");
  PHINode *uniqueIdPhiNode =
      PHINode::Create(Type::getInt64Ty(phiNode->getType()->getContext()),
                      numIncomingValues, "phinode.unique_id", phiNode);
  PHINode *objAddrPhiNode = PHINode::Create(m_void_ptr_type, numIncomingValues,
                                            "phinode.obj_addr", phiNode);
  associateObjIdAndAddr(phiNode, uniqueIdPhiNode, objAddrPhiNode);
}

void BAPS::handlePHINodeAgain(PHINode *phiNode) {

  Type *type = phiNode->getType();
  if (!isa<PointerType>(type)) {
    return;
  }

  PHINode *objIdPhiNode = nullptr;
  PHINode *objAddrPhiNode = nullptr;
  objIdPhiNode = dyn_cast<PHINode>(getAssociatedObjId(phiNode));
  objAddrPhiNode = dyn_cast<PHINode>(getAssociatedObjAddr(phiNode));
  unsigned numIncomingValues = phiNode->getNumIncomingValues();

  for (unsigned m = 0; m < numIncomingValues; ++m) {

    Value *incomingValue = phiNode->getIncomingValue(m);
    BasicBlock *incomingBB = phiNode->getIncomingBlock(m);
    //        DEBUG_MSG(errs() << "incomingValue" << *incomingValue << "\n");

    if (isa<ConstantPointerNull>(incomingValue)) {
      //            DEBUG_MSG(errs() << "ConstantPointerNull\n");
      objIdPhiNode->addIncoming(m_constant_zero, incomingBB);
      objAddrPhiNode->addIncoming(m_void_null_ptr, incomingBB);
      continue;
    }

    if (isa<UndefValue>(incomingValue)) {
      //            DEBUG_MSG(errs() << "UndefValue\n");
      objIdPhiNode->addIncoming(m_constant_zero, incomingBB);
      objAddrPhiNode->addIncoming(m_void_null_ptr, incomingBB);
      continue;
    }

    if (isa<GlobalVariable>(incomingValue)) {
      //            DEBUG_MSG(errs() << "GlobalVariable\n");
      objIdPhiNode->addIncoming(m_constant_one, incomingBB);
      objAddrPhiNode->addIncoming(incomingValue, incomingBB);
      continue;
    }

    if (isa<Constant>(incomingValue)) {
      //            DEBUG_MSG(errs() << "Constant\n");
      objIdPhiNode->addIncoming(m_constant_one, incomingBB);
      objAddrPhiNode->addIncoming(incomingValue, incomingBB);
      continue;
    }

    if (checkUniqueIdMetadataPresent(incomingValue)) {
      //            DEBUG_MSG(errs() << "checkUniqueIdMetadataPresent" <<
      //            *getAssociatedObjId(incomingValue) << "\n");
      objIdPhiNode->addIncoming(getAssociatedObjId(incomingValue), incomingBB);
      objAddrPhiNode->addIncoming(getAssociatedObjAddr(incomingValue),
                                  incomingBB);
      continue;
    }
  }
}

void BAPS::handleCall(CallInst *callInst) {

  Function *calleeFunction = callInst->getCalledFunction();

  if (calleeFunction && calleeFunction->getName().find("llvm.memset") == 0) {
    //        DEBUG_MSG(errs()<<"llvm.memset: "<<*callInst<<"\n");
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm.memcpy") == 0)) {
    //        DEBUG_MSG(errs()<<"llvm.memcpy: "<<*callInst<<"\n");
    handleMemcpy(callInst);
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm.memmove") == 0)) {
    handleMemcpy(callInst);
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm") == 0)) {
    return;
  }

  if (calleeFunction && isFuncDefByBAPS(calleeFunction->getName())) {
    if (!isa<PointerType>(callInst->getType())) {
      return;
    }
    associateObjIdAndAddr(callInst, m_constant_zero, m_void_null_ptr);
    return;
  }

  Instruction *inst = callInst;
  Instruction *insertAt = getNextInstruction(inst);
  introduceShadowStackAllocation(callInst);
  iterateCallSiteIntroduceShadowStackStores(callInst);
  if (isa<PointerType>(callInst->getType())) {
    introduceShadowStackLoads(callInst, insertAt, 0);
  }
  introduceShadowStackDeallocation(callInst, insertAt);
}

void BAPS::handleMemcpy(CallInst *callInst) {
  Function *function = callInst->getCalledFunction();
  if (!function) {
    return;
  }
  assert(function && "function is null?");
  CallSite cs(callInst);
  Value *arg1 = cs.getArgument(0);
  Value *arg2 = cs.getArgument(1);
  Value *arg3 = cs.getArgument(2);
  SmallVector<Value *, 8> args;
  args.push_back(arg1);
  args.push_back(arg2);
  args.push_back(arg3);
  if (arg3->getType() == Type::getInt64Ty(arg3->getContext())) {
    CallInst::Create(m_baps_copy_metadata, args, "", callInst);
  } else {
  }
  args.clear();
}

void BAPS::introduceShadowStackAllocation(CallInst *callInst) {
  // Count the number of pointer arguments and whether a pointer return
  int numPointerArgsAndReturn = getNumOfPtrArgsAndReturn(callInst);
  if (numPointerArgsAndReturn == 0) {
    return;
  }

  Value *totalPtrArgs;
  totalPtrArgs =
      ConstantInt::get(Type::getInt32Ty(callInst->getType()->getContext()),
                       numPointerArgsAndReturn, false);
  SmallVector<Value *, 8> args;
  args.clear();
  args.push_back(totalPtrArgs);
  CallInst::Create(m_baps_allocate_shadow_stack_space, args, "", callInst);
}

void BAPS::iterateCallSiteIntroduceShadowStackStores(CallInst *callInst) {

  int numPointerArgsAndReturn = getNumOfPtrArgsAndReturn(callInst);
  if (numPointerArgsAndReturn == 0) {
    return;
  }

  int argCount = 1;
  CallSite cs(callInst);
  //  DEBUG_MSG(errs() << "handling instruction: " << *callInst << "\n");
  for (unsigned i = 0; i < cs.arg_size(); ++i) {
    Value *argValue = cs.getArgument(i);
    if (isa<PointerType>(argValue->getType())) {
      introduceShadowStackStores(argValue, callInst, argCount);
      ++argCount;
    }
  }
}

void BAPS::introduceShadowStackDeallocation(CallInst *callInst,
                                            Instruction *insertAt) {
  int pointerArgsAndReturn = getNumOfPtrArgsAndReturn(callInst);
  if (pointerArgsAndReturn == 0) {
    return;
  }
  SmallVector<Value *, 8> args;
  //    errs() << callInst->getCalledFunction()->getName() << " " <<
  //    pointerArgsAndReturn << '\n';
  CallInst::Create(m_baps_deallocate_shadow_stack_space, args, "", insertAt);
}

/**
 * getNumOfPtrArgsAndReturn()
 * Returns the number of pointer arguments and return
 * @param callInst
 * @return
 */

int BAPS::getNumOfPtrArgsAndReturn(CallInst *callInst) {
  int totalPtrCount = 0;
  CallSite cs(callInst);
  for (auto i = 0; i < cs.arg_size(); ++i) {
    Value *argValue = cs.getArgument(i);
    if (isa<PointerType>(argValue->getType())) {
      ++totalPtrCount;
    }
  }
  if (totalPtrCount != 0) {
    ++totalPtrCount;
  } else {
    if (isa<PointerType>(callInst->getType())) {
      ++totalPtrCount;
    }
  }
  return totalPtrCount;
}

void BAPS::handleSelect(SelectInst *selectInst) {
  Type *type = selectInst->getType();
  if (!isa<PointerType>(type)) {
    return;
  }

  Value *condition = selectInst->getOperand(0);
  Value *operandObjId[2];
  Value *operandObjAddr[2];

  for (auto m = 0; m < 2; m++) {

    Value *operand = selectInst->getOperand(m + 1);
    operandObjId[m] = nullptr;
    operandObjAddr[m] = nullptr;

    if (checkUniqueIdMetadataPresent(operand)) {
      operandObjId[m] = getAssociatedObjId(operand);
      operandObjAddr[m] = getAssociatedObjAddr(operand);
    }

    if (isa<ConstantPointerNull>(operand) &&
        !checkUniqueIdMetadataPresent(operand)) {
      operandObjId[m] = m_constant_zero;
      operandObjAddr[m] = m_void_null_ptr;
    }

    if (isa<Constant>(operand)) {
      operandObjId[m] = m_constant_one;
      operandObjAddr[m] = operand;
    }
    assert(operandObjId[m] != nullptr &&
           "operand doesn't have objId with select?");
    assert(operandObjAddr[m] != nullptr &&
           "operand doesn't have objAddr with select?");
  }

  SelectInst *selectObjId =
      SelectInst::Create(condition, operandObjId[0], operandObjId[1],
                         "select.unique_id", selectInst);
  SelectInst *selectObjAddr =
      SelectInst::Create(condition, operandObjAddr[0], operandObjAddr[1],
                         "select.obj_addr", selectInst);

  Value *value = selectInst;
  associateObjIdAndAddr(value, selectObjId, selectObjAddr);
}

void BAPS::handleIntToPtr(IntToPtrInst *intToPtrInst) {
  Value *value = intToPtrInst;
  associateObjIdAndAddr(value, m_constant_zero, m_void_null_ptr);
}

void BAPS::handleRetInst(ReturnInst *returnInst) {
  Value *value = returnInst->getReturnValue();
  /**
   * value is nullptr means the function has no return value;
   */
  if (value == nullptr) {
    return;
  }
  if (isa<PointerType>(value->getType())) {
    introduceShadowStackStores(value, returnInst, 0);
  }
}

void BAPS::handleExtractElement(ExtractElementInst *extractElementInst) {
  Type *type = extractElementInst->getType();
  if (!isa<PointerType>(type)) {
    return;
  }

  Value *value = extractElementInst;
  associateObjIdAndAddr(value, m_constant_one, m_constant_one);
  return;
}

void BAPS::handleExtractValue(ExtractValueInst *extractValueInst) {
  Type *type = extractValueInst->getType();
  if (isa<PointerType>(type)) {
    assert(0 && "ExtractValue is returning a pointer, and, not handled");
  }

  Value *value = extractValueInst;
  associateObjIdAndAddr(value, m_constant_one, m_constant_one);
  return;
}

void BAPS::handleStore(StoreInst *storeInst) {
  Value *valueOperand = storeInst->getValueOperand();
  Type *valueType = valueOperand->getType();
  Value *pointerOperand = storeInst->getPointerOperand();
  Type *pointerType = pointerOperand->getType();
  Instruction *insertAt = getNextInstruction(storeInst);
  //    DEBUG_MSG(errs() << "handleStore: " << *storeInst << "\n");
  if (isa<VectorType>(valueType)) {
    const VectorType *vectorType = dyn_cast<VectorType>(valueType);
    if (isa<PointerType>(vectorType->getElementType())) {
      //      handleVectorStore(storeInst);
      return;
    }
  }
  /**
   * If a pointer is stored, the corresponding unique_id must be stored in the
   * shadow space
   */
  if (!isa<PointerType>(valueType)) {
    return;
  }
  //    DEBUG_MSG(errs() << "handleStore: " << *storeInst << "\n");
  if (isa<ConstantPointerNull>(valueOperand)) {
    insertMetadataStores(pointerOperand, m_void_null_ptr, m_constant_zero,
                         m_constant_zero, insertAt);
    return;
  }

  if (isa<GlobalVariable>(valueOperand)) {
    insertMetadataStores(pointerOperand, valueOperand, m_constant_one,
                         m_constant_one, insertAt);
    insertMetadataStores(valueOperand, valueOperand, m_constant_one,
                         m_constant_one, insertAt);
    return;
  }

  /**
   * if it is a global expression being stored, then add suitable unique_id
   */

  Value *obj_size = m_constant_zero;
  Value *obj_id = m_constant_zero;
  Value *obj_addr = m_void_null_ptr;
  if (isa<Constant>(valueOperand)) {
    Constant *constant = dyn_cast<Constant>(valueOperand);
    obj_id = m_constant_one;
    obj_addr = valueOperand;
  } else {
    if (!checkUniqueIdMetadataPresent(valueOperand)) {
      return;
    }
    obj_id = getAssociatedObjId(valueOperand);
    obj_addr = getAssociatedObjAddr(valueOperand);
  }
  //    DEBUG_MSG(errs() << "handleStore: " << *storeInst << "\n");
  //    DEBUG_MSG(errs() << "insertAt: " << *insertAt << "\n");
  insertMetadataStores(pointerOperand, obj_addr, obj_size, obj_id, insertAt);
}

void BAPS::handleInvoke(InvokeInst *invokeInst) {
  /**
   * we allocate stack variable unique_id also in stack,
   * so we don't need to explicitly free it
   * because it will be freed automatically
   */
  //    InvokeInst *inst = invokeInst;
}

/**
 * getConstantExprBaseBound()
 * This function uniform handles all global constant expression and
 * obtains the base and bound for these expressions
 * @param constant
 * @param begin
 * @param end
 */
void BAPS::getConstantExprBaseBound(Constant *constant, Value *&begin,
                                    Value *&end) {
  if (isa<ConstantPointerNull>(constant)) {
    begin = m_void_null_ptr;
    end = m_void_null_ptr;
    return;
  }
  ConstantExpr *constantExpr = dyn_cast<ConstantExpr>(constant);
  begin = m_void_null_ptr;
  end = m_void_null_ptr;
}

Value *BAPS::getAssociatedObjId(Value *pointerOperand) {
  if (checkUniqueIdMetadataPresent(pointerOperand)) {
    return m_pointer_obj_id[pointerOperand];
  }
  return m_constant_zero;
}

Value *BAPS::getAssociatedObjAddr(Value *pointerOperand) {
  if (checkObjAddrMetadataPresent(pointerOperand)) {
    return m_pointer_obj_addr[pointerOperand];
  }
  return m_void_null_ptr;
}

bool BAPS::checkObjAddrMetadataPresent(Value *inst) {
  if (m_pointer_obj_addr.count(inst)) {
    return true;
  }
  return false;
}

bool BAPS::checkUniqueIdMetadataPresent(Value *inst) {
  if (m_pointer_obj_id.count(inst)) {
    return true;
  }
  return false;
}

/**
 * insertMetadataLoads()
 * @param loadInst
 */

void BAPS::insertMetadataLoads(LoadInst *loadInst) {
  SmallVector<Value *, 8> args;
  Instruction *inst = loadInst;
  Instruction *insertAt = getNextInstruction(inst);
  /* If the inst returns a pointer, then load the obj_addr and obj_id
   * from the shadow space
   */
  Value *pValue = loadInst->getPointerOperand();
  Value *voidPtr = castToVoidPtr(pValue, insertAt);

  IRBuilder<> IRB(insertAt);
  args.clear();
  args.push_back(voidPtr);
  Instruction *obj_id = nullptr;
  Instruction *obj_addr = nullptr;
  obj_id =
      IRB.CreateCall(m_baps_load_trie_pointer_metadata_unique_id, args, "");
  obj_addr = IRB.CreateCall(m_baps_load_trie_pointer_metadata_obj, args, "");
  Value *value = loadInst;
  associateObjIdAndAddr(value, obj_id, obj_addr);
}

Instruction *BAPS::getNextInstruction(Instruction *instruction) {
  if (isa<TerminatorInst>(instruction)) {
    return instruction;
  } else {
    //        BasicBlock *bb = instruction->getParent();
    //        for (BasicBlock::iterator ib = bb->begin(), ie = bb->end(); ib !=
    //        ie; ++ib) {
    //            if (instruction == dyn_cast<Instruction>(ib)) {
    //                ++ib;
    //                return &*ib;
    //            }
    //        }
    BasicBlock::iterator i(instruction);
    ++i;
    return &*i;
  }
}

bool BAPS::checkArgsHasPtrType(Argument *argument) {
  if (!argument->hasByValAttr()) {
    return false;
  }
  SequentialType *sequentialType =
      dyn_cast<SequentialType>(argument->getType());
  assert(sequentialType &&
         "[byval] attribute with non-sequential type pointer");

  StructType *structType =
      dyn_cast<StructType>(sequentialType->getElementType());
  if (structType) {
    bool hasPtrs = checkPtrsInStructType(structType);
    return hasPtrs;
  } else {
    assert(structType && "non-struct byval parameters?");
  }
  // By default we assume any struct can return pointers
  return true;
}

bool BAPS::checkPtrsInStructType(StructType *structType) {
  errs() << "we are calling checkPtrsInStructType()\n";
  bool ptrFlag = true;
  for (StructType::element_iterator ei = structType->element_begin(),
                                    ee = structType->element_end();
       ei != ee; ++ei) {
    Type *elementType = *ei;
    if (isa<StructType>(elementType)) {
      assert(0 && "struct type has some element also is struct type ");
      StructType *structElementType = dyn_cast<StructType>(elementType);
      bool recursiveFlag = checkPtrsInStructType(structElementType);
      ptrFlag = ptrFlag | recursiveFlag;
    }
    if (isa<PointerType>(elementType)) {
      ptrFlag = true;
    }
    if (isa<ArrayType>(elementType)) {
      ptrFlag = true;
    }
  }
  return ptrFlag;
}

/**
 * associateBaseBound()
 * This function associates the base/bound, i.e., begin/end with the pointer
 * operand in the BAPS maps;
 * @param pointerOperand
 * @param begin
 * @param end
 */
void BAPS::associateBaseBound(Value *pointerOperand, Value *begin, Value *end) {
  if (m_pointer_begin.count(pointerOperand)) {
    disassociateBaseBound(pointerOperand);
  }
  if (begin->getType() != m_void_ptr_type) {
    assert(begin->getType() && "begin/base does not have a void pointer type");
  }
  m_pointer_begin[pointerOperand] = begin;
  if (m_pointer_end.count(pointerOperand)) {
    assert(m_pointer_end.count(pointerOperand) &&
           "end/bound map already has an entry in the map");
  }
  if (end->getType() != m_void_ptr_type) {
    assert(end->getType() &&
           "end/(base+bound) does not have a void pointer type");
  }
  m_pointer_end[pointerOperand] = end;
}

void BAPS::disassociateBaseBound(Value *pointerOperand) {
  if (m_pointer_begin.count(pointerOperand)) {
    m_pointer_begin.erase(pointerOperand);
  }
  if (m_pointer_end.count(pointerOperand)) {
    m_pointer_end.erase(pointerOperand);
  }
  assert((m_pointer_begin.count(pointerOperand) == 0) &&
         "dissociating base failed\n");
  assert((m_pointer_end.count(pointerOperand) == 0) &&
         "dissociating bound failed");
}

/**
 *
 * @param pointerOperand
 * @param unique_id
 * @param obj_addr
 */
void BAPS::associateObjIdAndAddr(Value *pointerOperand, Value *unique_id,
                                 Value *obj_addr) {
  if (m_pointer_obj_id.count(pointerOperand)) {
    disassociateObjIdAndAddr(pointerOperand);
  }
  if (unique_id->getType() != m_unique_id_type) {
    assert(key->getType() && "key does not the right type ");
  }
  m_pointer_obj_id[pointerOperand] = unique_id;
  if (m_pointer_obj_addr.count(pointerOperand)) {
    disassociateObjIdAndAddr(pointerOperand);
  }
  m_pointer_obj_addr[pointerOperand] = obj_addr;
}

void BAPS::disassociateObjIdAndAddr(Value *pointerOperand) {
  if (m_pointer_obj_id.count(pointerOperand)) {
    m_pointer_obj_id.erase(pointerOperand);
  }
  assert(m_pointer_obj_id.count(pointerOperand) == 0 &&
         "disassociateObjIdAndAddr() failed");
  if (m_pointer_obj_addr.count(pointerOperand)) {
    m_pointer_obj_addr.erase(pointerOperand);
  }
  assert(m_pointer_obj_addr.count(pointerOperand) == 0 &&
         "disassociateObjIdAndAddr() failed");
}

/**
 * introduceShadowStackLoads()
 * This function introduces calls to perform the loads from the shadow stack to
 * retrieve the metadata. This function also associates the loaded metadata with
 * the pointer arguments in the BAPS maps.
 * @param value
 * @param insertAt
 * @param argCount
 */

void BAPS::introduceShadowStackLoads(Value *value, Instruction *insertAt,
                                     int argCount) {

  if (!isa<PointerType>(value->getType())) {
    return;
  }

  Value *argNumber;
  argNumber = ConstantInt::get(Type::getInt32Ty(value->getType()->getContext()),
                               argCount, false);
  SmallVector<Value *, 8> args;
  IRBuilder<> IRB(insertAt);

  args.clear();
  args.push_back(argNumber);

  Value *obj_id =
      IRB.CreateCall(m_baps_shadow_stack_pointer_load_unique_id, args);
  args.clear();
  args.push_back(argNumber);
  Value *obj_addr = IRB.CreateCall(m_baps_shadow_stack_pointer_load_obj, args);

  associateObjIdAndAddr(value, obj_id, obj_addr);
}

/**
 * introduceShadowStackStores()
 * @param value
 * @param insertAt
 * @param argCount
 */

void BAPS::introduceShadowStackStores(Value *value, Instruction *insertAt,
                                      int argCount) {

  if (!isa<PointerType>(value->getType())) {
    return;
  }

  Value *argNumber;
  argNumber = ConstantInt::get(Type::getInt32Ty(value->getType()->getContext()),
                               argCount, false);
  SmallVector<Value *, 8> args;
  IRBuilder<> IRB(insertAt);

  Value *obj_id = getAssociatedObjId(value);
  if (obj_id == nullptr) {
    obj_id = m_constant_zero;
  }

  args.clear();
  args.push_back(obj_id);
  args.push_back(argNumber);
  IRB.CreateCall(m_baps_shadow_stack_pointer_store_unique_id, args);

  Value *obj_addr = getAssociatedObjAddr(value);
  if (obj_addr == nullptr) {
    obj_addr = m_void_null_ptr;
  }
  args.clear();
  args.push_back(obj_addr);
  args.push_back(argNumber);
  IRB.CreateCall(m_baps_shadow_stack_pointer_store_obj, args);
}

/**
 * getLocalObjId()
 * This function introduces a memory allocation call for allocating shadow stack
 * frames for the stack frames on function entry. This function also stores the
 * unique_id in the reference Value* arguments provided to the function.
 * Further, unique_id is allocated only when temporal checking is performed.
 * @param function Function* of the function performing the allocation
 * @param unique_id Value* & is the reference_argument to return the unique_id
 */
void BAPS::getLocalObjId(Function *function, Value *&unique_id) {
  if (!isAllocaPresent(function)) {
    return;
  }

  unique_id = nullptr;
  Instruction *allocInst = nullptr;
  allocInst = dyn_cast<Instruction>(function->begin()->begin());
  assert(allocInst && "allocInst failed due to function->begin() is null?");
  addMemoryAllocationCall(function, unique_id, allocInst);
  return;
}

void BAPS::freeLocalObjId(Function *function, Value *&unique_id) {
  /**
   * we allocate stack variable unique_id also in stack,
   * so we don't need to explicitly free it
   * because it will be freed automatically
   */
}

/**
 * addMemoryAllocationCall()
 * This function introduces a call to allocating unique_id for stack frames.
 * After the call, it performs the load of the unique_id to use it as the
 * metadata for pointers pointing to stack allocations in the function.
 * @param function Function for which the key and the lock is being allocated
 * @param insertAt Instruction* before which the function call is introduced
 */
void BAPS::addMemoryAllocationCall(Function *function, Value *&unique_id,
                                   Instruction *insertAt) {
  SmallVector<Value *, 8> args;
  Instruction *firstInst = insertAt;
  //    Instruction *firstInst =
  //    dyn_cast<Instruction>(function->begin()->begin());
  IRBuilder<> IRB(firstInst);
  AllocaInst *allocaInst = IRB.CreateAlloca(
      Type::getInt64Ty(function->getContext()), nullptr, "alloca.uniqueId");
  IRB.CreateStore(m_constant_two, allocaInst, false);
  LoadInst *loadInst = IRB.CreateLoad(allocaInst, "load.uniqueId");
  unique_id = loadInst;
}

void BAPS::introduceDereferenceCheck(Function *function) {

  if (function->isVarArg()) {
    return;
  }

  // Temporal Check Optimizations

  m_dominator_tree = &getAnalysis<DominatorTreeWrapperPass>(*function);

  /* WorkList Algorithm for introducing dereference checks. Each basic
   * block is visited only once. We start by visiting the current
   * basic block, then pushing all the successors of the current
   * basic block on to the queue if it has not been visited
   */

  std::set<BasicBlock *> bb_visited;
  std::queue<BasicBlock *> bb_worklist;
  Function::iterator bb_iterator = function->begin();

  BasicBlock *bb = dyn_cast<BasicBlock>(bb_iterator);
  assert(bb && "bb is not a basic block ?");
  bb_worklist.push(bb);

  while (bb_worklist.size() != 0) {
    bb = bb_worklist.front();
    assert(bb && "bb is not a basic block ?");

    bb_worklist.pop();

    if (bb_visited.count(bb)) {
      /**
       * this basic block has been visited
       */
      continue;
    }
    /**
     * if here implies basic block bb is not visited, insert the basic block
     * into bb_visited
     */

    bb_visited.insert(bb);
    /**
     * Iterating over the successors and adding the successors to the work list,
     * i.e., bb_worklist
     */

    for (succ_iterator si = succ_begin(bb), se = succ_end(bb); si != se; ++si) {
      BasicBlock *next_bb = *si;
      assert(next_bb && "it is not a basic block?");
      bb_worklist.push(next_bb);
    }

    /* basic block temporal check optimization */
    std::map<Value *, int> bbCheckOptMap;
    /* structure check optimization */
    std::map<Value *, int> bbStructCheckOpt;

    for (BasicBlock::iterator i = bb->begin(), e = bb->end(); i != e; ++i) {
      Value *value = dyn_cast<Value>(i);
      Instruction *inst = dyn_cast<Instruction>(i);

      /*
       * do the dereference check stuff
       */

      if (!m_inst_present_in_original.count(value)) {
        continue;
      }
      switch (inst->getOpcode()) {
      case Instruction::Load: {
        introduceLoadInstCheck(inst, bbCheckOptMap);
        break;
      }
      case Instruction::Store: {
        introduceStoreInstCheck(inst, bbCheckOptMap);
        break;
      }
      case Instruction::Call: {
        //        introduceCallInstCheck(inst, bbCheckOptMap);
        break;
      }
      case Instruction::Invoke: {
        break;
      }
      default: {
        break;
      }
      }
    }
  }
}

void BAPS::introduceLoadInstCheck(Instruction *inst,
                                  std::map<Value *, int> &bbCheckOptMap) {
  /**
   * this function only handle LoadInst
   * if passed inst is not a LoadInst, we just return
   */
  if (!isa<LoadInst>(inst)) {
    return;
  }

  /**
   * from now on, we start to handle inst
   */

  if (optimizeLoadInstPtrVariableCheck(inst)) {
    return;
  }

  //  if (optimizeBasicBlockCheck(inst, bbCheckOptMap)){
  //    return;
  //  }

  SmallVector<Value *, 8> args;
  Value *pointerOperand = nullptr;

  LoadInst *loadInst = dyn_cast<LoadInst>(inst);
  assert(loadInst && "inst is null, i.e., inst is not a LoadInst ?");
  pointerOperand = loadInst->getPointerOperand();
  assert(pointerOperand && "pointerOperand is a nullptr?");

  Type *type = loadInst->getType();
  //    DEBUG_MSG(errs() << "[introduceLoadInstCheck]: " << *inst << "\n");
  //    DEBUG_MSG(errs() << "[introduceLoadInstCheck]: " << *type << "\n");
  //    DEBUG_MSG(errs() << "[introduceLoadInstCheck]: " << type->isPointerTy()
  //    << "\n"); if (type->isPointerTy()) {
  //        return;
  //    }

  Value *obj_id = nullptr;
  Value *obj_addr = nullptr;
  obj_id = getAssociatedObjId(pointerOperand);
  obj_addr = getAssociatedObjAddr(pointerOperand);
  assert(uniqueId && "[introduceTemporalCheck] pointer does not have obj_id?");
  Value *dest = castToVoidPtr(pointerOperand, inst);
  args.push_back(dest);
  args.push_back(obj_id);
  args.push_back(obj_addr);
  CallInst::Create(m_baps_pointer_dereference_check, args, "", inst);
  return;
}

void BAPS::introduceStoreInstCheck(Instruction *inst,
                                   std::map<Value *, int> &bbCheckOptMap) {
  /**
   * this function only handle LoadInst
   * if passed inst is not a LoadInst, we just return
   */
  if (!isa<StoreInst>(inst)) {
    return;
  }

  /**
   * from now on, we start to handle inst
   */

  if (optimizeStoreInstPtrVariableCheck(inst)) {
    return;
  }

  //  if (optimizeBasicBlockCheck(inst, bbCheckOptMap)){
  //    return;
  //  }

  SmallVector<Value *, 8> args;
  Value *pointerOperand = nullptr;

  StoreInst *storeInst = dyn_cast<StoreInst>(inst);
  assert(storeInst && "inst is null, i.e., inst is not a LoadInst ?");
  pointerOperand = storeInst->getPointerOperand();
  assert(pointerOperand && "pointerOperand is a nullptr?");

  Type *type = storeInst->getType();
  //    DEBUG_MSG(errs() << "[introduceStoreInstCheck]: " << *inst << "\n");
  //    DEBUG_MSG(errs() << "[introduceStoreInstCheck]: " << *type << "\n");
  //    DEBUG_MSG(errs() << "[introduceStoreInstCheck]: " << type->isPointerTy()
  //    << "\n"); if (type->isPointerTy()) {
  //        return;
  //    }

  Value *obj_id = nullptr;
  Value *obj_addr = nullptr;
  obj_id = getAssociatedObjId(pointerOperand);
  obj_addr = getAssociatedObjAddr(pointerOperand);
  assert(uniqueId && "[introduceTemporalCheck] pointer does not have obj_id?");
  Value *dest = castToVoidPtr(pointerOperand, inst);
  args.push_back(dest);
  args.push_back(obj_id);
  args.push_back(obj_addr);
  CallInst::Create(m_baps_pointer_dereference_check, args, "", inst);
  return;
}

void BAPS::introduceCallInstCheck(Instruction *inst,
                                  std::map<Value *, int> &bbCheckOptMap) {
  /**
   * this function only handle CallInst
   * if passed inst is not a LoadInst, we just return
   */
  if (!isa<CallInst>(inst)) {
    return;
  }

  CallInst *callInst = dyn_cast<CallInst>(inst);
  Function *calleeFunction = callInst->getCalledFunction();

  if (calleeFunction && calleeFunction->getName().find("llvm.memset") == 0) {
    //        DEBUG_MSG(errs()<<"llvm.memset: "<<*callInst<<"\n");
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm.memcpy") == 0)) {
    //        DEBUG_MSG(errs()<<"llvm.memcpy: "<<*callInst<<"\n");
    handleMemcpy(callInst);
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm.memmove") == 0)) {
    return;
  }

  if (calleeFunction && (calleeFunction->getName().find("llvm") == 0)) {
    return;
  }

  if (calleeFunction && isFuncDefByBAPS(calleeFunction->getName())) {
    if (!isa<PointerType>(callInst->getType())) {
      return;
    }
    associateObjIdAndAddr(callInst, m_constant_zero, m_constant_zero);
    return;
  }

  /**
   * this function only handle CallInst with pointer type argument
   */
  int numPointerArgsAndReturn = getNumOfPtrArgsAndReturn(callInst);
  if (numPointerArgsAndReturn == 0) {
    return;
  }

  /**
   * from now on, we start to handle inst
   */

  SmallVector<Value *, 8> args;

  CallSite cs(callInst);

  for (unsigned i = 0; i < cs.arg_size(); ++i) {
    Value *argValue = cs.getArgument(i);
    if (isa<PointerType>(argValue->getType())) {
      Value *dest = castToVoidPtr(argValue, inst);
      Value *obj_id = nullptr;
      Value *obj_addr = nullptr;
      obj_id = getAssociatedObjId(argValue);
      obj_addr = getAssociatedObjAddr(argValue);

      args.clear();
      args.push_back(dest);
      args.push_back(obj_id);
      args.push_back(obj_addr);
      CallInst::Create(m_baps_pointer_dereference_check, args, "", inst);
    }
  }
}

bool BAPS::optimizeLoadInstPtrVariableCheck(Instruction *inst) {
  /**
   * this function only handle LoadInst
   * if passed inst is not a LoadInst, we just return
   */
  if (!isa<LoadInst>(inst)) {
    /**
     * return true, which means we just omit this inst
     */
    return true;
  }

  LoadInst *loadInst = dyn_cast<LoadInst>(inst);
  Value *pointerOperand = nullptr;
  pointerOperand = loadInst->getPointerOperand();

  if (isa<ConstantPointerNull>(pointerOperand)) {
    return true;
  }

  if (isa<GlobalVariable>(pointerOperand)) {
    return true;
  }

  if (isa<Constant>(pointerOperand)) {
    return true;
  }

  while (true) {
    if (isa<GlobalVariable>(pointerOperand)) {
      return true;
    }
    if (isa<AllocaInst>(pointerOperand)) {
      return true;
    }
    if (isa<BitCastInst>(pointerOperand)) {
      BitCastInst *bitCastInst = dyn_cast<BitCastInst>(pointerOperand);
      assert(0 && "BitCastInst in optimizeGlobalAndStackVariableChecks");
      pointerOperand = bitCastInst->getOperand(0);
      continue;
    }
    if (isa<GetElementPtrInst>(pointerOperand)) {
      GetElementPtrInst *getElementPtrInst =
          dyn_cast<GetElementPtrInst>(pointerOperand);
      assert(0 && "GetElementPtrInst in optimizeGlobalAndStackVariableChecks");
      pointerOperand = getElementPtrInst->getOperand(0);
      continue;
    } else {
      return false;
    }
  }
}

bool BAPS::optimizeStoreInstPtrVariableCheck(Instruction *inst) {
  /**
   * this function only handle LoadInst
   * if passed inst is not a LoadInst, we just return
   */
  if (!isa<StoreInst>(inst)) {
    /**
     * return true, which means we just omit this inst
     */
    return true;
  }

  StoreInst *storeInst = dyn_cast<StoreInst>(inst);
  Value *pointerOperand = nullptr;
  pointerOperand = storeInst->getPointerOperand();

  if (isa<ConstantPointerNull>(pointerOperand)) {
    return true;
  }

  if (isa<GlobalVariable>(pointerOperand)) {
    return true;
  }

  if (isa<Constant>(pointerOperand)) {
    return true;
  }

  while (true) {
    if (isa<GlobalVariable>(pointerOperand)) {
      return true;
    }
    if (isa<AllocaInst>(pointerOperand)) {
      return true;
    }
    if (isa<BitCastInst>(pointerOperand)) {
      BitCastInst *bitCastInst = dyn_cast<BitCastInst>(pointerOperand);
      assert(0 && "BitCastInst in optimizeGlobalAndStackVariableChecks");
      pointerOperand = bitCastInst->getOperand(0);
      continue;
    }
    if (isa<GetElementPtrInst>(pointerOperand)) {
      GetElementPtrInst *getElementPtrInst =
          dyn_cast<GetElementPtrInst>(pointerOperand);
      assert(0 && "GetElementPtrInst in optimizeGlobalAndStackVariableChecks");
      pointerOperand = getElementPtrInst->getOperand(0);
      continue;
    } else {
      return false;
    }
  }
}

bool BAPS::optimizeBasicBlockCheck(Instruction *inst,
                                   std::map<Value *, int> &bbOptMap) {
  if (bbOptMap.count(inst)) {
    return true;
  }
  Value *pointerOperand = getPointerLoadOrStore(inst);
  Value *gepSource = nullptr;
  if (isa<GetElementPtrInst>(pointerOperand)) {
    GetElementPtrInst *getElementPtrInst =
        dyn_cast<GetElementPtrInst>(pointerOperand);
    gepSource = getElementPtrInst->getOperand(0);
  } else {
    gepSource = pointerOperand;
  };
  // Iterate over all other instructions in this basic block and look
  // for gep_instructions with the same source
  BasicBlock *currInstBB = inst->getParent();
  assert(currInstBB && "currInstBB null?");
  Instruction *nextInst = getNextInstruction(inst);
  BasicBlock *nextInstBB = nextInst->getParent();
  while (currInstBB == nextInstBB && nextInst != currInstBB->getTerminator()) {
    if (isa<CallInst>(nextInst)) {
      break;
    }
    if (checkLoadStoreSourceIsGEP(nextInst, gepSource)) {
      bbOptMap[nextInst] = 1;
    }
    nextInst = getNextInstruction(nextInst);
    nextInstBB = nextInst->getParent();
  }
  return false;
}

Value *BAPS::getPointerLoadOrStore(Instruction *inst) {
  Value *pointerOperand = nullptr;
  switch (inst->getOpcode()) {
  case Instruction::Load: {
    LoadInst *loadInst = dyn_cast<LoadInst>(inst);
    pointerOperand = loadInst->getPointerOperand();
    break;
  }
  case Instruction::Store: {
    StoreInst *storeInst = dyn_cast<StoreInst>(inst);
    pointerOperand = storeInst->getPointerOperand();
    break;
  }
  default: {
  }
  }
  assert((pointerOperand != nullptr) && "pointerOperand can not be nullptr");
  return pointerOperand;
}

bool BAPS::checkLoadStoreSourceIsGEP(Instruction *loadOrStoreInst,
                                     Value *gepSource) {
  Value *pointerOperand = nullptr;
  if (!isa<LoadInst>(loadOrStoreInst) && !isa<StoreInst>(loadOrStoreInst)) {
    return false;
  }
  if (isa<LoadInst>(loadOrStoreInst)) {
    pointerOperand = loadOrStoreInst->getOperand(0);
  }
  if (isa<StoreInst>(loadOrStoreInst)) {
    pointerOperand = loadOrStoreInst->getOperand(1);
  }
  assert((pointerOperand != nullptr) && "pointerOperand can not be nullptr");
  if (!isa<GetElementPtrInst>(pointerOperand)) {
    return false;
  }
  GetElementPtrInst *getElementPtrInst =
      dyn_cast<GetElementPtrInst>(pointerOperand);
  assert(getElementPtrInst && "getElementPtrInst");
  Value *getElementPtrInstOperand = getElementPtrInst->getOperand(0);
  if (getElementPtrInstOperand == gepSource) {
    return true;
  } else {
    return false;
  }
}

static void registerCountFunc(const PassManagerBuilder &,
                              legacy::PassManagerBase &PM) {

  PM.add(new BAPS());
}

// static RegisterStandardPasses
// RegisterCountFunc1(PassManagerBuilder::EP_OptimizerLast, registerCountFunc);
// static RegisterStandardPasses
// RegisterCountFunc2(PassManagerBuilder::EP_EnabledOnOptLevel0,
// registerCountFunc);
//
// static RegisterPass<BAPS> Y("doBAPS", "do BAPS Pass");

ModulePass *llvm::createBAPSPass() { return new BAPS(); }
