

add_llvm_loadable_module(LLVMCount
        Count.cpp

        DEPENDS
        intrinsics_gen
        PLUGIN_TOOL
        opt
        )

