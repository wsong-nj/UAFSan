UAFSan is based on the LLVM 7.1 compiler infrastructure and consists of two parts: runtime library and instrumentation module.

How to compile LLVM/Clang-7.1 and UAFSan?
1. Install dependencies required to compile LLVM/Clang-7.1
	sudo apt install cmake autoconf gcc g++ git
2. Get the source code of LLVM/Clang-7.1.
   i) The first way is to download the source code from the website: https://releases.llvm.org/
   ii) The second way is to use the following scripts.
      export BRANCH=release_70
   	git clone http://llvm.org/git/llvm.git -b $BRANCH
   	git clone http://llvm.org/git/clang.git llvm/tools/clang -b $BRANCH
   	git clone http://llvm.org/git/clang-tools-extra.git llvm/tools/clang/tools/extra -b $BRANCH
   	git clone http://llvm.org/git/compiler-rt.git llvm/projects/compiler-rt -b $BRANCH
   iii) The third way is to use the source code under the directory LLVM/Clang-7.1
3. Configure the LLVM/Clang-7.1 and compile it.
      mkdir build && cd build
      cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_TESTS=OFF -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_EXAMPLES=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_ENABLE_ASSERTIONS=OFF ..
      make -j8
      sudo make install
4. Download the source code of UAFSan and copy the folders in the directory (instrumentation) to the corresponding LLVM source directory.
      rm -rf build && mkdir build && cd build
      cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_TESTS=OFF -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_EXAMPLES=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_ENABLE_ASSERTIONS=OFF ..
      make -j8
      sudo make install
5. After the above five steps, the instrumentation module has been compiled and integrated with LLVM/Clang-7.1.
6. The source code of the runtime library we provide is under the directory (runtime library). And the pre-built runtime library named libbaps.a is located in the cmake-build-debug directory.

How to use UAFSan?
The script to use UAFSan is as follows, where the libbaps.a is the runtime library, and the -fbaps flag is passed to clang to enable UAFSan.
   clang++ -fbaps ./libbaps.a -ldl -rdynamic -g -O0 main.c && ./a.out
If the instrumented program reports a UAF error, then UAFSan is compiled correctly. Then UAFSan can be used to detect UAFs in other programs.

The directory structure of the UAFSan repository is as follows:
--sourcecode
----instrumentation module
------include  //copy to llvm/include
------lib    //copy to llvm/lib
------clang // copy to llvm/tools/clang
----runtime library 
----test
------main.c
----LLVM/Clang-7.1
