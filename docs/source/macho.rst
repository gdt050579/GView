GView Specific Plugin: Mach-O
=============================

The Mach-O plugin parses Mach-O and Mach-O Fat binaries (macOS/iOS), including Go
binaries, with section/segment/symbol extraction and code signature validation.

References
----------

* **LLVM / Mach-O format**: `MachODump <https://opensource.apple.com/source/llvmCore/llvmCore-3425.0.36/tools/llvm-objdump/MachODump.cpp.auto.html>`__, `BinaryFormat/MachO.h <https://llvm.org/doxygen/BinaryFormat_2MachO_8h_source.html>`__, `MachO namespace <https://llvm.org/doxygen/namespacellvm_1_1MachO.html>`__, `SymbolTable.cpp <https://github.com/llvm/llvm-project/blob/ce2ae381246df89e560c0dfd0a7fdf275f266d9e/lld/MachO/SymbolTable.cpp>`__
* **Apple Security / codesign**: `Security <https://opensource.apple.com/source/Security>`__, `codesign.c <https://opensource.apple.com/source/Security/Security-59754.80.3/SecurityTool/sharedTool/codesign.c.auto.html>`__, `codedirectory.h <https://opensource.apple.com/source/libsecurity_codesigning/libsecurity_codesigning-55032/lib/codedirectory.h.auto.html>`__
* **cctools / otool**: `ofile_print.c <https://github.com/opensource-apple/cctools/blob/master/otool/ofile_print.c>`__
* **dyld**: `ImageLoaderMachO <https://opensource.apple.com/source/dyld/dyld-852.2/src/ImageLoaderMachO.cpp.auto.html>`__, `dyld <https://opensource.apple.com/source/dyld/dyld-852.2>`__, `MachOLoaded <https://opensource.apple.com/source/dyld/dyld-655.1.1/dyld3/MachOLoaded.cpp.auto.html>`__
* **XNU headers**: `mach-o/nlist.h <https://opensource.apple.com/source/xnu/xnu-4570.71.2/EXTERNAL_HEADERS/mach-o/nlist.h>`__, `mach-o/stab.h <https://opensource.apple.com/source/xnu/xnu-2050.18.24/EXTERNAL_HEADERS/mach-o/stab.h>`__
* **Third-party**: `macholib <https://macholib.readthedocs.io/en/latest>`__, `go-macho (blacktop) <https://github.com/blacktop/go-macho>`__, `LIEF MachO <https://github.com/lief-project/LIEF>`__, `zsign <https://github.com/zhlynn/zsign>`__, `osx-abi-macho-file-format-reference <https://github.com/aidansteele/osx-abi-macho-file-format-reference>`__
* **Articles**: `Code Signing (newosxbook) <http://www.newosxbook.com/articles/CodeSigning.pdf>`__, `Mach-O (redmaple) <https://redmaple.tech/blogs/macho-files>`__, `iOS code signature <http://xelz.info/blog/2019/01/11/ios-code-signature>`__
* **Validation**: `validate_macho_sig.py <https://gist.github.com/laanwj/a0e00bcd3fe4cd2aa1c0803e91310495>`__
