project(LLVMDemangle)

add_library(LLVMDemangle STATIC
  src/Demangle.cpp
  src/ItaniumDemangle.cpp
  src/MicrosoftDemangle.cpp
  src/MicrosoftDemangleNodes.cpp
  src/RustDemangle.cpp
)

target_include_directories(LLVMDemangle PUBLIC include/)
if (NOT MSVC)
  target_compile_options(LLVMDemangle PRIVATE -Wno-deprecated-declarations)
endif()