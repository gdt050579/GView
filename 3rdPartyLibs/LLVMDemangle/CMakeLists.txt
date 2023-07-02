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

  if (APPLE)
    if (CMAKE_GENERATOR STREQUAL "Xcode")
        set_target_properties(${PROJECT_NAME} PROPERTIES
            ARCHIVE_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            LIBRARY_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            ARCHIVE_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            LIBRARY_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}")
    endif()
  endif()
endif()