cmake_minimum_required(VERSION 3.15)

# Do not force vcpkg to use the system tools (VCPKG_FORCE_SYSTEM_BINARIES), not even on Linux ARM: vcpkg downloads
# its own CMake and Ninja for arm64 too, and the system CMake 3.x can not run the vcpkg scripts any more.

set(CMAKE_TOOLCHAIN_FILE "${CMAKE_CURRENT_SOURCE_DIR}/AppCUI/vcpkg/scripts/buildsystems/vcpkg.cmake"
  CACHE STRING "Vcpkg toolchain file")

message("CMAKE_TOOLCHAIN_FILE => ${CMAKE_TOOLCHAIN_FILE}")

message("CMAKE_SYSTEM_PROCESSOR => ${CMAKE_SYSTEM_PROCESSOR}")
message("CMAKE_HOST_SYSTEM_PROCESSOR => ${CMAKE_HOST_SYSTEM_PROCESSOR}")
message("CMAKE_C_COMPILER_ARCHITECTURE_ID => ${CMAKE_C_COMPILER_ARCHITECTURE_ID}")

option(ENABLE_TESTS "Enable tests" OFF)
# Remote TUI (GView serve / connect / listen, docs/source/remote_protocol.rst): TLS 1.3 + mutual TLS over TCP.
# OFF by default: when disabled no networking code for the remote mode is compiled into GView.
option(GVIEW_ENABLE_REMOTE "Build the remote TUI client/server (TLS 1.3, mutual TLS, OpenSSL)" OFF)
message("GVIEW_ENABLE_REMOTE => ${GVIEW_ENABLE_REMOTE}")
set(CURRENT_PROJECT_NAME GView)
if (ENABLE_TESTS)
    message("ENALBED TESTING")
    enable_testing()
    set(CURRENT_PROJECT_NAME GViewTesting)
endif()

project(${CURRENT_PROJECT_NAME} VERSION 1.0 DESCRIPTION "GView - GenericViewer" LANGUAGES C CXX)

# WebAssembly (wasm32-emscripten, see docs/source/wasm.rst): GView runs inside a web page, where shared libraries can
# not be loaded and there is no network stack, worker thread or child process available to GView.
if (EMSCRIPTEN)
    set(GVIEW_STATIC_PLUGINS_DEFAULT ON)
    set(GVIEW_ENABLE_NETWORK_DEFAULT OFF)
    set(GVIEW_ENABLE_REMOTE OFF CACHE BOOL "Build the remote TUI client/server (TLS 1.3, mutual TLS, OpenSSL)" FORCE)
else()
    set(GVIEW_STATIC_PLUGINS_DEFAULT OFF)
    set(GVIEW_ENABLE_NETWORK_DEFAULT ON)
endif()
option(GVIEW_STATIC_PLUGINS "Link every plugin into the GView executable instead of loading it at runtime" ${GVIEW_STATIC_PLUGINS_DEFAULT})
# OFF: no libcurl - the auto-updater, Learning and Evaluation Mode, the Smart Assistant and FileDownloader are not
# available (the GViewUpdater helper is not built either)
option(GVIEW_ENABLE_NETWORK "Build the features that need network access (libcurl)" ${GVIEW_ENABLE_NETWORK_DEFAULT})
message("GVIEW_STATIC_PLUGINS => ${GVIEW_STATIC_PLUGINS}")
message("GVIEW_ENABLE_NETWORK => ${GVIEW_ENABLE_NETWORK}")
if (GVIEW_STATIC_PLUGINS)
    add_compile_definitions(GVIEW_STATIC_PLUGINS)
endif()
if (GVIEW_ENABLE_NETWORK)
    add_compile_definitions(GVIEW_ENABLE_NETWORK)
endif()

include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)

# no LTO for wasm32-emscripten: the link of the single GView module is already the slowest step
if( supported AND NOT EMSCRIPTEN )
	message(STATUS "${PROJECT_NAME} => IPO / LTO enabled")
	set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
	message(STATUS "${PROJECT_NAME} => IPO / LTO not supported: <${error}>")
endif()

# versioning
file(READ "GViewCore/include/GView.hpp" GView_content)
string(REGEX MATCH "#define GVIEW_VERSION \"([0-9]+.[0-9]+.[0-9]+)\"" _ ${GView_content})
set(GVIEW_VERSION ${CMAKE_MATCH_1})
message("${PROJECT_NAME} version: ${GVIEW_VERSION}")
string(REPLACE "." "," VERSION_LIST ${GVIEW_VERSION})
set(GVIEW_VERSION_LIST ${VERSION_LIST},0)

if (MSVC)
    set(GVIEW_RESOURCE_FILE_TEMPLATE "${CMAKE_CURRENT_SOURCE_DIR}/cmake/windows.rc.in")
endif()

set(CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(core_testing)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
if (NOT EMSCRIPTEN) # wasm32-emscripten links one static module (-fPIC would require dynamic linking)
    set(CMAKE_POSITION_INDEPENDENT_CODE ON)
endif()

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Debug" CACHE STRING 
	    "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." 
	    FORCE)
endif(NOT CMAKE_BUILD_TYPE)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
     set(DEBUG_BUILD 1)
endif()

if(NOT DEFINED GVIEW_BINARIES_OUT_DIR)
    set(GVIEW_BINARIES_OUT_DIR "${CMAKE_SOURCE_DIR}/bin/${CMAKE_BUILD_TYPE}")
endif()

if (NOT MSVC)
	set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${GVIEW_BINARIES_OUT_DIR})
	set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${GVIEW_BINARIES_OUT_DIR})
endif()
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${GVIEW_BINARIES_OUT_DIR})

foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
    if (NOT MSVC)
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${GVIEW_BINARIES_OUT_DIR})
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${GVIEW_BINARIES_OUT_DIR})
    endif()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} ${GVIEW_BINARIES_OUT_DIR} )
endforeach()

if (MSVC)
    add_definitions(-DBUILD_FOR_WINDOWS)
    add_compile_options(-W3 /MP)
    
elseif (APPLE)
    add_definitions(-DBUILD_FOR_OSX)
    if (DEBUG_BUILD)
        add_compile_options(-g)
        add_compile_options(-W)
    endif()
   
    SET(CMAKE_INSTALL_NAME_DIR @executable_path)
    message(STATUS "CMAKE_INSTALL_NAME_DIR => ${CMAKE_INSTALL_NAME_DIR}")
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH ON)
    SET(CMAKE_INSTALL_RPATH @executable_path)
    message(STATUS "CMAKE_INSTALL_RPATH => ${CMAKE_INSTALL_RPATH}")
    
    if(CMAKE_LINK_LIBRARY_USING_weak_library_SUPPORTED)
        message(STATUS "${PROJECT_NAME} => CMAKE_LINK_LIBRARY_USING_weak_library_SUPPORTED")
    	target_link_libraries(${PROJECT_NAME} PRIVATE "$<LINK_LIBRARY:weak_library,lib,external>")
    else()
        message(STATUS "${PROJECT_NAME} => NOT CMAKE_LINK_LIBRARY_USING_weak_library_SUPPORTED")
    	# target_link_libraries(${PROJECT_NAME} PRIVATE lib external)
    endif()
    
    # install(TARGETS ${CURSES_LIBRARIES} LIBRARY DESTINATION "." NAMELINK_ONLY)    
elseif (EMSCRIPTEN)
    # emscripten also sets UNIX: POSIX code paths (BUILD_FOR_UNIX) + BUILD_FOR_WASM for what the browser can not do
    add_definitions(-DBUILD_FOR_UNIX -DBUILD_FOR_WASM)
    add_compile_options(-W)
    # every translation unit must use the exception model AppCUI is built with (see AppCUI/CMakeLists.txt)
    if (APPCUI_WASM_JSPI)
        add_compile_options(-fwasm-exceptions)
        add_link_options(-fwasm-exceptions)
    else()
        add_compile_options(-fexceptions)
        add_link_options(-fexceptions)
    endif()
    # AppCUI is linked whole-archive (its frontends register themselves from static initializers)
    if (NOT CMAKE_LINK_LIBRARY_USING_WHOLE_ARCHIVE_SUPPORTED)
        set(CMAKE_LINK_LIBRARY_USING_WHOLE_ARCHIVE "LINKER:--whole-archive" "<LINK_ITEM>" "LINKER:--no-whole-archive")
        set(CMAKE_LINK_LIBRARY_USING_WHOLE_ARCHIVE_SUPPORTED TRUE)
    endif()
elseif (UNIX)
    add_definitions(-DBUILD_FOR_UNIX)
    add_compile_options(-g)
    add_compile_options(-W)
    
    SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,-rpath -Wl,$ORIGIN")
endif()

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang")
     add_compile_options(-Wall -Wextra
             -Wno-switch
             -Wpointer-arith
             -Wcast-qual
             -Wredundant-decls
             -Wctor-dtor-privacy
             -Wwrite-strings
             -Wdisabled-optimization
             -Wzero-as-null-pointer-constant
             -Wvla) # -pedantic
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 5.0)
    add_compile_options(-Wtrampolines -Wduplicated-cond -Wduplicated-branches -Wnull-dereference)
endif()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        set(CXX_FILESYSTEM_LIBRARIES "stdc++fs")
endif()


if (NOT DEBUG_BUILD)
    if (MSVC)
        add_compile_options(-Ob2)
    else()
        add_compile_options(-O3)
    endif()
endif()

if(DEFINED DISSASM_DEV)
    add_definitions(-DDISSASM_DEV)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(3rdPartyLibs/LLVMDemangle)

add_subdirectory(AppCUI)
add_subdirectory(GViewCore)

if(NOT DEFINED CMAKE_TESTING_ENABLED)
    add_subdirectory(GView)
    if (GVIEW_ENABLE_NETWORK) # helper of the auto-updater
        add_subdirectory(GViewUpdater)
    endif()
endif()

if (APPLE)
    if (CMAKE_GENERATOR STREQUAL "Xcode")
        foreach(OUTPUTCONFIG ${CMAKE_CONFIGURATION_TYPES})
            string(TOUPPER ${OUTPUTCONFIG} OUTPUTCONFIG)
            set_target_properties(${PROJECT_NAME} PROPERTIES
                ARCHIVE_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
                LIBRARY_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
                RUNTIME_OUTPUT_DIRECTORY_${OUTPUTCONFIG} "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            )
        endforeach()
    endif()
endif()

if(NOT DEFINED CMAKE_TESTING_ENABLED)
    # Types supported by GView
    add_subdirectory(Types/PE)
    add_subdirectory(Types/ICO)
    add_subdirectory(Types/CSV)
    add_subdirectory(Types/BMP)
    add_subdirectory(Types/MACHO)
    add_subdirectory(Types/ISO)
    add_subdirectory(Types/PREFETCH)
    add_subdirectory(Types/MAM)
    add_subdirectory(Types/LNK)
    add_subdirectory(Types/JOB)
    add_subdirectory(Types/PCAP)
    add_subdirectory(Types/ELF)
    add_subdirectory(Types/JT)
    add_subdirectory(Types/INI)
    add_subdirectory(Types/CPP)
    add_subdirectory(Types/JSON)
    add_subdirectory(Types/VBA)
    add_subdirectory(Types/JS)
    add_subdirectory(Types/PYEXTRACTOR)
    add_subdirectory(Types/ZIP)
    add_subdirectory(Types/SQLite)
    add_subdirectory(Types/JCLASS)
    add_subdirectory(Types/EML)
    add_subdirectory(Types/DOC)
    add_subdirectory(Types/JPG)
    add_subdirectory(Types/XML)
    if (NOT EMSCRIPTEN) # podofo, openjpeg, tiff and jbig2dec are not built for wasm32-emscripten
        add_subdirectory(Types/PDF)
    endif()

    # Generic plugins supported by GView
    add_subdirectory(GenericPlugins)

    if (GVIEW_STATIC_PLUGINS)
        include(static_plugins)
        gview_link_static_plugins(GView)
    endif()
                                    
    if (APPLE)
            set_property(TARGET "${PROJECT_NAME}" PROPERTY INSTALL_RPATH "@loader_path")
    elseif (UNIX)
        set_property(TARGET "${PROJECT_NAME}" PROPERTY INSTALL_RPATH "$ORIGIN")
    endif()
endif()