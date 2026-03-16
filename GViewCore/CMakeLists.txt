cmake_minimum_required(VERSION 3.13)

# Project setup
project(GViewCore VERSION 1.0)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)

if(NOT DEFINED CMAKE_TESTING_ENABLED)
    add_library(${PROJECT_NAME} SHARED)
else()
    add_executable(${PROJECT_NAME})

    find_package(Catch2 CONFIG REQUIRED)
    target_link_libraries(${PROJECT_NAME} PRIVATE Catch2::Catch2WithMain) # Catch2::Catch2

    include(CTest)
    include(Catch)
    catch_discover_tests(${PROJECT_NAME})
endif()

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "lib")
target_compile_definitions(${PROJECT_NAME} PRIVATE -DBUILD_AS_DYNAMIC_LIB)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DCORE_EXPORTABLE)
target_include_directories(${PROJECT_NAME} PRIVATE ../3rdPartyLibs/LLVMDemangle/include)
target_link_libraries(${PROJECT_NAME} PRIVATE LLVMDemangle)
                                                             
find_package(OpenSSL REQUIRED)
target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_CRYPTO_LIBRARY})

find_package(ZLIB REQUIRED)
message("ZLIB_INCLUDE_DIR => ${ZLIB_INCLUDE_DIR}")
message("ZLIB_LIBRARIES => ${ZLIB_LIBRARIES}")
target_include_directories(${PROJECT_NAME} PRIVATE ${ZLIB_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE ${ZLIB_LIBRARIES})

find_package(capstone CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE capstone::capstone)

find_package(minizip-ng CONFIG REQUIRED)
message(STATUS "minizip-ng_DIR => ${minizip-ng_DIR}")

# vcpkg directory structure
get_filename_component(MINIZIP_SHARE_INCLUDE_DIR ${minizip-ng_DIR} DIRECTORY)
get_filename_component(MINIZIP_PARENT_DIR ${MINIZIP_SHARE_INCLUDE_DIR} DIRECTORY)
set(MINIZIP_INCLUDE_DIR "${MINIZIP_PARENT_DIR}/include/minizip-ng")

message(STATUS "MINIZIP_INCLUDE_DIR => ${MINIZIP_INCLUDE_DIR}")
target_include_directories(${PROJECT_NAME} PRIVATE ${MINIZIP_INCLUDE_DIR})
target_link_libraries(${PROJECT_NAME} PRIVATE MINIZIP::minizip-ng)

message(STATUS "SQLITE3_INCLUDE_DIR => ${SQLITE3_INCLUDE_DIR}")
find_package(unofficial-sqlite3 CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE unofficial::sqlite3::sqlite3)

find_package(re2 CONFIG REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE re2::re2)

find_package(CURL REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE CURL::libcurl)

find_package(nlohmann_json REQUIRED)
target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)

if (MSVC)
    add_compile_options(-W3)
elseif (APPLE)
    if (DEBUG_BUILD)
        add_compile_options(-g)
        add_compile_options(-W)
    endif()
elseif (UNIX)
    if (DEBUG_BUILD)
        add_compile_options(-g)
        add_compile_options(-W)
    endif()
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

if (NOT DEBUG_BUILD)
    if (MSVC)
        #add_compile_options(-O2)
        add_compile_options(-Ob2)
	#string( REPLACE "/RTC1" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} )
    else()
        add_compile_options(-O3)
    endif()
endif()

target_include_directories(GViewCore PUBLIC ../AppCUI)
target_link_libraries(GViewCore PUBLIC AppCUI)

include_directories(include)
include_directories(src/include)
include_directories(src/View/BufferViewer)
include_directories(src/View/ImageViewer)
include_directories(src/View/GridViewer)
include_directories(src/View/DissasmViewer)
include_directories(src/View/TextViewer)
include_directories(src/View/ContainerViewer)
include_directories(src/View/LexicalViewer)
include_directories(src/View/YaraViewer)
add_subdirectory(src)


file(GLOB_RECURSE GVIEWCORE_HEADERS include/*.hpp)
target_sources(GViewCore PRIVATE ${GVIEWCORE_HEADERS})
get_target_property(GVIEWCORE_SOURCES GViewCore SOURCES)
source_group(TREE ${CMAKE_SOURCE_DIR}/GViewCore FILES ${GVIEWCORE_SOURCES} ${GVIEWCORE_HEADERS})

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

if (MSVC)
    include(windows_resource)
    add_windows_resource("libGViewCore.dll" "GViewCore.rc")
endif()