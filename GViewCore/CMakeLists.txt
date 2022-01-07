cmake_minimum_required(VERSION 3.13)

# Project setup
project(GViewCore VERSION 1.0)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
add_library(GViewCore SHARED)
set_target_properties(GViewCore PROPERTIES PREFIX "lib")
target_compile_definitions(GViewCore PRIVATE -DBUILD_AS_DYNAMIC_LIB)
target_compile_definitions(GViewCore PRIVATE -DCORE_EXPORTABLE)

if (MSVC)
    add_definitions(-DBUILD_FOR_WINDOWS)
    add_compile_options(-W3)
elseif (APPLE)
    add_definitions(-DBUILD_FOR_OSX)
    if (DEBUG_BUILD)
        add_compile_options(-g)
        add_compile_options(-W)
    endif()
elseif (UNIX)
    add_definitions(-DBUILD_FOR_UNIX)
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
add_subdirectory(src)


file(GLOB_RECURSE GVIEWCORE_HEADERS include/*.hpp)
target_sources(GViewCore PRIVATE ${GVIEWCORE_HEADERS})
get_target_property(GVIEWCORE_SOURCES GViewCore SOURCES)
source_group(TREE ${CMAKE_SOURCE_DIR}/GViewCore FILES ${GVIEWCORE_SOURCES} ${GVIEWCORE_HEADERS})

