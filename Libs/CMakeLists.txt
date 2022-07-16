project(Libs)

set_property(GLOBAL PROPERTY USE_FOLDERS ON)
add_library(${PROJECT_NAME} SHARED)
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "lib")
set_target_properties(${PROJECT_NAME} PROPERTIES LINKER_LANGUAGE CXX)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DBUILD_AS_DYNAMIC_LIB)
target_compile_definitions(${PROJECT_NAME} PRIVATE -DCORE_EXPORTABLE)

if (NOT MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE -Wno-deprecated-declarations)
endif()

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
        add_compile_options(-Ob2)
    else()
        add_compile_options(-O3)
    endif()
endif()

target_include_directories(${PROJECT_NAME} PUBLIC ../AppCUI)
target_link_libraries(${PROJECT_NAME} PUBLIC AppCUI)

include_directories(include)
add_subdirectory(src)

file(GLOB_RECURSE LIBS_HEADERS include/*.hpp)
target_sources(${PROJECT_NAME} PRIVATE ${LIBS_HEADERS})
get_target_property(LIBS_SOURCES ${PROJECT_NAME} SOURCES)
source_group(TREE ${CMAKE_SOURCE_DIR}/${PROJECT_NAME} FILES ${LIBS_SOURCES} ${LIBS_HEADERS})
