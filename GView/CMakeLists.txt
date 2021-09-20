cmake_minimum_required(VERSION 3.13)

# Project setup
project(GView VERSION 1.0)
add_executable(GView)

include_directories(include)
file(GLOB_RECURSE GVIEWMAIN_HEADERS include/*.hpp)
target_sources(GView PRIVATE ${GVIEWMAIN_HEADERS})

target_include_directories(GView PUBLIC ../AppCUI)
target_link_libraries(GView PUBLIC AppCUI)

target_include_directories(GView PUBLIC ../GViewCore)
target_link_libraries(GView PUBLIC GViewCore)

add_subdirectory(src)

file(GLOB_RECURSE GVIEW include/*.hpp)
target_sources(GView PRIVATE ${GVIEW_HEADERS})
get_target_property(GVIEW_SOURCES GView SOURCES)
source_group(TREE ${CMAKE_SOURCE_DIR}/GView FILES ${GVIEW_SOURCES} ${GVIEW_HEADERS})



