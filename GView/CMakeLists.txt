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
    add_windows_resource("GView.exe" "GView.rc")
endif()

if (EMSCRIPTEN)
    # a static web site: GView.html + GView.mjs + GView.wasm, next to AppCUI's host script, font and dev server
    set_target_properties(GView PROPERTIES SUFFIX ".mjs")
    set(APPCUI_WEB_DIR "${CMAKE_SOURCE_DIR}/AppCUI/AppCUI/web")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/web/GView.html.in" "${GVIEW_BINARIES_OUT_DIR}/GView.html" @ONLY)
    configure_file("${APPCUI_WEB_DIR}/appcui-host.js" "${GVIEW_BINARIES_OUT_DIR}/appcui-host.js" COPYONLY)
    configure_file("${APPCUI_WEB_DIR}/serve.py" "${GVIEW_BINARIES_OUT_DIR}/serve.py" COPYONLY)
    configure_file("${CMAKE_SOURCE_DIR}/AppCUI/AppCUI/resources/JuliaMono-Regular.ttf" "${GVIEW_BINARIES_OUT_DIR}/JuliaMono-Regular.ttf" COPYONLY)
endif()