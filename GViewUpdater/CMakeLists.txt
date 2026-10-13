cmake_minimum_required(VERSION 3.15)

# GViewUpdater: installs an update staged by GView (see GViewUpdater/src/Apply.hpp).
# It must not depend on GViewCore, AppCUI or any vcpkg library: it runs while those binaries are being replaced.
project(GViewUpdater VERSION 1.0 LANGUAGES CXX)

add_executable(GViewUpdater
    src/main.cpp
    src/Apply.cpp
    src/Apply.hpp
)
set_target_properties(GViewUpdater PROPERTIES CXX_STANDARD 20 CXX_STANDARD_REQUIRED ON)

if (MSVC)
    # static CRT: no runtime DLL may be loaded from the folder being updated
    set_property(TARGET GViewUpdater PROPERTY MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    include(windows_resource)
    add_windows_resource("GViewUpdater.exe" "GViewUpdater.rc")
endif()

if (APPLE)
    if (CMAKE_GENERATOR STREQUAL "Xcode")
        set_target_properties(${PROJECT_NAME} PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}"
            RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_BINARY_DIR}/../bin/${CMAKE_BUILD_TYPE}")
    endif()
endif()
