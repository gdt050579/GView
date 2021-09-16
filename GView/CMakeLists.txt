cmake_minimum_required(VERSION 3.13)

# Project setup
project(GView VERSION 1.0)

add_executable(GView main.cpp)

target_include_directories(GView PUBLIC ../AppCUI)
target_link_libraries(GView PUBLIC AppCUI)

target_include_directories(GView PUBLIC ../GViewCore)
target_link_libraries(GView PUBLIC GViewCore)


