cmake_minimum_required(VERSION 3.13)

# Project setup
project(SimpleWin VERSION 1.0)

add_executable(SimpleWin main.cpp)



target_include_directories(SimpleWin PUBLIC ../AppCUI)
target_link_libraries(SimpleWin PUBLIC AppCUI)



