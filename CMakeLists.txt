cmake_minimum_required(VERSION 3.15...3.30)

project(
    IATHook 
    VERSION 2.0
    DESCRIPTION "Import Address Table hook example"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(iathook src/main.cpp)