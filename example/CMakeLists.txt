cmake_minimum_required(VERSION 4.1)
project(MemoryToolsCPP)

set(CMAKE_CXX_STANDARD 11)

add_executable(${CMAKE_PROJECT_NAME} example.cpp)

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE ../)