cmake_minimum_required(VERSION 3.28)
project(Chronus)

set(CMAKE_CXX_STANDARD 26)

add_executable(Chronus main.cpp
        Sources/Chronus.cpp
        Sources/MurmurHash3.cpp
        Sources/Lean.cpp
        Headers/Params.h
)
