cmake_minimum_required(VERSION 3.31)
project(oss_fuzz)

set(CMAKE_CXX_STANDARD 20)

add_library(oss_fuzz STATIC
        libpng_read_fuzzer.cc)
