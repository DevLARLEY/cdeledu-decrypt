cmake_minimum_required(VERSION 3.30 FATAL_ERROR)
project(cdeledu LANGUAGES C)

set(CMAKE_C_STANDARD 11)

add_executable(cdeledu main.c runtime.c wasm-rt-exceptions-impl.c wasm-rt-impl.c wasm-rt-mem-impl.c)

target_link_libraries(cdeledu m pthread)