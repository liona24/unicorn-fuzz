cmake_minimum_required(VERSION 3.0.0)
project(lfu VERSION 0.1.0)

add_library(lfu SHARED
    src/lfu.cpp
)

target_include_directories(lfu PRIVATE include/)

add_subdirectory(third_party/unicorn)
target_link_libraries(lfu PUBLIC unicorn)

target_compile_options(lfu PRIVATE
    -fsanitize=fuzzer
    -fno-sanitize-coverage=trace-pc-guard,edge,trace-cmp,indirect-calls,8bit-counters
)

target_compile_features(lfu PRIVATE cxx_std_17)
