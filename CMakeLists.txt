cmake_minimum_required(VERSION 3.0.0)
project(lfu VERSION 0.1.0)

include(FindPkgConfig)

find_package(LLVM REQUIRED)

if (LLVM_FOUND)
  message(STATUS "LLVM_VERSION: ${LLVM_VERSION}")
else()
  message(FATAL_ERROR "You need LLVM to build this.")
endif()

add_library(lfu SHARED
    src/lfu.cpp
    src/allocator.cpp
    src/coverage.cpp
    src/crash_collector.cpp
    src/abi.cpp
)

target_include_directories(lfu PRIVATE include/)

add_subdirectory(third_party/unicorn)
target_link_libraries(lfu PUBLIC unicorn)

target_link_libraries(lfu PRIVATE "${LLVM_LIBRARY_DIRS}/clang/${LLVM_VERSION}/lib/libclang_rt.fuzzer_no_main-x86_64.a")

target_compile_features(lfu PRIVATE cxx_std_17)

pkg_check_modules (CAPSTONE REQUIRED capstone)
if (CAPSTONE_FOUND)
  target_link_libraries(lfu PRIVATE ${CAPSTONE_LIBRARIES})
  target_include_directories(lfu PRIVATE ${CAPSTONE_INCLUDE_DIRS})
else()
  message(FATAL_ERROR "You need capstone to build this.")
endif()

add_custom_command(
    TARGET lfu POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_SOURCE_DIR}/python-bindings/lfu/lib
    COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:lfu> ${CMAKE_SOURCE_DIR}/python-bindings/lfu/lib/$<TARGET_FILE_NAME:lfu>
)

add_subdirectory(examples/)
add_subdirectory(test/)
