
function(add_example name)
    add_executable(${name}
        ${name}.c
    )
    add_executable("${name}_fuzz_standalone"
        ${name}.c
    )
    target_link_options("${name}" PRIVATE
        -Wl,-z,relro
        -Wl,-z,now
    )
    target_compile_options("${name}_fuzz_standalone" PRIVATE
        -fsanitize=fuzzer,address
    )
    target_link_options("${name}_fuzz_standalone" PRIVATE
        -fsanitize=fuzzer,address
    )
    target_compile_definitions("${name}_fuzz_standalone" PRIVATE
        FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    )
endfunction()

add_example(basic)
add_example(int_overflow)

add_executable(test_coverage
    test_coverage.cpp
)
target_compile_options(
    test_coverage PRIVATE
    -fsanitize-coverage=inline-8bit-counters
    -fsanitize=address
)
target_link_options(test_coverage PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -fsanitize=address
)
target_link_libraries(test_coverage PRIVATE "${LLVM_LIBRARY_DIRS}/clang/${LLVM_VERSION}/lib/libclang_rt.fuzzer_no_main-x86_64.a")
