
function(add_example name)
    add_executable(${name}
        ${name}.c
    )
    add_executable("${name}_fuzz_standalone"
        ${name}.c
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

add_example(int_overflow)
