#pragma once

#include "stddef.h"
#include "stdint.h"

#include <unicorn/unicorn.h>

#define EXPORT __attribute__((visibility("default")))

// Callback for every fuzz input. (Think LLVMFuzzerTestOneInput)
// You should setup the proper context for the fuzz target using the provided data here.
using init_context = int (*)(const uint8_t* data, size_t size);

#ifdef __cplusplus
extern "C" {
#endif

// Set the internal engine used by the fuzzer
// This should be called before using any of the convenience functions
EXPORT void lfu_init_engine(uc_engine* uc);

// Start the fuzzing, passing the additionally provided arguments to libFuzzer
// `init_context_callback` will be invoked for each fuzz input
// For each input, the fuzzer will run the emulator starting from address `begin` until address
// `until`
EXPORT int lfu_start_fuzzer(int argc,
                            char* argv[],
                            init_context init_context_callback,
                            uint64_t begin,
                            uint64_t until);

// Convenience function to replace the default libc malloc / free allocator with a custom one
// This custom allocator employs shadow memory to detect simple memory bugs.
// Furthermore, the allocator is very simple, thus restricts memory allocations to a total of the
// given pool size. The allocated memory is reset for each fuzz run
EXPORT int lfu_replace_allocator(uint64_t malloc_addr, uint64_t free_addr, size_t pool_size);

// Wrapper for uc_mem_map for internal book keeping. Use this if you want the custom allocator to
// work properly
EXPORT uint64_t lfu_mmap(uint64_t addr, uint64_t size, int perm, const char* name);
// Convenience function to allocate some memory using the custom allocator.
// This is useful if you f.e. want to setup some memory for the fuzz target during `init_context`
EXPORT uint64_t lfu_allocate(uint64_t size);
// Free some memory allocated using `lfu_allocate`
EXPORT void lfu_deallocate(uint64_t addr);

// Add a patch for the fuzz target. This patch will be applied on every run.
// You may optionally specify a name for debugging purposes.
EXPORT void lfu_add_patch(uint64_t addr, const uint8_t* patch, size_t size, const char* name);

#ifdef __cplusplus
} // extern "C"
#endif
