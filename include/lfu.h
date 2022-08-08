#pragma once

#include "stddef.h"
#include "stdint.h"

#include <unicorn/unicorn.h>

#define EXPORT __attribute__((visibility("default")))

using init_context = int (*)(const uint8_t* data, size_t size);

#ifdef __cplusplus
extern "C" {
#endif

EXPORT void lfu_init_engine(uc_engine* uc);

EXPORT int lfu_start_fuzzer(int argc,
                            char* argv[],
                            init_context init_context_callback,
                            uint64_t begin,
                            uint64_t until);

EXPORT int lfu_replace_allocator(uint64_t malloc_addr, uint64_t free_addr, size_t pool_size);

EXPORT int lfu_mmap(uint64_t addr, uint64_t size, int perm, const char* name);
EXPORT uint64_t lfu_allocate(uint64_t size);
EXPORT void lfu_deallocate(uint64_t addr);

#ifdef __cplusplus
} // extern "C"
#endif
