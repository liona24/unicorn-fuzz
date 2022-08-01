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

#ifdef __cplusplus
} // extern "C"
#endif
