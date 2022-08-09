#include "lfu.h"

#include <array>
#include <cassert>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include <unicorn/unicorn.h>

#include "allocator.h"
#include "defs.h"
#include "state.h"

#ifdef __cplusplus
extern "C" {
#endif

// TODO: Coverage stuff goes here

extern "C" int LLVMFuzzerRunDriver(int* argc,
                                   char*** argv,
                                   int (*UserCb)(const uint8_t* Data, size_t Size));

#ifdef __cplusplus
} // extern "C"
#endif

int fuzz_one_input(const uint8_t* data, size_t size) {
    auto& state = State::the();
    assert(state.init_context_callback != nullptr &&
           "fuzzing should not be started without an initialization routine");

    TRACE("");

    if (state.init_context_callback(data, size)) {
        return -1;
    }

    if (state.allocator) {
        state.allocator->reset();
    }

    for (const auto& patch : state.patches) {
        patch.apply(state.uc);
    }

    uc_err err = uc_emu_start(state.uc, state.begin, state.until, 0, 0);
    if (err) {
        WARN("failed uc_emu_start: %s", uc_strerror(err));
        abort();
    }

    return 0;
}

void malloc_hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)addr;
    (void)size;
    (void)user_data;

    // TODO: make this arch dependent

    uint64_t malloc_size;
    uint64_t result = 0;
    uc_err err = uc_reg_read(uc, UC_X86_REG_RDI, &malloc_size);

    if (err != UC_ERR_OK) {
        WARN("failed to read malloc size");
    } else {
        result = State::the().allocator->alloc(malloc_size);
    }

    err = uc_reg_write(uc, UC_X86_REG_RAX, &result);
    if (err != UC_ERR_OK) {
        WARN("failed to write malloc pointer!");
    }
}

void free_hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)addr;
    (void)size;
    (void)user_data;

    uint64_t malloc_addr;
    uc_err err = uc_reg_read(uc, UC_X86_REG_RDI, &malloc_addr);

    if (err != UC_ERR_OK) {
        WARN("failed to read pointer to free");
    } else {
        State::the().allocator->dealloc(malloc_addr);
    }
}

void lfu_init_engine(uc_engine* uc) {
    if (State::the().uc != nullptr) {
        WARN("engine already initialized!");
        return;
    }

    State::the().uc = uc;
    State::the().mmem.reset(new MemoryMap);

    // TODO: Setup hooks for coverage and sanitizers
}

int lfu_start_fuzzer(int argc,
                     char* argv[],
                     init_context init_context_callback,
                     uint64_t begin,
                     uint64_t until) {

    assert(argc > 0 && argv[0] != nullptr && "you need to provide a program name!");

    auto& state = State::the();

    if (state.uc == nullptr) {
        WARN("missing unicorn engine!");
        return -1;
    }

    state.init_context_callback = init_context_callback;
    state.begin = begin;
    state.until = until;

    return LLVMFuzzerRunDriver(&argc, &argv, fuzz_one_input);
}

int lfu_replace_allocator(uint64_t malloc_addr, uint64_t free_addr, size_t pool_size) {
    auto& state = State::the();

    if (state.allocator) {
        WARN("allocator already initialized!");
        return -1;
    }

    TRACE("replacing malloc @ %lx and free @ %lx", malloc_addr, free_addr);

    state.allocator.reset(new Allocator(pool_size));

    auto add_hook = [&state](uc_hook* hook, void* callback, uint64_t addr) {
        uc_err err = uc_hook_add(state.uc, hook, UC_HOOK_CODE, callback, nullptr, addr, addr + 1);

        if (err != UC_ERR_OK) {
            return err;
        }

        state.patches.emplace_back(addr, std::vector<uint8_t>({ 0xc3 }), "allocator");
        state.patches.back().apply(state.uc);

        return UC_ERR_OK;
    };

    uc_err err = add_hook(&state.h_malloc, (void*)&malloc_hook, malloc_addr);
    if (err != UC_ERR_OK) {
        WARN("malloc hook failed: %s", uc_strerror(err));
        return err;
    }

    err = add_hook(&state.h_free, (void*)&free_hook, free_addr);
    if (err != UC_ERR_OK) {
        WARN("free hook failed: %s", uc_strerror(err));
        return err;
    }

    return 0;
}

int lfu_mmap(uint64_t addr, uint64_t size, int perm, const char* name) {
    if (State::the().mmem->mmap(addr, size, perm, name) != addr) {
        WARN("map_memory(%lx, %lu, %d, \"%s\") failed", addr, size, perm, name);
        return 1;
    }

    return 0;
}

uint64_t lfu_allocate(uint64_t size) {
    auto& state = State::the();

    if (!state.allocator) {
        WARN("allocator is not active!");
        return 0;
    }

    return state.allocator->alloc(size);
}

void lfu_deallocate(uint64_t addr) {
    auto& state = State::the();

    if (!state.allocator) {
        WARN("allocator is not active!");
        return;
    }

    state.allocator->dealloc(addr);
}

void lfu_add_patch(uint64_t addr, const uint8_t* patch_raw, size_t size, const char* name) {
    auto& state = State::the();

    std::string name_s = "<empty>";
    if (name != nullptr) {
        name_s.assign(name);
    }

    TRACE(" @ %lx %s", addr, name_s.c_str());

    std::vector<uint8_t> patch;
    patch.assign(patch_raw, patch_raw + size);

    state.patches.emplace_back(addr, patch, name_s);
    if (state.uc != nullptr) {
        state.patches.back().apply(state.uc);
    }
}
