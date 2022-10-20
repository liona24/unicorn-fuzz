#include "lfu.h"

#include <array>
#include <cassert>
#include <iostream>
#include <map>
#include <memory>
#include <unordered_map>
#include <vector>

#include <unicorn/unicorn.h>

#include "abi.h"
#include "allocator.h"
#include "coverage.h"
#include "defs.h"
#include "state.h"

#ifdef __cplusplus
extern "C" {
#endif

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

    assert(state.context && "context should have been initialized");
    uc_err err = uc_context_restore(state.uc, state.context);
    if (err != UC_ERR_OK) {
        WARN("error during context restore: %s", uc_strerror(err));
        abort();
    }

    if (state.init_context_callback(data, size)) {
        return -1;
    }

    if (state.allocator) {
        state.allocator->reset();
    }

    for (const auto& patch : state.patches) {
        patch.apply(state.uc);
    }

    err = uc_emu_start(state.uc, state.begin, state.until, 0, 0);
    if (err != UC_ERR_OK) {
        WARN("error: %s", uc_strerror(err));
        state.render_context();
        abort();
    }

    return 0;
}

int setup_for_fuzzing(init_context init_context_callback, uint64_t begin, uint64_t until) {
    auto& state = State::the();

    if (state.uc == nullptr) {
        WARN("missing unicorn engine!");
        return -1;
    }

    state.init_context_callback = init_context_callback;
    state.begin = begin;
    state.until = until;

    if (state.context) {
        uc_context_free(state.context);
        state.context = nullptr;
    }

    uc_err err = uc_context_alloc(state.uc, &state.context);
    if (err != UC_ERR_OK) {
        WARN("could not allocate uc_context: %s", uc_strerror(err));
        return -1;
    }

    err = uc_context_save(state.uc, state.context);
    if (err != UC_ERR_OK) {
        WARN("could not save uc context: %s", uc_strerror(err));
        return -1;
    }

    return 0;
}

void triage_hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    auto& state = State::the();
    auto tracer = static_cast<InsnTracer*>(user_data);

    uint8_t code_buf[32];
    size = std::min(size, 32u);

    const char* mnemonic = "(bad)";
    const char* op = "";

    if (uc_mem_read(uc, addr, code_buf, size) == UC_ERR_OK &&
        tracer->disassemble_one_insn(addr, code_buf, size)) {
        mnemonic = tracer->insn->mnemonic;
        op = tracer->insn->op_str;
    }

    fprintf(stderr, "\n%lx: %s\t%s", addr, mnemonic, op);

    const auto map = state.mmem->name_for_map(addr);
    if (map) {
        fprintf(stderr, "\t\tin %s", map->c_str());
    }

    fprintf(stderr, "\n");

    state.render_context();
}

void malloc_hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)addr;
    (void)size;
    (void)user_data;

    uint64_t malloc_size = State::the().abi->read_arg0(uc);
    uint64_t result = State::the().allocator->alloc(malloc_size);
    State::the().abi->set_ret(uc, result);
}

void free_hook(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)addr;
    (void)size;
    (void)user_data;

    uint64_t malloc_addr = State::the().abi->read_arg0(uc);
    State::the().allocator->dealloc(malloc_addr);
}

void lfu_init_engine(uc_engine* uc) {
    if (State::the().uc != nullptr) {
        WARN("engine already initialized!");
        return;
    }

    State::the().uc = uc;
    State::the().abi.reset(IABIAbstraction::for_uc(uc));
    State::the().mmem.reset(new MemoryMap);

    State::the().coverage.reset(new Coverage);
    if (State::the().coverage->enable_instrumentation()) {
        WARN("coverage instrumentation failed!");
    }
}

int lfu_start_fuzzer(int argc,
                     char* argv[],
                     init_context init_context_callback,
                     uint64_t begin,
                     uint64_t until) {

    assert(argc > 0 && argv[0] != nullptr && "you need to provide a program name!");

    int res = setup_for_fuzzing(init_context_callback, begin, until);
    if (res < 0) {
        return res;
    }

    return LLVMFuzzerRunDriver(&argc, &argv, fuzz_one_input);
}

void lfu_triage_one_input(init_context init_context_callback,
                          uint64_t begin,
                          uint64_t until,
                          const uint8_t* input,
                          size_t input_size) {

    int res = setup_for_fuzzing(init_context_callback, begin, until);
    if (res < 0) {
        WARN("setup failed, nothing will be run");
        return;
    }

    std::unique_ptr<InsnTracer> tracer(new InsnTracer(*State::the().abi));

    uc_hook hook;
    uc_err err =
        uc_hook_add(State::the().uc, &hook, UC_HOOK_CODE, (void*)&triage_hook, tracer.get(), 1, 0);

    if (err != UC_ERR_OK) {
        WARN("trace hook failed, nothing will be run");
        return;
    }

    fuzz_one_input(input, input_size);

    uc_hook_del(State::the().uc, hook);
}

int lfu_replace_allocator(uint64_t malloc_addr, uint64_t free_addr, size_t pool_size) {
    return lfu_replace_allocator2(&malloc_addr, 1, &free_addr, 1, pool_size);
}

int lfu_replace_allocator2(const uint64_t malloc_addr[],
                           size_t malloc_addr_size,
                           const uint64_t free_addr[],
                           size_t free_addr_size,
                           size_t pool_size) {

    auto& state = State::the();

    if (state.allocator) {
        WARN("allocator already initialized!");
        return -1;
    }

    state.allocator.reset(new Allocator(pool_size));

    auto add_hook = [&state](uc_hook* hook, void* callback, uint64_t addr) {
        uc_err err = uc_hook_add(state.uc, hook, UC_HOOK_CODE, callback, nullptr, addr, addr + 1);

        if (err != UC_ERR_OK) {
            return err;
        }

        state.patches.emplace_back(addr, state.abi->ret_instr(), "allocator");
        state.patches.back().apply(state.uc);

        return UC_ERR_OK;
    };

    uc_err err;

    for (size_t i = 0; i < malloc_addr_size; ++i) {
        const uint64_t addr = malloc_addr[i];

        TRACE("replacing malloc @ %lx", addr);

        state.h_malloc.emplace_back();

        err = add_hook(&state.h_malloc.back(), (void*)&malloc_hook, addr);
        if (err != UC_ERR_OK) {
            WARN("malloc hook @ %lx failed: %s", addr, uc_strerror(err));
            return err;
        }
    }

    for (size_t i = 0; i < free_addr_size; i++) {
        const uint64_t addr = free_addr[i];

        TRACE("replacing free @ %lx", addr);

        state.h_free.emplace_back();

        err = add_hook(&state.h_free.back(), (void*)&free_hook, addr);
        if (err != UC_ERR_OK) {
            WARN("free hook @ %lx failed: %s", addr, uc_strerror(err));
            return err;
        }
    }

    if (state.allocator->enable_address_sanitizer()) {
        WARN("enable sanitizer failed!");
        return -1;
    }

    return 0;
}

uint64_t lfu_mmap(uint64_t addr, uint64_t size, int perm, const char* name) {
    const uint64_t actual_addr = State::the().mmem->mmap(addr, size, perm, name);
    if (actual_addr == 0) {
        WARN("map_memory(%lx, %lu, %d, \"%s\") failed", addr, size, perm, name);
    }

    return actual_addr;
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

void lfu_force_crash() {
    State::the().render_context();
    abort();
}
