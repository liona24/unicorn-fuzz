#include <lfu.h>

#include <unicorn/unicorn.h>

#include <cassert>
#include <iostream>
#include <memory>

#define WARN(msg, ...) fprintf(stderr, "[!] %s:%d - " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__)

struct State {
    explicit State() {}

    static State& the() {
        static std::unique_ptr<State> instance { nullptr };

        if (!instance) {
            instance.reset(new State);
        }

        return *instance.get();
    }

    uc_engine* uc { nullptr };
    // Address range to simulate for each input
    uint64_t begin, until;
    init_context init_context_callback { nullptr };
};

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

    if (state.init_context_callback(data, size)) {
        return -1;
    }

    uc_err err = uc_emu_start(state.uc, state.begin, state.until, 0, 0);
    if (err) {
        WARN("failed uc_emu_start: %s", uc_strerror(err));
        abort();
    }

    return 0;
}

void lfu_init_engine(uc_engine* uc) {
    if (State::the().uc != nullptr) {
        WARN("engine already initialized!");
        return;
    }

    State::the().uc = uc;

    // TODO: Setup hooks for coverage and sanitizers
}

int lfu_start_fuzzer(int argc,
                     char* argv[],
                     init_context init_context_callback,
                     uint64_t begin,
                     uint64_t until) {

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
