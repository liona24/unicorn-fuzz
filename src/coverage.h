#pragma once

#include <unordered_map>

#include <unicorn/unicorn.h>

#include "allocator.h"

class Coverage {
public:
    // ~ 1 pages reserved for coverage information
    static constexpr uint64_t MAX_NUM_BASIC_BLOCKS = MemoryMap::PAGE_SIZE;
    // if you decide for the PC support, replace with something like this:
    // MemoryMap::PAGE_SIZE * 1 / (sizeof(void*) + sizeof(void*));

    explicit Coverage() {}
    ~Coverage();

    Coverage(Coverage&&) = delete;
    Coverage(const Coverage&) = delete;

    int enable_instrumentation();

    void trace_bb(uint64_t addr);

    void* get_current_fake_pc() const;

private:
    uc_hook h_cmp_ { 0 };
    uc_hook h_bb_ { 0 };

    struct PCTableEntry {
        void* bb;
        size_t flags;
    };

    std::array<uint8_t, MAX_NUM_BASIC_BLOCKS> inl_8bit_counters_;

    // Commented out because fuzzing seems to be working fine without it. I assume it is relevant
    // only for printing coverage / crash analysis by libFuzzer std::array<PCTableEntry,
    // MAX_NUM_BASIC_BLOCKS> pc_table_;

    uint64_t current_bb_idx_ { 0 };
    std::unordered_map<uint64_t, uint32_t> basic_blocks_ {};

    // This is used in order to provide distinct PCs for __sanitizer_cov_trace_cmp[1248] calls.
    // libFuzzer will try to retrieve the caller address and since we are emulating this address
    // will always be the same. In order to circumvent this we have this jump table here, serving as
    // many "call sites" as MAX_NUM_BASIC_BLOCKS
    uint8_t* fake_caller_pcs_ { nullptr };
};
