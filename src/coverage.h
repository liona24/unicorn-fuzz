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
    // std::array<PCTableEntry, MAX_NUM_BASIC_BLOCKS> pc_table_;

    uint64_t current_bb_idx_ { 0 };
    std::unordered_map<uint64_t, uint32_t> basic_blocks_ {};

    uint8_t* fake_caller_pcs_ { nullptr };
};
