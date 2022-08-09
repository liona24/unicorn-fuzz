#pragma once

#include <unordered_map>

#include <unicorn/unicorn.h>

#include "allocator.h"

class Coverage {
public:
    static constexpr uint64_t MAX_NUM_BASIC_BLOCKS = MemoryMap::PAGE_SIZE;

    explicit Coverage() {}
    ~Coverage();

    Coverage(Coverage&&) = delete;
    Coverage(const Coverage&) = delete;

    int enable_instrumentation();

    void increment_counter(uint64_t addr);

private:
    uc_hook h_cmp_;
    uc_hook h_bb_;

    std::array<uint8_t, MAX_NUM_BASIC_BLOCKS> inl_8bit_counters_;
    std::unordered_map<uint64_t, uint32_t> basic_blocks_ {};
};
