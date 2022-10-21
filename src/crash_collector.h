#pragma once

#include "stddef.h"
#include "stdint.h"
#include <filesystem>
#include <string>
#include <unordered_map>

#include <unicorn/unicorn.h>

#include "abi.h"

class CrashCollector {
public:
    CrashCollector() {}

    CrashCollector(const CrashCollector&) = delete;
    CrashCollector(CrashCollector&&) = delete;

    void track_next_input(const uint8_t* data, size_t size);

    bool report_state_as_crash_if_new(uc_engine* uc, uc_err err, const IABIAbstraction& abi);

private:
    const uint8_t* current_input_ { nullptr };
    size_t current_input_size_ { 0 };

    struct Info {
        Info(size_t hash)
            : hash(hash)
            , hit_count(0) {}

        size_t hash;
        size_t hit_count;
    };

    std::unordered_map<uint64_t, Info> crashes_ {};
};
