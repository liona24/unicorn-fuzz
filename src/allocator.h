#pragma once

#include <array>
#include <cassert>
#include <map>
#include <stddef.h>
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <vector>

class MemoryMap {
public:
    static constexpr uint64_t PAGE_SIZE = 0x1000;

    explicit MemoryMap() {}

    MemoryMap(const MemoryMap&) = delete;
    MemoryMap(MemoryMap&&) = delete;

    uint64_t mmap(uint64_t addr, uint64_t size, int perm, const std::string& name);

private:
    struct Map {
        explicit Map(uint64_t size, int perm, const std::string& name)
            : size(size)
            , perm(perm)
            , name(name) {}

        uint64_t size;
        int perm;
        const std::string name;
    };

    std::map<uint64_t, Map> maps_ {};
};

class Allocator {
public:
    static constexpr uint64_t POISON_SIZE = 0x100;

    explicit Allocator(size_t pool_size) { reset_arena(pool_size); }

    Allocator(const Allocator&) = delete;
    Allocator(Allocator&&) = delete;

    uint64_t alloc(uint64_t size);
    void dealloc(uint64_t addr);
    void reset();

private:
    void reset_arena(size_t pool_size);

    struct Arena {
        uint64_t base_addr { 0 };
        uint64_t addr { 0 };
        uint64_t size { 0 };

        void mmap(size_t pool_size);
        uint64_t get_chunk(uint64_t aligned_size);
    };

    Arena arena_;
    std::unordered_map<uint64_t, size_t> allocations_ {};
    std::vector<uint8_t> shadow_;
};
