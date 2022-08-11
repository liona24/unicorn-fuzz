#include "allocator.h"

#include <cstdint>
#include <cstdio>

#include "defs.h"
#include "state.h"

#include <unicorn/unicorn.h>

namespace {
template <typename T>
static constexpr T align_up(T x, T a) {
    return x + (a - static_cast<T>(1)) & ~(a - static_cast<T>(1));
}
} // namespace

static_assert(Allocator::POISON_SIZE == align_up(Allocator::POISON_SIZE, (uint64_t)8),
              "poison size should be aligned to 8 bytes!");

uint64_t MemoryMap::mmap(uint64_t addr, uint64_t size, int perm, const std::string& name) {
    size = align_up(size, (uint64_t)PAGE_SIZE);
    addr = align_up(addr, (uint64_t)PAGE_SIZE);

    if (addr != 0) {
        auto it = maps_.find(addr);
        if (it != maps_.end() && it->second.name == name && it->second.perm == perm &&
            it->second.size == size) {
            TRACE("with (%lx, %lu, %d, \"%s\") ignored because it already exists", addr, size, perm,
                  name.c_str());
            return addr;
        }
    }

    if (addr == 0) {
        auto prev = maps_.begin();
        auto it = maps_.begin();
        it++;

        while (it != maps_.end()) {
            if (prev->first + prev->second.size + size < it->first) {
                addr = prev->first + prev->second.size;
                break;
            }

            it++;
            prev++;
        }

        if (addr == 0) {
            if (prev == maps_.end()) {
                // arbitrary address
                addr = PAGE_SIZE;
            } else {
                addr = prev->first + prev->second.size;
            }
        }
    }

    uc_err err = uc_mem_map(State::the().uc, addr, size, perm);

    if (err != UC_ERR_OK) {
        WARN("uc_mem_map(uc, %lx, %lu, %d) returned error: %s", addr, size, perm, uc_strerror(err));
        return 0;
    } else {
        maps_.try_emplace(addr, size, perm, name);
        return addr;
    }
}

uint64_t Allocator::alloc(uint64_t size) {
    const uint64_t size_aligned = align_up(size, (uint64_t)8);
    const uint64_t actual_size = size_aligned + 2 * POISON_SIZE;

    const uint64_t addr0 = arena_.get_chunk(actual_size);
    if (addr0 == 0) {
        return 0;
    }

    const uint64_t user_addr = addr0 + POISON_SIZE;
    allocations_.emplace(user_addr, size_aligned);

    const uint64_t shadow_addr = (addr0 - arena_.base_addr) >> 3;
    constexpr uint64_t red = POISON_SIZE >> 3;
    std::fill(shadow_.begin() + shadow_addr, shadow_.begin() + shadow_addr + red, 0xFF);
    std::fill(shadow_.begin() + shadow_addr + red,
              shadow_.begin() + shadow_addr + red + (size_aligned >> 3), 0x00);
    std::fill(shadow_.begin() + shadow_addr + red + (size_aligned >> 3),
              shadow_.begin() + shadow_addr + red + (size_aligned >> 3) + red, 0xFF);

    for (int i = 0; i < size_aligned - size; i++) {
        shadow_[shadow_addr + red + (size_aligned >> 3) - 1] |= 1 << (7 - i);
    }

    TRACE("size = %lu; user_addr = %lx", size, user_addr);
    return user_addr;
}
void Allocator::dealloc(uint64_t addr) {
    TRACE("%lx", addr);
    auto allocation = allocations_.find(addr);
    if (allocation == allocations_.end()) {
        WARN("invalid free: %lx", addr);
        return;
    }

    const uint64_t size = allocation->second >> 3;
    const uint64_t shadow_addr = (addr - arena_.base_addr) >> 3;

    // just poison the allocation and forget about it
    std::fill(shadow_.begin() + shadow_addr, shadow_.begin() + shadow_addr + size, 0xFF);
    allocations_.erase(allocation);
}

void Allocator::reset() {
    allocations_.clear();
    std::fill(shadow_.begin(), shadow_.end(), 0);
    arena_.clear();

    // Since the MemoryMap is persistent across runs we do not need to re-map everything
}

void Allocator::reset_arena(size_t pool_size) {
    arena_.mmap(pool_size);
    shadow_.resize(arena_.size >> 3);
    std::fill(shadow_.begin(), shadow_.end(), 0);
}

void Allocator::Arena::mmap(size_t pool_size) {
    size = align_up(pool_size, MemoryMap::PAGE_SIZE);
    base_addr = State::the().mmem->mmap(0, size, UC_PROT_READ | UC_PROT_WRITE, "allocator");

    if (base_addr == 0) {
        WARN("could not allocate malloc arena!");
        size = 0;
    } else {
        TRACE("allocator setup with pool size %lu at %lx", size, base_addr);
        addr = base_addr;
    }
}

uint64_t Allocator::Arena::get_chunk(uint64_t aligned_size) {
    if (aligned_size > size) {
        WARN("no memory left");
        return 0;
    }

    const uint64_t ret = addr;

    addr += aligned_size;
    size -= aligned_size;

    return ret;
}

void Allocator::Arena::clear() {
    const uint64_t original_size = addr - base_addr + size;
    addr = base_addr;
    size = original_size;
}

static void hook_mem_access(uc_engine* uc,
                            uc_mem_type type,
                            uint64_t addr,
                            int size,
                            int64_t value,
                            void* user_data) {
    (void)uc;
    (void)value;

    Allocator* alloc = reinterpret_cast<Allocator*>(user_data);
    alloc->validate_mem_access(addr, size, type);
}

int Allocator::enable_address_sanitizer() {
    TRACE("");

    auto& state = State::the();

    uc_err err = uc_hook_add(state.uc, &h_access_, UC_HOOK_MEM_VALID, (void*)&hook_mem_access,
                             (void*)this, 1, 0);
    if (err != UC_ERR_OK) {
        WARN("could not add memory access hook: %s", uc_strerror(err));
        return err;
    }

    return 0;
}

void Allocator::validate_mem_access(uint64_t addr, size_t size, uc_mem_type type) const {
    if (addr < arena_.base_addr || addr > arena_.addr + size) {
        return;
    }
    if (size > 8) {
        WARN("unexpected access size > 8: %zu", size);
        return;
    }

    const uint64_t shadow_addr = (addr - arena_.base_addr) >> 3;
    const uint64_t addr_aligned = align_up(addr, (uint64_t)8);
    int start_bit = (8 - (int)(addr_aligned - addr)) % 8;
    for (int i = 0; i < size; i++) {
        const uint8_t shadow_byte = shadow_[shadow_addr + ((i + start_bit) >> 3)];
        const int bit = (i + start_bit) % 8;
        if ((shadow_byte & (1 << bit)) != 0) {
            report_invalid_memory_access(addr, size, type);
            return;
        }
    }
}

void Allocator::report_invalid_memory_access(uint64_t addr, size_t size, uc_mem_type type) const {
    WARN("invalid memory access @ %lx of size %lu", addr, size);
    fprintf(stderr, "shadow memory around the address:\n");
    const uint64_t shadow_addr = (addr - arena_.base_addr) >> 3;
    for (int i = 8; i > 0; i--) {
        if (shadow_addr > i) {
            fprintf(stderr, "%02x ", shadow_[shadow_addr - i]);
        } else {
            fprintf(stderr, "?? ");
        }
    }
    for (int i = 0; i <= 8; i++) {
        if (i + shadow_addr < shadow_.size()) {
            fprintf(stderr, "%02x ", shadow_[i + shadow_addr]);
        } else {
            fprintf(stderr, "?? ");
        }
    }
    fprintf(stderr, "\n                        ");
    for (int i = 0; i < std::max((size_t)1, size >> 3); i++) {
        fprintf(stderr, "^^ ");
    }
    fprintf(stderr, "\n");

    // TODO: more info
    abort();
}
