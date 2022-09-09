#include "coverage.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

#include "allocator.h"
#include "defs.h"
#include "state.h"

#include <unicorn/unicorn.h>

#ifdef __cplusplus
extern "C" {
#endif

extern void __sanitizer_cov_8bit_counters_init(uint8_t* Start, uint8_t* Stop);
extern void __sanitizer_cov_pcs_init(const uintptr_t* pcs_beg, const uintptr_t* pcs_end);

extern void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
extern void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
extern void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
extern void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);

/*
// Instrumentation which is currently not implemented:

void __sanitizer_cov_pcs_init(const uintptr_t* pcs_beg, const uintptr_t* pcs_end);

void __sanitizer_cov_trace_pc_indir(uintptr_t Callee);

// these are currently treated equally to their non-const counterpart
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2);
void __sanitizer_cov_trace_const_cmp4(uint32 Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_const_cmp2(uint16 Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_const_cmp1(uint8 Arg1, uint8_t Arg2);

void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t* Cases);

void __sanitizer_cov_trace_div4(uint32_t Val);
void __sanitizer_cov_trace_div8(uint64_t Val);

void __sanitizer_cov_trace_gep(uintptr_t Idx);

void __sanitizer_weak_hook_memcmp(void *caller_pc, const void *s1,
                                  const void *s2, size_t n, int result);

void __sanitizer_weak_hook_strncmp(void *caller_pc, const char *s1,
                                   const char *s2, size_t n, int result);

void __sanitizer_weak_hook_strcmp(void *caller_pc, const char *s1,
                                   const char *s2, int result);

void __sanitizer_weak_hook_strncasecmp(void *called_pc, const char *s1,
                                       const char *s2, size_t n, int result);

void __sanitizer_weak_hook_strcasecmp(void *called_pc, const char *s1,
                                      const char *s2, int result);

void __sanitizer_weak_hook_strstr(void *called_pc, const char *s1,
                                  const char *s2, char *result);

void __sanitizer_weak_hook_strcasestr(void *called_pc, const char *s1,
                                      const char *s2, char *result);

void __sanitizer_weak_hook_memmem(void *called_pc, const void *s1, size_t len1,
                                  const void *s2, size_t len2, void *result);

*/

#ifdef __cplusplus
}
#endif

static void hook_insn_cmp(uc_engine* uc,
                          uint64_t addr,
                          uint64_t arg1,
                          uint64_t arg2,
                          uint32_t size,
                          void* user_data) {
    (void)uc;

    TRACE(" @ %lx (%lu, %lu) size = %u", addr, arg1, arg2, size);

    void* target = nullptr;

    switch (size) {
    case 64:
        target = (void*)&__sanitizer_cov_trace_cmp8;
        break;
    case 32:
        target = (void*)&__sanitizer_cov_trace_cmp4;
        break;
    case 16:
        target = (void*)&__sanitizer_cov_trace_cmp2;
        break;
    case 8:
        target = (void*)&__sanitizer_cov_trace_cmp1;
        break;
    default:
        break;
    }

    if (target != nullptr) {
        Coverage* coverage = reinterpret_cast<Coverage*>(user_data);
        void* fake_pc = coverage->get_current_fake_pc();

        register uint64_t a1 asm("rdi") = arg2;
        register uint64_t a2 asm("rsi") = arg1;

        // this will jump into our "ret-sled" which will emulate MAX_NUM_BASIC_BLOCKS distinct PCs
        asm volatile goto("lea %l[fin](%%rip), %%rax;"
                          "push %%rax;"
                          "push %0;"
                          "jmp *%1;"
                          :
                          : "r"(fake_pc), "r"(target), "r"(a1), "r"(a2)
                          : "rax"
                          : fin);
    }

fin:
    return;
}

static void hook_basic_block(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)uc;
    (void)size;

    TRACE(" @ %lx", addr);

    Coverage* coverage = reinterpret_cast<Coverage*>(user_data);
    coverage->trace_bb(addr);
}

Coverage::~Coverage() {

    if (State::the().uc != nullptr) {
        if (h_bb_) {
            uc_hook_del(State::the().uc, h_bb_);
            h_bb_ = 0;
        }
        if (h_cmp_) {
            uc_hook_del(State::the().uc, h_cmp_);
            h_cmp_ = 0;
        }
    }

    if (fake_caller_pcs_ != nullptr) {
        munmap(fake_caller_pcs_, MAX_NUM_BASIC_BLOCKS);
        fake_caller_pcs_ = nullptr;
    }
}

int Coverage::enable_instrumentation() {
    auto& state = State::the();

    if (h_cmp_ || h_bb_) {
        WARN("instrumentation already enabled!");
        return 0;
    }
    uc_err err;

    fake_caller_pcs_ = (uint8_t*)mmap(nullptr, MAX_NUM_BASIC_BLOCKS, PROT_READ | PROT_WRITE,
                                      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
    if (fake_caller_pcs_ == nullptr) {
        WARN("mmap of fake pc map failed! continuing without cmp instrumentation (%s)",
             strerror(errno));
    } else {
        // fill with ret instructions
        std::fill(fake_caller_pcs_, fake_caller_pcs_ + MAX_NUM_BASIC_BLOCKS, 0xc3);

        if (mprotect(fake_caller_pcs_, MAX_NUM_BASIC_BLOCKS, PROT_READ | PROT_EXEC)) {
            WARN("mprotect of fake pc map failed! continuing without cmp instrumentation (%s)",
                 strerror(errno));
        } else {
            // we add both UC_TCG_OP_FLAG_CMP and UC_TCG_OP_FLAG_DIRECT here, because it drastically
            // improves testcase generation
            constexpr uint32_t flags = 0;
            err = uc_hook_add(state.uc, &h_cmp_, UC_HOOK_TCG_OPCODE, (void*)&hook_insn_cmp,
                              (void*)this, 1, 0, UC_TCG_OP_SUB, flags);
            if (err != UC_ERR_OK) {
                WARN("could not add cmp hook! continuing without basic cmp instrumentation (%s)",
                     uc_strerror(err));
            }

            auto callback = [&state, this](uint64_t arg1, uint64_t arg2, uint32_t size) {
                hook_insn_cmp(state.uc, -1, arg1, arg2, size, (void*)this);
            };
            state.abi->add_additional_cmp_instrumentation(state.uc, callback);
        }
    }

    err = uc_hook_add(state.uc, &h_bb_, UC_HOOK_BLOCK, (void*)&hook_basic_block, (void*)this, 1, 0);
    if (err != UC_ERR_OK) {
        WARN("could not add basic block hook: %s", uc_strerror(err));
        return err;
    }

    std::fill(inl_8bit_counters_.begin(), inl_8bit_counters_.end(), 0);

    __sanitizer_cov_8bit_counters_init(inl_8bit_counters_.data(),
                                       inl_8bit_counters_.data() + inl_8bit_counters_.size());

    /*
    size_t i = 0;
    for (auto& entry : pc_table_) {
        // we cheat a bit here. these addresses are lazily resolved when we actually hit them
        entry.bb = (void*)i;
        entry.flags = 0;

        if (i == 0) {
            // for now we assume that only the first basic block is a "function entry"
            entry.flags = 1;
        }

        i++;
    }

    __sanitizer_cov_pcs_init((uintptr_t*)pc_table_.data(),
                             (uintptr_t*)(pc_table_.data() + pc_table_.size()));
    */

    return 0;
}

void Coverage::trace_bb(uint64_t addr) {
    auto it = basic_blocks_.find(addr);
    if (it == basic_blocks_.end()) {
        if (basic_blocks_.size() >= inl_8bit_counters_.size()) {
            WARN("max number of basic blocks reached!");
            return;
        }

        auto res = basic_blocks_.emplace(addr, basic_blocks_.size());
        if (!res.second) {
            WARN("could not add new basic block!");
            return;
        }

        it = res.first;
    }

    current_bb_idx_ = it->second;
    inl_8bit_counters_[it->second]++;
}

void* Coverage::get_current_fake_pc() const {
    assert(fake_caller_pcs_ != nullptr &&
           "should not enable instrumentation when fake pc map failed!");

    return (void*)&fake_caller_pcs_[current_bb_idx_];
}
