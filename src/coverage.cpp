#include "coverage.h"

#include <stdint.h>

#include "allocator.h"
#include "defs.h"
#include "state.h"
#include "unicorn/unicorn.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void __sanitizer_cov_8bit_counters_init(uint8_t* Start, uint8_t* Stop);

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
    (void)user_data;

    TRACE(" @ %lx (%lu, %lu) size = %u", addr, arg1, arg2, size);

    switch (size) {
    case 64:
        __sanitizer_cov_trace_cmp8(arg1, arg2);
        break;
    case 32:
        __sanitizer_cov_trace_cmp4((uint32_t)arg1, (uint32_t)arg2);
        break;
    case 16:
        __sanitizer_cov_trace_cmp2((uint16_t)arg1, (uint16_t)arg2);
        break;
    case 8:
        __sanitizer_cov_trace_cmp1((uint8_t)arg1, (uint8_t)arg2);
        break;
    }
}

static void hook_basic_block(uc_engine* uc, uint64_t addr, uint32_t size, void* user_data) {
    (void)uc;
    (void)size;

    TRACE(" @ %lx", addr);

    Coverage* coverage = reinterpret_cast<Coverage*>(user_data);
    coverage->increment_counter(addr);
}

Coverage::~Coverage() {

    if (State::the().uc != nullptr) {
        if (h_bb_) {
            uc_hook_del(State::the().uc, h_bb_);
        }
        if (h_cmp_) {
            uc_hook_del(State::the().uc, h_cmp_);
        }
    }
}

int Coverage::enable_instrumentation() {
    auto& state = State::the();

    uc_err err = uc_hook_add(state.uc, &h_cmp_, UC_HOOK_TCG_OPCODE, (void*)&hook_insn_cmp, nullptr,
                             1, 0, UC_TCG_OP_SUB, UC_TCG_OP_FLAG_CMP);
    if (err != UC_ERR_OK) {
        WARN("could not add cmp hook: %s", uc_strerror(err));
        return err;
    }

    err = uc_hook_add(state.uc, &h_bb_, UC_HOOK_BLOCK, (void*)&hook_basic_block, (void*)this, 1, 0);
    if (err != UC_ERR_OK) {
        WARN("could not add basic block hook: %s", uc_strerror(err));
        return err;
    }

    __sanitizer_cov_8bit_counters_init(inl_8bit_counters_.data(),
                                       inl_8bit_counters_.data() + MAX_NUM_BASIC_BLOCKS);

    return 0;
}

void Coverage::increment_counter(uint64_t addr) {
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

    inl_8bit_counters_[it->second]++;
}
