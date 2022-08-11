
#include <gtest/gtest-death-test.h>
#include <gtest/gtest.h>
#include <unicorn/unicorn.h>

#include "allocator.h"
#include "defs.h"
#include "lfu.h"
#include "state.h"

static const uint8_t shellcode_ok[] = {
    /* 0000000000000000 <_start>: */
    0x48, 0x31, 0xc0,                         // xor    %rax,%rax
    0x48, 0xc7, 0xc7, 0x10, 0x00, 0x00, 0x00, // mov    $0xb,%rdi
    0xe8, 0x08, 0x00, 0x00, 0x00,             // call   17 <malloc>
    0x8a, 0x58, 0x00,                         // mov    0x0(%rax),%bl
    0x8a, 0x58, 0x0f,                         // mov    0xf(%rax),%bl

    0x90, 0x90, // nop nop

    /* 0000000000000017 <malloc>: */
    0x90, // nop

    /* 0000000000000018 <free>: */
    0x90, // nop
};

static const uint8_t shellcode_oob_access_1b[] = {
    /* 0000000000000000 <_start>: */
    0x48, 0x31, 0xc0,                         // xor    %rax,%rax
    0x48, 0xc7, 0xc7, 0x0b, 0x00, 0x00, 0x00, // mov    $0xb,%rdi
    0xe8, 0x06, 0x00, 0x00, 0x00,             // call   15 <malloc>
    0x8a, 0x58, 0x0a,                         // mov    0xa(%rax),%bl
    0x8a, 0x58, 0x0b,                         // mov    0xb(%rax),%bl

    /* 0000000000000015 <malloc>: */
    0x90, // nop

    /* 0000000000000016 <free>: */
    0x90, // nop
};

static const uint8_t shellcode_oob_access_8b[] = {
    /* 0000000000000000 <_start>: */
    0x48, 0x31, 0xc0,                         // xor    %rax,%rax
    0x48, 0xc7, 0xc7, 0x0b, 0x00, 0x00, 0x00, // mov    $0xb,%rdi
    0xe8, 0x08, 0x00, 0x00, 0x00,             // call   17 <malloc>
    0x48, 0x8b, 0x58, 0x03,                   // mov    0x2(%rax),%rbx
    0x48, 0x8b, 0x58, 0x04,                   // mov    0x3(%rax),%rbx

    /* 0000000000000017 <malloc>: */
    0x90, // nop

    /* 0000000000000018 <free>: */
    0x90, // nop
};

TEST(SanitizerDeathTest, Sanity) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_NE(start, 0);

    uint64_t stack = lfu_mmap(0, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_ok, sizeof(shellcode_ok));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_X86_REG_RSP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x17, start + 0x18, 0x1000), UC_ERR_OK);
    err = uc_emu_start(uc, start, start + 0x16, 0, 0);
    EXPECT_EQ(err, UC_ERR_OK);
}

TEST(SanitizerDeathTest, OverflowAccess1B) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_NE(start, 0);

    uint64_t stack = lfu_mmap(0, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_oob_access_1b, sizeof(shellcode_oob_access_1b));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_X86_REG_RSP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x15, start + 0x16, 0x1000), UC_ERR_OK);
    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x16, 0, 0), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ .*b of size 1");
}

TEST(SanitizerDeathTest, OverflowAccess8B) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_X86, UC_MODE_64, &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_NE(start, 0);

    uint64_t stack = lfu_mmap(0, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_oob_access_8b, sizeof(shellcode_oob_access_8b));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_X86_REG_RSP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x17, start + 0x18, 0x1000), UC_ERR_OK);
    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x18, 0, 0), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ .*4 of size 8");
}
