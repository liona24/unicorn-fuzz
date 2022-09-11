
#include <cstdint>
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

/*
# Code:
# compile with
# clang -c -target mips -mcpu=mips32 test/simple_code_mips.s
.section .text

    .space 0x1000

    _start:
        move $v0, $0
        li $v0, 0

        li $a0, 11
        la $t0, malloc
        jalr $t0

        lbu $t0, 10($v0)
        lbu $t0, 11($v0)

        nop

    malloc:
        # stub, will be intercepted by our runtime
        jr $ra

    free:
        # stub, will be intercepted by our runtime
        jr $ra
*/
static const uint32_t shellcode_mips32_le_oob_1b[] = {
    /* 00001000 <_start>: */
    0x00001025, // move    v0, zero
    0x24020000, // li      v0,0
    0x2404000b, // li      a0,11
    0x3c080000, // lui     t0,0x0
    0x25081028, // addiu   t0,t0,4136
    0x0100f809, // jalr    t0
    0x00000000, // nop
    0x9048000a, // lbu     t0,10(v0)
    0x9048000b, // lbu     t0,11(v0)
    0x00000000, // nop

    /* 00001028 <malloc>: */
    0x03e00008, // jr      ra
    0x00000000, // nop

    /* 00001030 <free>: */
    0x03e00008, // jr      ra
    0x00000000, // nop

};

static const uint32_t shellcode_mips32_le_oob_n1b[] = {
    /* 00001000 <_start>: */
    0x00001025, // move    v0, zero
    0x24020000, // li      v0,0
    0x2404000b, // li      a0,11
    0x3c080000, // lui     t0,0x0
    0x25081028, // addiu   t0,t0,4136
    0x0100f809, // jalr    t0
    0x00000000, // nop
    0x90480000, // lbu     t0,0(v0)
    0x9048ffff, // lbu     t0,-1(v0)
    0x00000000, // nop

    /* 00001028 <malloc>: */
    0x03e00008, // jr      ra
    0x00000000, // nop

    /* 00001030 <free>: */
    0x03e00008, // jr      ra
    0x00000000, // nop

};

/*
# Code:
# compile with
# clang -c -target armv7-pc-linux-eabi -mcpu=cortex-a15 test/simple_code_arm.s
# you may need to link as well, the bl instruction does not seem to get resolved?
.section .text

    .globl _start

    .space 0x1000

    _start:
        mov r0, $11
        bl malloc

        ldr r1,[r0,$10]
        ldr r1,[r0,$11]

        nop

    malloc:
        # stub, will be intercepted by our runtime
        nop

    free:
        # stub, will be intercepted by our runtime
        nop
*/

static const uint32_t shellcode_arm32_le_oob_1b[] = {
    /* 00001000 <_start>: */
    0xe3a0000b, // mov     r0, #11
    0xeb000002, // bl      1014 <malloc>
    0xe590100a, // ldr     r1, [r0, #10]
    0xe590100b, // ldr     r1, [r0, #11]
    0xe320f000, // nop     {0}

    /* 00001014 <malloc>: */
    0xe320f000, // nop     {0}

    /* 00001018 <free>: */
    0xe320f000, // nop     {0}
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
    err = uc_emu_start(uc, start, start + 0x16, 0, 123);
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
    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x16, 0, 123), testing::KilledBySignal(SIGABRT),
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
    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x18, 0, 123), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ .*4 of size 8");
}

TEST(SanitizerDeathTest, Mips32LeOverflowAccess1B) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_MIPS, uc_mode(UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN), &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x1000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_EQ(start, 0x1000);

    uint32_t stack =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_mips32_le_oob_1b,
                       sizeof(shellcode_mips32_le_oob_1b) * sizeof(uint32_t));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_MIPS_REG_SP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x28, start + 0x30, 0x1000), UC_ERR_OK);

    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x24, 0, 123), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ 210b of size 1");
}

TEST(SanitizerDeathTest, Mips32LeUnderflowAccess1B) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_MIPS, uc_mode(UC_MODE_MIPS32 | UC_MODE_LITTLE_ENDIAN), &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x1000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_EQ(start, 0x1000);

    uint32_t stack =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_mips32_le_oob_n1b,
                       sizeof(shellcode_mips32_le_oob_n1b) * sizeof(uint32_t));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_MIPS_REG_SP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x28, start + 0x30, 0x1000), UC_ERR_OK);

    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x24, 0, 123), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ 20ff of size 1");
}

TEST(SanitizerDeathTest, Arm32LeOverflowAccess1B) {
    State::the(true);

    uc_engine* uc;
    uc_err err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    EXPECT_EQ(err, UC_ERR_OK);

    lfu_init_engine(uc);

    const uint64_t start =
        lfu_mmap(0x1000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_EXEC, ".text");
    EXPECT_EQ(start, 0x1000);

    uint32_t stack =
        lfu_mmap(0x10000, MemoryMap::PAGE_SIZE, UC_PROT_READ | UC_PROT_WRITE, "[stack]");
    EXPECT_NE(stack, 0);

    stack += MemoryMap::PAGE_SIZE - 8;

    err = uc_mem_write(uc, start, shellcode_arm32_le_oob_1b,
                       sizeof(shellcode_arm32_le_oob_1b) * sizeof(uint32_t));
    EXPECT_EQ(err, UC_ERR_OK);

    err = uc_reg_write(uc, UC_ARM_REG_SP, &stack);
    EXPECT_EQ(err, UC_ERR_OK);

    EXPECT_EQ(lfu_replace_allocator(start + 0x14, start + 0x18, 0x1000), UC_ERR_OK);

    EXPECT_EXIT(uc_emu_start(uc, start, start + 0x10, 0, 123), testing::KilledBySignal(SIGABRT),
                "invalid memory access @ 210a of size 4");
}
