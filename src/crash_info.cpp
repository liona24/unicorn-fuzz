#include "crash_info.h"

#include <cctype>
#include <cstddef>
#include <stdio.h>

#include "state.h"
#include "unicorn/x86.h"

#define eprintf(...) fprintf(stderr, __VA_ARGS__)

void print_hex_dump(uint64_t start_addr, const uint8_t* buf, size_t len, size_t bytes_per_line) {
    constexpr size_t bytes_per_group = 4;

    if (bytes_per_line < bytes_per_group) {
        bytes_per_line = bytes_per_group;
    }

    size_t i = 0;

    eprintf("%016lx: ", start_addr);
    for (size_t i = 0; i < len; i++) {
        eprintf("%02x", (unsigned)buf[i]);
        if ((i + 1) % bytes_per_group == 0) {
            eprintf(" ");
        }
        if ((i + 1) % bytes_per_line == 0) {
            eprintf("\n%016lx: ", start_addr + i + 1);
        }
    }
    eprintf("\n");
}

static const std::map<uint32_t, std::string> X86_64_REGS = {
    { UC_X86_REG_RAX, "rax" },    { UC_X86_REG_RBP, "rbp" },     { UC_X86_REG_RBX, "rbx" },
    { UC_X86_REG_RCX, "rcx" },    { UC_X86_REG_RDI, "rdi" },     { UC_X86_REG_RDX, "rdx" },
    { UC_X86_REG_RIP, "rip" },    { UC_X86_REG_RSI, "rsi" },     { UC_X86_REG_RSP, "rsp" },
    { UC_X86_REG_R8, "r8" },      { UC_X86_REG_R9, "r9" },       { UC_X86_REG_R10, "r10" },
    { UC_X86_REG_R11, "r11" },    { UC_X86_REG_R12, "r12" },     { UC_X86_REG_R13, "r13" },
    { UC_X86_REG_R14, "r14" },    { UC_X86_REG_R15, "r15" },     { UC_X86_REG_FS_BASE, "fs" },
    { UC_X86_REG_GS_BASE, "gs" }, { UC_X86_REG_FLAGS, "flags" }, { UC_X86_REG_RFLAGS, "rflags" },
};

void render_crash_context() {
    auto& state = State::the();

    eprintf("registers:\n");
    for (const auto& pair : X86_64_REGS) {
        uint64_t val;
        uc_reg_read(state.uc, pair.first, &val);
        eprintf(" %s\t= %016lx\n", pair.second.c_str(), val);
    }
    eprintf("stack dump:\n");

    uint8_t stack[64];
    uint64_t stack_ptr;
    uc_reg_read(state.uc, UC_X86_REG_RSP, &stack_ptr);
    uc_mem_read(state.uc, stack_ptr, stack, sizeof(stack));
    print_hex_dump(stack_ptr, stack, sizeof(stack), 8);
}
