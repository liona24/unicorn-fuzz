#include "abi.h"

#include <map>
#include <stdio.h>
#include <string>

#include "defs.h"

#include "unicorn/mips.h"
#include "unicorn/unicorn.h"
#include "unicorn/x86.h"

IABIAbstraction* IABIAbstraction::for_uc(uc_engine* uc) {
    uc_mode mode;
    uc_err err;
    err = uc_ctl_get_mode(uc, &mode);
    if (err != UC_ERR_OK) {
        WARN("could not get mode!");
        goto error;
    }

    uc_arch arch;
    err = uc_ctl_get_arch(uc, &arch);
    if (err != UC_ERR_OK) {
        WARN("could not get arch!");
        goto error;
    }

#define HAS(m) ((mode & m) != 0)

    switch (arch) {
    case UC_ARCH_X86:
        if (HAS(UC_MODE_64)) {
            return new ABIAbstractionX86_64;
        }
        break;
    case UC_ARCH_MIPS:
        if (HAS(UC_MODE_MIPS32)) {
            if (HAS(UC_MODE_BIG_ENDIAN)) {
                return new ABIAbstractionMips32BE;
            } else {
                return new ABIAbstractionMips32LE;
            }
        }
        break;
    default:
        break;
    }

#undef HAS

error:
    WARN("arch / mode not supported!");
    abort();
}

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

uint64_t IABIAbstraction::read_reg_wrapper(uc_engine* uc, int regid) const {
    uint64_t val = 0;
    uc_err err = uc_reg_read(uc, regid, &val);

    if (err != UC_ERR_OK) {
        WARN("uc_reg_read failed: %s", uc_strerror(err));
        val = 0;
    }

    return val;
}
void IABIAbstraction::write_reg_wrapper(uc_engine* uc, int regid, uint64_t value) const {
    uc_err err = uc_reg_write(uc, regid, &value);

    if (err != UC_ERR_OK) {
        WARN("uc_reg_write failed: %s", uc_strerror(err));
    }
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

static const std::map<uint32_t, std::string> MIPS32_REGS = {
    { UC_MIPS_REG_A0, "a0" }, { UC_MIPS_REG_A1, "a1" }, { UC_MIPS_REG_A2, "a2" },
    { UC_MIPS_REG_A3, "a3" }, { UC_MIPS_REG_V0, "v0" }, { UC_MIPS_REG_V1, "v1" },
    { UC_MIPS_REG_GP, "gp" }, { UC_MIPS_REG_SP, "sp" }, { UC_MIPS_REG_FP, "fp" },
    { UC_MIPS_REG_RA, "ra" }, { UC_MIPS_REG_PC, "pc" },
};

uint64_t ABIAbstractionX86_64::read_arg0(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_X86_REG_RDI);
}
uint64_t ABIAbstractionX86_64::read_arg1(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_X86_REG_RSI);
}
void ABIAbstractionX86_64::set_ret(uc_engine* uc, uint64_t val) const {
    write_reg_wrapper(uc, UC_X86_REG_RAX, val);
}

const std::vector<uint8_t>& ABIAbstractionX86_64::ret_instr() const {
    static const std::vector<uint8_t> ret { 0xc3 };

    return ret;
}

void ABIAbstractionX86_64::render_crash_context(uc_engine* uc) const {
    eprintf("registers:\n");
    for (const auto& pair : X86_64_REGS) {
        uint64_t val;
        uc_reg_read(uc, pair.first, &val);
        eprintf(" %s\t= %016lx\n", pair.second.c_str(), val);
    }
    eprintf("stack dump:\n");

    uint8_t stack[64];
    uint64_t stack_ptr;
    uc_reg_read(uc, UC_X86_REG_RSP, &stack_ptr);
    uc_mem_read(uc, stack_ptr, stack, sizeof(stack));
    print_hex_dump(stack_ptr, stack, sizeof(stack), 8);
}

uint64_t ABIAbstractionMips32X::read_arg0(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_MIPS_REG_A0);
}
uint64_t ABIAbstractionMips32X::read_arg1(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_MIPS_REG_A1);
}
void ABIAbstractionMips32X::set_ret(uc_engine* uc, uint64_t val) const {
    write_reg_wrapper(uc, UC_MIPS_REG_V0, val);
}

void ABIAbstractionMips32X::render_crash_context(uc_engine* uc) const {
    eprintf("registers:\n");
    for (const auto& pair : MIPS32_REGS) {
        uint32_t val;
        uc_reg_read(uc, pair.first, &val);
        eprintf(" %s\t= %08x\n", pair.second.c_str(), val);
    }
    eprintf("stack dump:\n");

    uint8_t stack[32];
    uint32_t stack_ptr;
    uc_reg_read(uc, UC_MIPS_REG_SP, &stack_ptr);
    uc_mem_read(uc, stack_ptr, stack, sizeof(stack));
    print_hex_dump(stack_ptr, stack, sizeof(stack), 4);
}

const std::vector<uint8_t>& ABIAbstractionMips32BE::ret_instr() const {
    static const std::vector<uint8_t> ret { 0x03, 0xe0, 0x00, 0x08 };

    return ret;
}

const std::vector<uint8_t>& ABIAbstractionMips32LE::ret_instr() const {
    static const std::vector<uint8_t> ret { 0x08, 0x00, 0xe0, 0x03 };

    return ret;
}
