#include "abi.h"

#include <cassert>
#include <fstream>
#include <map>
#include <ostream>
#include <stdio.h>
#include <string>

#include "capstone.h"
#include "defs.h"

#include "mips.h"
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

#define HAS(m) ((mode & m) != 0 || mode == 0)

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
    case UC_ARCH_ARM:
        if (HAS(UC_MODE_ARM)) {
            return new ABIAbstractionArm32EABI;
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

static const std::map<uint32_t, std::string> ARM32_REGS = {
    { UC_ARM_REG_R0, "r0" },   { UC_ARM_REG_R1, "r1" },     { UC_ARM_REG_R2, "r2" },
    { UC_ARM_REG_R3, "r3" },   { UC_ARM_REG_R4, "r4" },     { UC_ARM_REG_R5, "r5" },
    { UC_ARM_REG_R6, "r6" },   { UC_ARM_REG_R7, "r7" },     { UC_ARM_REG_R8, "r8" },
    { UC_ARM_REG_R9, "r9" },   { UC_ARM_REG_R10, "r10" },   { UC_ARM_REG_R11, "r11" },
    { UC_ARM_REG_R12, "r12" }, { UC_ARM_REG_SP, "sp" },     { UC_ARM_REG_LR, "lr" },
    { UC_ARM_REG_PC, "pc" },   { UC_ARM_REG_CPSR, "cpsr" },
};

std::pair<cs_arch, cs_mode> ABIAbstractionX86_64::get_capstone_arch() const {
    return std::make_pair(CS_ARCH_X86, CS_MODE_64);
}

uint64_t ABIAbstractionX86_64::read_pc(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_X86_REG_RIP);
}
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

void ABIAbstractionX86_64::render_context(uc_engine* uc) const {
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

std::pair<cs_arch, cs_mode> ABIAbstractionMips32X::get_capstone_arch() const {
    return std::make_pair(CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | endianess()));
}

uint64_t ABIAbstractionMips32X::read_pc(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_MIPS_REG_PC);
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

void ABIAbstractionMips32X::render_context(uc_engine* uc) const {
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

CmpInstrData::CmpInstrData(uc_engine* uc,
                           cs_arch arch,
                           cs_mode mode,
                           std::function<CmpInstrCallback> callback,
                           void* hook_ptr)
    : uc(uc)
    , callback(callback) {
    cs_err err;

    if ((err = cs_open(arch, mode, &ch)) != CS_ERR_OK ||
        (err = cs_option(ch, CS_OPT_DETAIL, CS_OPT_ON)) != CS_ERR_OK) {
        WARN("failed to initialize capstone: %s", cs_strerror(err));
        return;
    }

    insn = cs_malloc(ch);
    if (insn == nullptr) {
        WARN("could not allocate insn buffer: %s", cs_strerror(cs_errno(ch)));
        return;
    }

    uc_err uerr = uc_hook_add(uc, &hook, UC_HOOK_CODE, hook_ptr, (void*)this, 1, 0);
    if (uerr != UC_ERR_OK) {
        WARN("error adding cmp instrumentation hook: %s", uc_strerror(uerr));
        return;
    }

    is_init = true;
}

CmpInstrData::~CmpInstrData() {
    if (is_init) {
        if (insn) {
            cs_free(insn, 1);
            insn = nullptr;
        }

        cs_close(&ch);
        ch = 0;

        is_init = false;
    }

    if (hook) {
        uc_hook_del(uc, hook);
        hook = 0;
    }
}

InsnTracer::InsnTracer(const IABIAbstraction& abi) {
    const auto arch = abi.get_capstone_arch();

    cs_err err = cs_open(arch.first, arch.second, &ch);
    if (err != CS_ERR_OK) {
        WARN("failed to initialize capstone: %s", cs_strerror(err));
        return;
    }

    insn = cs_malloc(ch);
    if (insn == nullptr) {
        WARN("could not allocate insn buffer: %s", cs_strerror(cs_errno(ch)));
        return;
    }

    is_init = true;
}

InsnTracer::~InsnTracer() {
    if (is_init) {
        if (insn) {
            cs_free(insn, 1);
            insn = nullptr;
        }

        cs_close(&ch);
        ch = 0;
        is_init = false;
    }
}

bool InsnTracer::disassemble_one_insn(uint64_t addr, const uint8_t* buffer, size_t size) {
    if (!is_init) {
        return false;
    }

    if (!cs_disasm_iter(ch, &buffer, &size, &addr, insn)) {
        TRACE("decoding instruction failed: %s", cs_strerror(cs_errno(ch)));
        return false;
    }

    return true;
}

static bool get_value_of_operand_mips(uc_engine* uc, const cs_mips_op& op, uint32_t& out) {
    switch (op.type) {
    case MIPS_OP_REG: {
        static_assert((int)MIPS_REG_0 == UC_MIPS_REG_0,
                      "capstone and unicorn registers are incompatible!");

        uc_err err = uc_reg_read(uc, (int)op.reg, &out);
        if (err != UC_ERR_OK) {
            TRACE("register reading failed: %s", uc_strerror(err));
            return false;
        }
        break;
    }
    case MIPS_OP_IMM:
        out = static_cast<uint32_t>(op.imm);
        break;
    case MIPS_OP_MEM:
    case MIPS_OP_INVALID:
        // we do not handle those
        return false;
    }

    return true;
}

static void additional_instr_hook_mips(uc_engine* uc,
                                       uint64_t addr,
                                       uint32_t size,
                                       void* user_data) {
    assert(size == 4 && "this does not seem to be mips32?");

    CmpInstrData* d = reinterpret_cast<CmpInstrData*>(user_data);

    uint8_t code[4] = { 0 };
    uc_err err = uc_mem_read(uc, addr, code, size);
    if (err != UC_ERR_OK) {
        TRACE("reading instruction failed: %s", uc_strerror(err));
        return;
    }

    const uint8_t* code_p = code;
    size_t size_copy = size;
    uint64_t addr_copy = addr;

    if (!cs_disasm_iter(d->ch, &code_p, &size_copy, &addr_copy, d->insn)) {
        TRACE("decoding instruction failed: %s", cs_strerror(cs_errno(d->ch)));
        return;
    }

    if (!cs_insn_group(d->ch, d->insn, CS_GRP_JUMP)) {
        return;
    }
    TRACE("[%lx] %s\t%s", addr, d->insn->mnemonic, d->insn->op_str);

    // Conditional jumps which compare one/two registers / immediates
    // in case of 3 operands, the first and second operand can be fetched
    // in case of 2 operands, the compared value will be zero
    // in any case, the last operand will be the branch target
    uint32_t operands[2] = { 0 };
    const uint8_t op_count = d->insn->detail->mips.op_count;
    if (op_count == 3 || op_count == 2) {
        // the first n - 1 operands will be the registers to compare
        for (int i = 0; i < op_count - 1; i++) {
            if (!get_value_of_operand_mips(uc, d->insn->detail->mips.operands[i], operands[i])) {
                // could not get concrete value, ignore
                return;
            }
        }

        constexpr uint32_t size = 32;
        d->callback(operands[0], operands[1], size);
    }
}

void ABIAbstractionMips32X::add_additional_cmp_instrumentation(
    uc_engine* uc,
    std::function<CmpInstrCallback> cmp_callback) {

    instr_.reset(new CmpInstrData(uc, CS_ARCH_MIPS, cs_mode(CS_MODE_MIPS32 | endianess()),
                                  cmp_callback, (void*)&additional_instr_hook_mips));
    if (!instr_->is_init) {
        WARN("continuing without additional coverage instrumentation!");
        return;
    }

    TRACE("enabled additional coverage instrumentation hooks");
}

cs_mode ABIAbstractionMips32BE::endianess() const { return CS_MODE_BIG_ENDIAN; }

const std::vector<uint8_t>& ABIAbstractionMips32BE::ret_instr() const {
    static const std::vector<uint8_t> ret { 0x03, 0xe0, 0x00, 0x08 };

    return ret;
}

cs_mode ABIAbstractionMips32LE::endianess() const { return CS_MODE_LITTLE_ENDIAN; }

const std::vector<uint8_t>& ABIAbstractionMips32LE::ret_instr() const {
    static const std::vector<uint8_t> ret { 0x08, 0x00, 0xe0, 0x03 };

    return ret;
}

std::pair<cs_arch, cs_mode> ABIAbstractionArm32EABI::get_capstone_arch() const {
    return std::make_pair(CS_ARCH_ARM, CS_MODE_ARM);
}

uint64_t ABIAbstractionArm32EABI::read_pc(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_ARM_REG_PC);
}
uint64_t ABIAbstractionArm32EABI::read_arg0(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_ARM_REG_R0);
}
uint64_t ABIAbstractionArm32EABI::read_arg1(uc_engine* uc) const {
    return read_reg_wrapper(uc, UC_ARM_REG_R1);
}
void ABIAbstractionArm32EABI::set_ret(uc_engine* uc, uint64_t val) const {
    write_reg_wrapper(uc, UC_ARM_REG_R0, val);
}

void ABIAbstractionArm32EABI::render_context(uc_engine* uc) const {
    eprintf("registers:\n");
    for (const auto& pair : ARM32_REGS) {
        uint32_t val;
        uc_reg_read(uc, pair.first, &val);
        eprintf(" %s\t= %08x\n", pair.second.c_str(), val);
    }
    eprintf("stack dump:\n");

    uint8_t stack[32];
    uint32_t stack_ptr;
    uc_reg_read(uc, UC_ARM_REG_SP, &stack_ptr);
    uc_mem_read(uc, stack_ptr, stack, sizeof(stack));
    print_hex_dump(stack_ptr, stack, sizeof(stack), 4);
}

const std::vector<uint8_t>& ABIAbstractionArm32EABI::ret_instr() const {
    static const std::vector<uint8_t> ret { 0x1e, 0xff, 0x2f, 0xe1 };

    return ret;
}
