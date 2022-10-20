#pragma once

#include <functional>
#include <memory>
#include <vector>

#include <capstone/capstone.h>
#include <unicorn/unicorn.h>

// (arg1, arg2, size in bits)
using CmpInstrCallback = void(uint64_t, uint64_t, uint32_t);
struct CmpInstrData {
    CmpInstrData(uc_engine* uc,
                 cs_arch arch,
                 cs_mode mode,
                 std::function<CmpInstrCallback> callback,
                 void* hook_ptr);
    ~CmpInstrData();

    bool is_init { false };

    csh ch { 0 };
    cs_insn* insn { nullptr };

    uc_engine* uc { nullptr };
    uc_hook hook { 0 };

    std::function<CmpInstrCallback> callback;
};

class IABIAbstraction {
public:
    virtual ~IABIAbstraction() = default;

    virtual uint64_t read_arg0(uc_engine* uc) const = 0;
    virtual uint64_t read_arg1(uc_engine* uc) const = 0;
    virtual void set_ret(uc_engine* uc, uint64_t val) const = 0;

    virtual const std::vector<uint8_t>& ret_instr() const = 0;

    virtual void render_context(uc_engine* uc) const = 0;

    virtual void add_additional_cmp_instrumentation(uc_engine*, std::function<CmpInstrCallback>) {}

    static IABIAbstraction* for_uc(uc_engine* uc);

protected:
    uint64_t read_reg_wrapper(uc_engine* uc, int regid) const;
    void write_reg_wrapper(uc_engine* uc, int regid, uint64_t value) const;
};

class ABIAbstractionX86_64 : public IABIAbstraction {
public:
    virtual ~ABIAbstractionX86_64() override = default;

    uint64_t read_arg0(uc_engine* uc) const final;
    uint64_t read_arg1(uc_engine* uc) const final;
    void set_ret(uc_engine* uc, uint64_t val) const final;

    const std::vector<uint8_t>& ret_instr() const final;

    void render_context(uc_engine* uc) const final;
};

class ABIAbstractionMips32X : public IABIAbstraction {
public:
    virtual ~ABIAbstractionMips32X() override = default;

    uint64_t read_arg0(uc_engine* uc) const final;
    uint64_t read_arg1(uc_engine* uc) const final;
    void set_ret(uc_engine* uc, uint64_t val) const final;

    void render_context(uc_engine* uc) const final;

    void add_additional_cmp_instrumentation(uc_engine*, std::function<CmpInstrCallback>) final;

protected:
    virtual cs_mode endianess() const = 0;

    std::unique_ptr<CmpInstrData> instr_;

    static const std::vector<uint8_t> ret_instr_le;
};

class ABIAbstractionMips32BE : public ABIAbstractionMips32X {
public:
    virtual ~ABIAbstractionMips32BE() override = default;

    const std::vector<uint8_t>& ret_instr() const final;

protected:
    cs_mode endianess() const final;
};

class ABIAbstractionMips32LE : public ABIAbstractionMips32X {
public:
    virtual ~ABIAbstractionMips32LE() override = default;

    const std::vector<uint8_t>& ret_instr() const final;

protected:
    cs_mode endianess() const final;
};

class ABIAbstractionArm32EABI : public IABIAbstraction {
    virtual ~ABIAbstractionArm32EABI() override = default;

    uint64_t read_arg0(uc_engine* uc) const final;
    uint64_t read_arg1(uc_engine* uc) const final;
    void set_ret(uc_engine* uc, uint64_t val) const final;

    const std::vector<uint8_t>& ret_instr() const final;

    void render_context(uc_engine* uc) const final;
};
