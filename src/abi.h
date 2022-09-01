#pragma once

#include <vector>

#include <unicorn/unicorn.h>

class IABIAbstraction {
public:
    virtual uint64_t read_arg0(uc_engine* uc) const = 0;
    virtual uint64_t read_arg1(uc_engine* uc) const = 0;
    virtual void set_ret(uc_engine* uc, uint64_t val) const = 0;

    virtual const std::vector<uint8_t>& ret_instr() const = 0;

    virtual void render_crash_context(uc_engine* uc) const = 0;

protected:
    uint64_t read_reg_wrapper(uc_engine* uc, int regid) const;
    void write_reg_wrapper(uc_engine* uc, int regid, uint64_t value) const;
};

class ABIAbstractionX86_64 : public IABIAbstraction {
public:
    uint64_t read_arg0(uc_engine* uc) const final;
    uint64_t read_arg1(uc_engine* uc) const final;
    void set_ret(uc_engine* uc, uint64_t val) const final;

    const std::vector<uint8_t>& ret_instr() const final;

    void render_crash_context(uc_engine* uc) const final;
};
