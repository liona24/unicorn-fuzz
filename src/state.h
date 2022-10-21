#pragma once

#include <initializer_list>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <unicorn/unicorn.h>

#include "abi.h"
#include "allocator.h"
#include "coverage.h"
#include "crash_collector.h"
#include "defs.h"
#include "lfu.h"

struct Patch {
    uint64_t addr;
    std::vector<uint8_t> patch;
    std::string name;

    Patch(const Patch&) = delete;
    Patch(Patch&&) = delete;

    Patch() = delete;
    Patch(uint64_t addr, const std::vector<uint8_t>& patch, const std::string& name)
        : addr(addr)
        , patch(patch)
        , name(name) {}

    uc_err apply(uc_engine* uc) const {
        TRACE("applying patch %s", name.c_str());
        uc_err err = uc_mem_write(uc, addr, patch.data(), patch.size());
        if (err != UC_ERR_OK) {
            WARN("applying patch \"%s\" failed: %s", name.c_str(), uc_strerror(err));
        }

        return err;
    }
};

struct State {
    explicit State() {}

    ~State() {
        if (uc && context) {
            uc_context_free(context);
            context = nullptr;
        }
    }

    static State& the(bool reset = false) {
        thread_local static std::unique_ptr<State> instance { nullptr };

        if (!instance || reset) {
            instance.reset(new State);
        }

        return *instance.get();
    }

    void crash(uc_err err = UC_ERR_OK) {
        if (!uc) {
            WARN("unicorn was not initialized but a crash was initiated!");
            abort();
        }
        if (!abi) {
            WARN("ABI was not initialized but a crash was initiated!");
            abort();
        }

        if (crash_collector) {
            crash_collector->report_state_as_crash_if_new(uc, err, *abi);

            // emulation may be stopped already, we simply ignore the return code
            uc_emu_stop(uc);
        } else {
            abi->render_context(uc);
            abort();
        }
    }

    uc_engine* uc { nullptr };
    std::unique_ptr<IABIAbstraction> abi { nullptr };

    // Address range to simulate for each input
    uint64_t begin, until;
    uc_context* context { nullptr };
    init_context init_context_callback { nullptr };

    std::unique_ptr<MemoryMap> mmem { nullptr };
    std::unique_ptr<Allocator> allocator { nullptr };
    std::unique_ptr<Coverage> coverage { nullptr };

    std::unique_ptr<CrashCollector> crash_collector { nullptr };

    std::vector<uc_hook> h_malloc;
    std::vector<uc_hook> h_free;

    std::list<Patch> patches {};
};
