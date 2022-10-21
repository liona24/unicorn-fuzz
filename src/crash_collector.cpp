#include "crash_collector.h"

#include <algorithm>
#include <fstream>
#include <functional>
#include <string_view>

namespace {
std::string format(const char* format, ...) {
    constexpr size_t max_size = 512;
    char buf[512] = { 0 };

    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, max_size, format, ap);
    va_end(ap);

    return buf;
}
} // namespace

bool file_matches_content(const std::filesystem::path& path, const uint8_t* buf, size_t buf_size) {
    std::basic_ifstream<uint8_t> file(path, std::ios::binary | std::ios::ate);
    std::streamsize size = file.tellg();

    if (size != buf_size) {
        return false;
    }

    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> content((std::istreambuf_iterator<uint8_t>(file)),
                                 std::istreambuf_iterator<uint8_t>());

    return std::equal(content.begin(), content.end(), buf, buf + buf_size);
}

void CrashCollector::track_next_input(const uint8_t* data, size_t size) {
    current_input_ = data;
    current_input_size_ = size;
}

bool CrashCollector::report_state_as_crash_if_new(uc_engine* uc,
                                                  uc_err err,
                                                  const IABIAbstraction& abi) {

    const uint64_t pc = abi.read_pc(uc);

    const std::string_view data(reinterpret_cast<const char*>(current_input_), current_input_size_);
    const auto hash = std::hash<std::string_view> {}(data);

    std::string path = ::format("crash-%016x-%016x", pc, hash);

    const auto it = crashes_.find(pc);
    if (it != crashes_.end() && it->second.hash == hash &&
        file_matches_content(path, current_input_, current_input_size_)) {
        return false;
    }

    if (it != crashes_.end()) {
        it->second.hit_count++;

        if (it->second.hit_count == 5) {
            fprintf(stderr, "!!! ignoring future crashes at PC %lx !!!\n", pc);
        }
        if (it->second.hit_count >= 5) {
            return true;
        }

        path += ".duplicate";
    } else {
        crashes_.emplace(pc, hash);
    }

    {
        std::fstream fout(path, std::ios::binary | std::ios::out);
        if (!fout.write(reinterpret_cast<const char*>(current_input_), current_input_size_)) {
            WARN("writing crashes failed!");
            abort();
        }
    }

    fprintf(stderr, "!!! NEW CRASH FOUND !!!\n");

    if (err != UC_ERR_OK) {
        fprintf(stderr, "UC_ERROR: %s\n", uc_strerror(err));
    }

    abi.render_context(uc);

    fprintf(stderr, "saving crash to %s\n", path.c_str());

    return true;
}
