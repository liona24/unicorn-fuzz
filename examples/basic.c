#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void parse_data(const uint8_t* buffer, size_t buf_len) {
    if (buf_len < 3) {
        return;
    }

    if (buffer[0] == 'A') {
        abort();
    }
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_data(data, size);

    return 0;
}
#else
int main(int argc, char** argv) {
    if (argc == 2) {
        parse_data((const uint8_t*)argv[1], strlen(argv[1]));
    } else {
        printf("Usage: %s <input>\n", argv[0]);
        return -1;
    }

    return 0;
}
#endif
