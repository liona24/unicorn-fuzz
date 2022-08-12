#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef __cplusplus
extern "C" {
#endif

extern void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);
extern void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
extern void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
extern void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);

#ifdef __cplusplus
}
#endif

typedef enum {
    STYPE_ANGELO = 0xdeadbeef,
    STYPE_JACK = 0xcafebabe,
    STYPE_DZONERZY = 0xc00fc00f,
    STYPE_INVALID = -1
} stype_t;

typedef char byte;
typedef unsigned char ubyte;

typedef struct {
    stype_t Kind;
    short Length;
} header_t;

#define BUF_SIZE 32

typedef struct {
    header_t Header;
    char Buffer[BUF_SIZE];
} content_t, *pcontent_t;

pcontent_t parse_data(const unsigned char* buffer, size_t buf_len) {
    __sanitizer_cov_trace_cmp8(buf_len, sizeof(header_t));
    if (buf_len < sizeof(header_t)) {
        return NULL;
    }

    pcontent_t parsed = (pcontent_t)malloc(sizeof(content_t));
    __sanitizer_cov_trace_cmp8((uint64_t)parsed, 0);
    if (parsed == NULL) {
        return NULL;
    }

    memcpy(&parsed->Header, buffer, sizeof(header_t));

    __sanitizer_cov_trace_cmp4(parsed->Header.Kind, STYPE_ANGELO);
    __sanitizer_cov_trace_cmp4(parsed->Header.Kind, STYPE_JACK);
    __sanitizer_cov_trace_cmp4(parsed->Header.Kind, STYPE_DZONERZY);
    switch (parsed->Header.Kind) {
    case STYPE_ANGELO:
    case STYPE_JACK:
    case STYPE_DZONERZY:
        break;
    default:
        goto error;
    }

    // (DONT) FIXME: integer addition overflow
    __sanitizer_cov_trace_cmp4((short)(parsed->Header.Length + 1), BUF_SIZE);
    if ((short)(parsed->Header.Length + 1) > BUF_SIZE) {
        goto error;
    }

    if (buf_len < sizeof(header_t) + parsed->Header.Length) {
        goto error;
    }

    memcpy(parsed->Buffer, buffer + sizeof(header_t), parsed->Header.Length);
    return parsed;

error:
    free(parsed);
    return NULL;
}

int test_one_input(const uint8_t* data, size_t size) {
    pcontent_t ret = parse_data(data, size);
    if (ret != NULL) {
        free(ret);
        return 0;
    }

    return -1;
}

extern "C" int LLVMFuzzerRunDriver(int* argc,
                                   char*** argv,
                                   int (*UserCb)(const uint8_t* Data, size_t Size));

int main(int argc, char* argv[]) { return LLVMFuzzerRunDriver(&argc, &argv, &test_one_input); }
