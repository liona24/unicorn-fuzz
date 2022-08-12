#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char* c_readfile(char* filename, size_t* filesize) {
    unsigned char* buffer = NULL;
    int read_size;
    FILE* handler = fopen(filename, "rb");
    if (handler) {
        fseek(handler, 0, SEEK_END);
        *filesize = ftell(handler);
        rewind(handler);
        buffer = (unsigned char*)malloc(sizeof(char) * (*filesize + 1));
        read_size = fread(buffer, sizeof(char), *filesize, handler);
        // buffer[filesize] = '\0';
        if (*filesize != read_size) {
            free(buffer);
            buffer = NULL;
        }
        fclose(handler);
    }
    return buffer;
}

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

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#define printf_(...)
#else
#define printf_(...) printf(__VA_ARGS__)
#endif

typedef struct {
    header_t Header;
    char Buffer[BUF_SIZE];
} content_t, *pcontent_t;

pcontent_t parse_data(const unsigned char* buffer, size_t buf_len) {
    if (buf_len < sizeof(header_t)) {
        return NULL;
    }

    pcontent_t parsed = (pcontent_t)malloc(sizeof(content_t));
    if (parsed == NULL) {
        printf_("no mem!\n");
        return NULL;
    }

    memcpy(&parsed->Header, buffer, sizeof(header_t));

    switch (parsed->Header.Kind) {
    case STYPE_ANGELO:
        printf_("Got kind ANGELO!\n");
        break;
    case STYPE_JACK:
        printf_("Got kind JACK!\n");
        break;
    case STYPE_DZONERZY:
        printf_("Got kind DZONERZY!\n");
        break;
    default:
        printf_("Invalid kind 0x%lx\n", parsed->Header.Kind);
        goto error;
    }

    printf_("Got size: 0x%x\n", parsed->Header.Length);

    // (DONT) FIXME: integer addition overflow
    if ((short)(parsed->Header.Length + 1) > BUF_SIZE) {
        printf_("invalid length > %d\n", BUF_SIZE);
        goto error;
    }

    if (buf_len < sizeof(header_t) + parsed->Header.Length) {
        printf_("invalid buffer length\n");
        goto error;
    }

    memcpy(parsed->Buffer, buffer + sizeof(header_t), parsed->Header.Length);
    return parsed;

error:
    free(parsed);
    return NULL;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pcontent_t ret = parse_data(data, size);
    if (ret != NULL) {
        free(ret);
        return 0;
    }

    return -1;
}
#else
int main(int argc, char** argv) {
    if (argc == 2) {
        char* inputfile = argv[1];
        printf("Using input file: %s\n", inputfile);
        size_t filesize = 0;
        unsigned char* buffer = c_readfile(inputfile, &filesize);
        if (!buffer) {
            printf("Invalid file specified!\n");
            exit(-1);
        }
        printf("Got file %lu bytes, start parsing\n", filesize);
        pcontent_t ret = parse_data(buffer, filesize);
        if (ret != NULL) {
            printf("Kind: 0x%lx Length: 0x%08x Buffer: %32s\n", ret->Header.Kind,
                   ret->Header.Length, ret->Buffer);
            free(ret);
        }
    } else {
        printf("Usage: %s <input>\n", argv[0]);
        return -1;
    }

    return 0;
}
#endif
