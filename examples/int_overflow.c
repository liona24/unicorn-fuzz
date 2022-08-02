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
    char* Buffer;
} content_t, *pcontent_t;

pcontent_t parse_data(const unsigned char* buffer, size_t buf_len) {
    pcontent_t data = (pcontent_t)malloc(sizeof(content_t));
    data->Kind = STYPE_INVALID;
    data->Length = 0;
    data->Buffer = NULL;
    size_t counter = 0;
    while (counter < buf_len) {
        // (DONT) FIXME: heap buffer OOB read
        unsigned long long kind = *(unsigned long long*)(buffer + counter);
        switch (kind) {
        case STYPE_ANGELO:
            printf("Got kind ANGELO!\n");
            data->Kind = kind;
            break;
        case STYPE_JACK:
            printf("Got kind JACK!\n");
            data->Kind = kind;
            break;
        case STYPE_DZONERZY:
            printf("Got kind DZONERZY!\n");
            data->Kind = kind;
            break;
        default:
            printf("Invalid kind 0x%llx\n", kind);
            return NULL;
        }
        counter += sizeof(kind);
        data->Length = *(short*)(buffer + counter);
        counter += sizeof(data->Length);
        printf("Got size: 0x%x\n", data->Length);
        // (DONT) FIXME: integer addition overflow
        if ((short)(data->Length + 1) > 32) {
            printf("invalid length > 32\n");
            return NULL;
        } else {
            data->Buffer = malloc(32);
            memset(data->Buffer, 0, data->Length);
            memcpy(data->Buffer, (buffer + counter), data->Length);
        }
        counter += data->Length;
        printf("counter = %zu\n", counter);
    }
    return data;
}

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    pcontent_t ret = parse_data(data, size);
    if (ret != NULL) {
        free(ret);
    }

    return 0;
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
        printf("Kind: 0x%lx Length: 0x%08x Buffer: %p\n", ret->Kind, ret->Length, ret->Buffer);
    } else {
        printf("Usage: %s <input>\n", argv[0]);
        return -1;
    }

    return 0;
}
#endif
