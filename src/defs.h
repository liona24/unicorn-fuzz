#pragma once

#define WARN(msg, ...) fprintf(stderr, "[!] %s:%d - " msg "\n", __FILE__, __LINE__, ##__VA_ARGS__)

#ifndef NDEBUG
#define TRACE(msg, ...) fprintf(stderr, "[*] %s " msg "\n", __PRETTY_FUNCTION__, ##__VA_ARGS__)
#else
#define TRACE(msg, ...)
#endif
