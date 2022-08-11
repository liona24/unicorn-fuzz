import ctypes
import os
from typing import Callable

import unicorn

SHARED_LIB_PATH = os.path.join(os.path.dirname(__file__), "lib", "liblfu.so")
LIB = ctypes.cdll.LoadLibrary(SHARED_LIB_PATH)

LFU_INIT_CALLBACK_TY = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t)

_lfu_init_engine = LIB.lfu_init_engine
_lfu_init_engine.argtypes = [
    ctypes.c_void_p # uc
]

_lfu_start_fuzzer = LIB.lfu_start_fuzzer
_lfu_start_fuzzer.argtypes = [
    ctypes.c_int, # argc
    ctypes.POINTER(ctypes.c_char_p), # argv
    LFU_INIT_CALLBACK_TY,
    ctypes.c_uint64, # begin
    ctypes.c_uint64, # until
]
_lfu_start_fuzzer.restype = ctypes.c_int

_lfu_map_memory = LIB.lfu_mmap
_lfu_map_memory.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_int,
    ctypes.c_char_p,
]
_lfu_map_memory.restype = ctypes.c_uint64

_lfu_replace_allocator = LIB.lfu_replace_allocator
_lfu_replace_allocator.argtypes = [
    ctypes.c_uint64,
    ctypes.c_uint64,
    ctypes.c_size_t,
]
_lfu_replace_allocator.restype = ctypes.c_int

_lfu_allocate = LIB.lfu_allocate
_lfu_allocate.argtypes = [
    ctypes.c_uint64,
]
_lfu_allocate.restype = ctypes.c_uint64

_lfu_deallocate = LIB.lfu_deallocate
_lfu_deallocate.argtypes = [
    ctypes.c_uint64,
]

_lfu_add_patch = LIB.lfu_add_patch
_lfu_add_patch.argtypes = [
    ctypes.c_uint64,
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_char_p,
]

def _wrap_init(init: Callable[[bytes], int]):

    @LFU_INIT_CALLBACK_TY
    def wrapper(data_raw, size):
        data = ctypes.string_at(data_raw, size)
        return init(data)

    return wrapper


def init_engine(uc: unicorn.Uc):
    _lfu_init_engine(uc._uch)


def start_fuzzer(argv: list[str], init: Callable[[bytes], int], begin: int, until: int):
    c_argv = (ctypes.c_char_p * (len(argv) + 1))()
    c_argv[0] = b"lfu"
    c_argv[1:] = list(map(str.encode, argv))

    init = _wrap_init(init)

    rv = _lfu_start_fuzzer(len(argv) + 1, c_argv, init, begin, until)

    if rv != 0:
        raise RuntimeError(f"lfu_start_fuzzer exit code {rv}")


def map_memory(addr: int, size: int, perm: int, name: str | None=None):
    if name is None:
        name = ""
    name = name.encode()

    rv = _lfu_map_memory(addr, size, perm, name)

    if rv == 0 or (addr != 0 and rv != addr):
        raise RuntimeError(f"lfu_map_memory returned {rv}")


def replace_allocator(malloc_addr: int, free_addr: int, pool_size: int):
    rv = _lfu_replace_allocator(malloc_addr, free_addr, pool_size)

    if rv != 0:
        raise RuntimeError(f"lfu_replace_allocator return code {rv}")


def allocate(size: int) -> int:
    return _lfu_allocate(size)


def deallocate(addr: int) -> int:
    return _lfu_deallocate(addr)


def add_patch(addr: int, patch: bytes, name: str | None=None):
    _lfu_add_patch(addr, patch, len(patch), name.encode())
