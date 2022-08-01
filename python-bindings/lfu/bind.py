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

def _wrap_init(init: Callable[[unicorn.Uc, bytes], int]):

    @LFU_INIT_CALLBACK_TY
    def wrapper(data_raw, size):
        data = bytes(ctypes.cast(data_raw, ctypes.POINTER(ctypes.c_uint8 * size)))
        return init(data)

    return wrapper


def init_engine(uc: unicorn.Uc):
    _lfu_init_engine(uc._uch)


def start_fuzzer(argv: list[str], init: Callable[[bytes], int], begin: int, until: int):
    c_argv = (ctypes.c_char_p * (len(argv) + 1))()
    c_argv[:-1] = list(map(str.encode, argv))
    c_argv[-1] = None

    init = _wrap_init(init)

    rv = _lfu_start_fuzzer(len(argv), c_argv, init, begin, until)

    if rv != 0:
        raise RuntimeError(f"lfu_start_fuzzer exit code {rv}")
