import base64
import json
import zlib

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64
import unicorn.unicorn_const as unicorn_const
import unicorn.x86_const as x86

from lfu.bind import map_memory, init_engine


def perm_name_to_uc_flags(name):
    perm = unicorn_const.UC_PROT_NONE
    if name.count("r"):
        perm |= unicorn_const.UC_PROT_READ
    if name.count("w"):
        perm |= unicorn_const.UC_PROT_WRITE
    if name.count("x"):
        perm |= unicorn_const.UC_PROT_EXEC

    return perm


def decompress_mem(b64_rep):
    compressed = base64.b64decode(b64_rep)
    return zlib.decompress(compressed)


def reg_name_to_uc_const(name):
    if name == "eflags":
        name = "flags"

    return getattr(x86, f"UC_X86_REG_{name.upper()}")


def restore(file_or_obj, uc: Uc | None = None, ignore_ro=True):

    snap = file_or_obj
    if not isinstance(file_or_obj, dict):
        snap = json.load(file_or_obj)

    assert snap["arch"] == "i386:x86-64", "Not implemented!"

    redo_mapping = False

    if uc is None:
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        init_engine(uc)
        ignore_ro = False
        redo_mapping = True

    for reg, value in snap["registers"].items():
        uc.reg_write(reg_name_to_uc_const(reg), value)

    writable = set()

    for mapp in snap["maps"]:
        start = mapp["start"]
        end = mapp["end"]
        perm = perm_name_to_uc_flags(mapp["permissions"])
        size = end - start

        if perm & unicorn_const.UC_PROT_WRITE:
            writable.add(start)

        if redo_mapping:
            map_memory(start, size, perm, mapp["path"])

    for addr, mem in snap["memory"].items():
        if ignore_ro and not addr in writable:
            continue

        uc.mem_write(int(addr), decompress_mem(mem))

    return uc
