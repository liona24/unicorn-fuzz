import base64
from dataclasses import dataclass
import json
import zlib

from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_ARCH_MIPS, UC_MODE_32, UC_ARCH_ARM, UC_MODE_ARM
import unicorn.unicorn_const as unicorn_const
import unicorn.x86_const as x86
import unicorn.mips_const as mips
import unicorn.arm_const as arm

from lfu.bind import map_memory, init_engine

WARN_ONCE = [True]

@dataclass
class ArchConfig():
    uc_args : tuple[int, int]
    reg_mod : object
    reg_prefix : str

    def reg_name_to_uc_const(self, name):
        if name == "eflags":
            name = "flags"

        rv = getattr(self.reg_mod, f"{self.reg_prefix}{name.upper()}", None)
        if rv is None and WARN_ONCE[0]:
            print(f"WARN: ignoring reg {name}: I dont know the unicorn alias.")

        return rv


SUPPORTED_ARCHS = {
    "mips:isa32r2": ArchConfig((UC_ARCH_MIPS, UC_MODE_32), mips, "UC_MIPS_REG_"),
    "i386:x86-64": ArchConfig((UC_ARCH_X86, UC_MODE_64), x86, "UC_X86_REG_"),
    "armv5t": ArchConfig((UC_ARCH_ARM, UC_MODE_ARM), arm, "UC_ARM_REG_"),
}


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


def restore(file_or_obj, uc: Uc | None = None, ignore_ro=True):

    snap = file_or_obj
    if not isinstance(file_or_obj, dict):
        snap = json.load(file_or_obj)

    arch_conf = SUPPORTED_ARCHS.get(snap["arch"], None)

    assert arch_conf is not None, "Not implemented: " + snap["arch"]

    redo_mapping = False

    if uc is None:
        uc = Uc(*arch_conf.uc_args)
        init_engine(uc)
        ignore_ro = False
        redo_mapping = True

    for regname, value in snap["registers"].items():
        reg = arch_conf.reg_name_to_uc_const(regname)
        if reg is not None:
            uc.reg_write(reg, value)

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

    WARN_ONCE[0] = False
    return uc
