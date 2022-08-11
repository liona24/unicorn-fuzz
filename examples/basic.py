import base64
import json

import lfu
import unicorn
import unicorn.x86_const as x86
from pwn import ELF


BINARY_PATH = "build/examples/basic"
ROOTFS = "/"
ARGV = [BINARY_PATH]

BINARY = ELF(BINARY_PATH)

# parse_data and its body
# TODO: parse this from binary
START_ADDR = 0x401150
# END_ADDR = 0x4011b6
END_ADDR = 0x40118a

def do_fuzzing(snapshot: dict, fuzzArgs: list[str]):
    uc = lfu.restore(snapshot)

    target = uc.reg_read(x86.UC_X86_REG_RDI)
    max_size = uc.reg_read(x86.UC_X86_REG_RSI)

    print("target", hex(target))
    print("max_size", max_size)

    def restore(data):
        if len(data) > max_size:
            return -1

        lfu.restore(snapshot, uc=uc)

        uc.reg_write(x86.UC_X86_REG_RSI, len(data))
        uc.mem_write(target, data)

        return 0

    def handle_instr(uc, addr, size, _user_data):
        print(hex(addr), size, uc.mem_read(addr, size).hex(), "rsi =", hex(uc.reg_read(x86.UC_X86_REG_RSI)))

    def handle_mem(uc, ty, addr, size, value, _user_data):
        print("mem", hex(addr), "size", size, "value", value, hex(value))

    # uc.hook_add(unicorn.UC_HOOK_CODE, handle_instr)
    # uc.hook_add(unicorn.UC_HOOK_MEM_VALID, handle_mem)

    lfu.start_fuzzer(["-print_pcs=1"], restore, START_ADDR, END_ADDR)

    # restore(b"ABCsdk")
    # print(uc.emu_start(START_ADDR, END_ADDR))



def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--snapshot", help="path to the snapshot", required=True)
    parser.add_argument("libFuzzerArgs", nargs=argparse.REMAINDER)
    args = parser.parse_args()


    fuzzArgs = args.libFuzzerArgs

    if len(fuzzArgs) > 0 and fuzzArgs[0] == "--":
        fuzzArgs = fuzzArgs[1:]

    with open(args.snapshot, "r") as fin:
        snapshot = json.load(fin)

    do_fuzzing(snapshot, fuzzArgs)


if __name__ == '__main__':
    main()
