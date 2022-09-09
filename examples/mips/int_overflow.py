import base64
import json

import lfu
import unicorn
import unicorn.mips_const as mips


BINARY_PATH = "examples/mips/int_overflow"

START_ADDR = 0x00400940
END_ADDR = 0x00400c3c

PUTS = 0x40f3e0
PRINTF = 0x4084e0
MALLOC = 0x00420ffc
FREE = 0x004217dc


def do_fuzzing(snapshot: dict, fuzzArgs: list[str]):
    uc = lfu.restore(snapshot)

    lfu.replace_allocator(MALLOC, FREE, 0x10000)

    lfu.add_patch(PRINTF, b"\x08\x00\xe0\x03", "printf")
    lfu.add_patch(PUTS, b"\x08\x00\xe0\x03", "puts")

    target = uc.reg_read(mips.UC_MIPS_REG_A0)
    max_size = uc.reg_read(mips.UC_MIPS_REG_A1)

    def restore(data):
        if len(data) > max_size:
            return -1

        lfu.restore(snapshot, uc=uc)

        # You may want to use instrumented malloc here for sanitizer support:
        # a0 = lfu.allocate(len(data))

        uc.reg_write(mips.UC_MIPS_REG_A1, len(data))
        uc.mem_write(target, data)

        return 0

    def handle_instr(uc, addr, size, _user_data):
        print(hex(addr), size, uc.mem_read(addr, size).hex())

    # uc.hook_add(unicorn.UC_HOOK_CODE, handle_instr)
    # uc.emu_start(START_ADDR, END_ADDR)

    lfu.start_fuzzer(fuzzArgs, restore, START_ADDR, END_ADDR)


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
