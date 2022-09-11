import base64
import json

import lfu
import unicorn
import unicorn.arm_const as arm


START_ADDR = 0x00010644
END_ADDR = 0x000107e0

PUTS = 0x0001de5c
PRINTF = 0x00017a50
MALLOC = 0x0002d328
FREE = 0x0002d9e8


def do_fuzzing(snapshot: dict, fuzzArgs: list[str]):
    uc = lfu.restore(snapshot)

    lfu.replace_allocator(MALLOC, FREE, 0x10000)

    lfu.add_patch(PRINTF, b"\x1e\xff\x2f\xe1", "printf")
    lfu.add_patch(PUTS, b"\x1e\xff\x2f\xe1", "puts")

    target = uc.reg_read(arm.UC_ARM_REG_R0)
    max_size = uc.reg_read(arm.UC_ARM_REG_R1)

    def restore(data):
        if len(data) > max_size:
            return -1

        lfu.restore(snapshot, uc=uc)

        # FIXME: vmmap for gef does not seem to work properly for ARM, we are missing a map here
        # You may want to use instrumented malloc here for sanitizer support:
        # target = lfu.allocate(len(data))

        uc.reg_write(arm.UC_ARM_REG_R1, len(data))
        # uc.reg_write(arm.UC_ARM_REG_R0, target)
        uc.mem_write(target, data)

        return 0

    def handle_instr(uc, addr, size, _user_data):
        print(hex(addr), size, uc.mem_read(addr, size).hex())

    # restore(b"a" * 32)
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
