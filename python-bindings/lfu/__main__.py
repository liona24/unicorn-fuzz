
TEMPLATE = """
import json

import lfu
import unicorn

# TODO: Change this
START_ADDR = 0x400000
END_ADDR = 0x401000

def do_fuzzing(snapshot: dict, fuzzArgs: list[str]):
    uc = lfu.restore(snapshot)

    def restore(data):
        lfu.restore(snapshot, uc=uc)

        # TODO: place data to fuzz into emulation context

        return 0

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

"""

def generate(args):
    output = args.output

    if output == "-":
        print(TEMPLATE)
    else:
        with open(output, "w") as fout:
            fout.write(TEMPLATE)


def main():
    import argparse
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(required=True)
    gen = sub.add_parser("generate", help="Generate a template to use for fuzzing")
    gen.add_argument("-o", "--output", default="-")
    gen.set_defaults(main=generate)

    args = parser.parse_args()

    args.main(args)


if __name__ == '__main__':
    main()
