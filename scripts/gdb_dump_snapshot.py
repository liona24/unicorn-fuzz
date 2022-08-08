import base64
import ast
import datetime
import json
import re
import zlib

import gdb


def read_register_larger_64bit(reg_name):

    # HACK: This parsers the register values for f.e. floating point
    # registers from the GDB output. If you know a better way of
    # converting numbers larger than 128 bits to python types, pls
    # let me know

    s = gdb.parse_and_eval(f"${reg_name}").format_string(raw=True)
    for i in range(1, len(s)):
        line = s[-i].strip()

        m = re.search(r"v(\d)_int(\d+) = {(.*)}", line)
        if m:
            _times = int(m.group(1))
            size = int(m.group(2))
            values = ast.literal_eval(f"({m.group(3)})")
            break
    else:
        raise ValueError("Could not parse values from " + reg_name)

    value = []
    for v in values:
        value.append(v.to_bytes(size, "little"))
    value = b"".join(value)

    return int.from_bytes(value, "little")


def get_base_addr():
    # TODO: if this is not a PIE, this should be 0
    return int(gdb.parse_and_eval(f"$_base()"))


def has_gef():
    try:
        gef
        return True
    except NameError:
        print("[!] no GEF found, memory maps will be incomplete!")
        return False


def main():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    snapshot = {}
    snapshot["time"] = timestamp

    frame = gdb.selected_frame()
    arch = frame.architecture()

    snapshot["arch"] = arch.name()
    snapshot["registers"] = {}

    for reg in arch.registers("general"):
        value = frame.read_register(reg.name)
        try:
            value = int(value)
        except ValueError:
            value = read_register_larger_64bit(reg.name)

        snapshot["registers"][reg.name] = value

    if has_gef():
        snapshot["base"] = get_base_addr()
        snapshot["maps"] = []
        snapshot["memory"] = {}
        for section in gef.memory.maps:
            tmp = {
                "start": section.page_start,
                "end": section.page_end,
                "offset": section.offset,
                "permissions": str(section.permission),
                "inode": section.inode,
                "path": section.path
            }
            snapshot["maps"].append(tmp)

            try:
                dump = gdb.selected_inferior().read_memory(section.page_start, section.page_end - section.page_start)
                compressed = base64.b64encode(zlib.compress(dump)).decode()
                snapshot["memory"][section.page_start] = compressed
            except gdb.MemoryError:
                print(f"[!] could not read section at {section.page_start:x}")

    path = f"dump_{timestamp}.json"
    with open(path, "w") as fout:
        json.dump(snapshot, fout, indent=2)

    print(f"[+] dumped snapshot to '{path}'")


if __name__ == '__main__':
    main()
