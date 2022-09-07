#!/usr/bin/bash

set -e

OWNER="$1"
OUT_DIR="$2/mips"
echo "Placing files to $OUT_DIR .."

mipsel-linux-gnu-gcc-10 basic.c -Wl,-z,relro -Wl,-z,now -static -o basic
mipsel-linux-gnu-gcc-10 int_overflow.c -Wl,-z,relro -Wl,-z,now -static -o int_overflow

mkdir $OUT_DIR
cp basic int_overflow $OUT_DIR

qemu-mipsel-static -L /usr/mipsel-linux-gnu/ -g 1234 basic some_random_input_for_basic &
gdb-multiarch -x dump.gdb basic

mv dump_*.json "$OUT_DIR/dump_basic.json"

dd if=/dev/random of=random_input bs=1 count=100
qemu-mipsel-static -L /usr/mipsel-linux-gnu/ -g 1234 int_overflow random_input &
gdb-multiarch -x dump.gdb int_overflow

mv dump_*.json "$OUT_DIR/dump_int_overflow.json"

chown -R $OWNER $OUT_DIR
