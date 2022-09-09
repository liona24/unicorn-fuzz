# unicorn-fuzz

Fuzz process snapshots with [unicorn](https://www.unicorn-engine.org/) + [libFuzzer](https://llvm.org/docs/LibFuzzer.html)

Supported architectures:
- X86 (64 Bit)
- MIPS 32 LE / BE

Why should you use this over `unicorn-afl`?
- Everything is in-process, no need for wrappers
- Custom allocator with rudimentary address sanitizer support
- (opinionated) Coverage instrumentation is better
- Just another fuzzer, may yield better results
- You may prefer libFuzzer

## Building

Tested on Fedora 36. Should work on any linux. No guarantees for any other OS.

Install build dependencies:
```
sudo dnf install cmake ninja pkg-config llvm-devel gtest-devel clang capstone-devel
```
(gtest is optional, used for tests)

(capstone is required to support additional coverage instrumentation, technically you could build without it)

Build using CMake:
```
mkdir build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
ninja
```

After that you may install the python wrapper:
```
python3 -m venv venv
source venv/bin/activate
pip install -e python-bindings/
```

## Quick Start

After following the install instructions above, try setting up one of the examples.

First you will need a process snapshot.
There is a convenience script which can be used in conjunction with GDB/GEF, but other frameworks like [qiling](https://github.com/qilingframework/qiling) should work as well.

```
gdb build/examples/basic
gdb> break *0x401150
gdb> run some_random_input_for_basic_example
...
gdb> source scripts/gdb_dump_snapshot.py
gdb> quit
```

Then run the example script within the virtual environment:
```
python3 examples/basic.py -s dump_<timestamp>.json
```
Which should quickly result in a crash like this:
```
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 2239385853
INFO: Loaded 1 modules   (4096 inline 8-bit counters): 4096 [0x5625f2a61e20, 0x5625f2a62e20),
INFO: -max_len is not provided; libFuzzer will not generate inputs larger than 4096 bytes
INFO: A corpus is not provided, starting from an empty corpus
#2      INITED ft: 3 corp: 1/1b exec/s: 0 rss: 77Mb
#26     NEW    ft: 4 corp: 2/4b lim: 4 exec/s: 0 rss: 77Mb L: 3/3 MS: 4 ChangeBinInt-InsertByte-ChangeBit-CopyPart-
[!] unicorn-fuzz/src/lfu.cpp:51 - error: Invalid memory read (UC_ERR_READ_UNMAPPED)
==29821== ERROR: libFuzzer: deadly signal
NOTE: libFuzzer has rudimentary signal handlers.
      Combine libFuzzer with AddressSanitizer or similar for better crash reports.
SUMMARY: libFuzzer: deadly signal
MS: 2 ChangeBinInt-ChangeByte-; base unit: 153a1377b2b18b6968fbb55a2fea2012f7c8d3fe
0x41,0x11,0x3e,
A\021>
artifact_prefix='./'; Test unit written to ./crash-6e28f43c93cd986a1a6bbc988b3f5795f9283027
Base64: QRE+
```

There is also a more complex example `examples/int_overflow` which will use some of the address sanitizer features as well as more coverage instrumentation.

After that you may easily set up a template for your own binary using `python3 -m lfu generate -h`
