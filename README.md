# unicorn-fuzz

## Building

Tested on Fedora 36. Should work on any linux. No guarantees for any other OS.

Install build dependencies:
```
sudo dnf install cmake ninja pkg-config llvm-devel gtest-devel clang
```
(gtest is optional, used for tests)

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
pip install -e python-bindings
```

## Quick Start
