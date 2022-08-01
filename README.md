# unicorn-fuzz

## Building

Install build dependencies:
```
sudo dnf install cmake ninja pkg-config clang
```

Build using CMake:
```
mkdir build
cd build
cmake -GNinja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
ninja
```
