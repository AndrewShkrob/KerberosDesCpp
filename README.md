# Implementation of Kerberos Protocol with DES encryption

This repo consists of simple demonstration how does the Kerberos works.

How to run:
```
cd Program/
cmake .
make -j 4
./Program
```

---
Dependencies you will need to build this project:
- Boost.Date_Time
- C++20
- CMake 3.16

## DES algorithm was taken from this repo: https://github.com/fffaraz/cppDES. It was modified to work with strings