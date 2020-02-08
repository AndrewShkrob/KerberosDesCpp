#ifndef PROGRAM_DES_HPP
#define PROGRAM_DES_HPP

#include <cstdint>

using ui64 = uint64_t;
using ui32 = uint32_t;
using ui8 = uint8_t;

enum class DesMode {
    ENCRYPT = false,
    DECRYPT = true
};

class Des {
public:
    explicit Des(ui64 key);

    ui64 encrypt(ui64 block);

    ui64 decrypt(ui64 block);

protected:
    ui64 des(ui64 block, DesMode mode);

    void keygen(ui64 key);

    static inline ui64 ip(ui64 block);

    static inline ui64 fp(ui64 block);

    static inline void feistel(ui32 &L, ui32 &R, ui32 F);

    static inline ui32 f(ui32 R, ui64 k);

private:
    ui64 sub_key[16];
};

#endif //PROGRAM_DES_HPP
