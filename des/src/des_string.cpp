#include <sstream>
#include <boost/algorithm/string/trim.hpp>
#include "../des_string.hpp"
#include "../des_data.hpp"

DesString::DesString(const std::string &key)
        : des(0) {
    assert(key.size() <= 7);
    ui64 buffer = 0;
    std::istringstream input(key);
    input.read(reinterpret_cast<char *>(&buffer), 8);
    des = Des(buffer);
}

std::string DesString::encrypt(const std::string &text) {
    return cipher(text, DesMode::ENCRYPT);
}

std::string DesString::decrypt(const std::string &text) {
    return cipher(text, DesMode::DECRYPT);
}

std::string DesString::cipher(const std::string &text, DesMode mode) {
    ui64 buffer;
    ui64 size = text.size();
    ui64 block = size / 8;
    if (mode == DesMode::DECRYPT)
        --block;
    std::istringstream input(text);
    std::ostringstream output;
    for (ui64 i = 0; i < block; ++i) {
        buffer = 0;
        input.read(reinterpret_cast<char *>(&buffer), 8);
        if (mode == DesMode::ENCRYPT)
            buffer = des.encrypt(buffer);
        else
            buffer = des.decrypt(buffer);
        output << std::string(reinterpret_cast<char *>(&buffer), 8);
    }
    if (mode == DesMode::ENCRYPT) {
        ui8 padding = 8 - (size % 8);
        if (padding == 0)
            padding = 8;
        buffer = 0;
        if (padding != 8) {
            input.read(reinterpret_cast<char *>(&buffer), 8 - padding);
            ui8 shift = padding * 8;
            buffer <<= shift;
            buffer |= LB64_MASK << (shift - 1u);
            buffer = des.encrypt(buffer);
            std::string res = std::string(reinterpret_cast<char *>(&buffer), 8);
            output << res;
        }
    } else {
        buffer = 0;
        input.read(reinterpret_cast<char *>(&buffer), 8);
        buffer = des.decrypt(buffer);
        ui8 padding = 0;
        while (!(buffer & 0x00000000000000ffu)) {
            buffer >>= 8u;
            ++padding;
        }
        buffer >>= 8u;
        ++padding;
        if (padding != 8)
            output << std::string(reinterpret_cast<char *>(&buffer), 8 - padding);
    }
    return output.str();
}