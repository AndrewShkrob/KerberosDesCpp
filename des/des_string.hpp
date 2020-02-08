#ifndef PROGRAM_DES_STRING_HPP
#define PROGRAM_DES_STRING_HPP

#include <string>
#include "des.hpp"

class DesString {
public:
    explicit DesString(const std::string &key);

    std::string encrypt(const std::string &text);

    std::string decrypt(const std::string &text);

protected:
    std::string cipher(const std::string &text, DesMode mode);

private:
    Des des;
};

#endif //PROGRAM_DES_STRING_HPP
