#ifndef PROGRAM_SERVER_HPP
#define PROGRAM_SERVER_HPP

#include <string>
#include "key_generator.hpp"
#include "kerberos/as.hpp"

class Server {
public:
    explicit Server(std::string name);

    void add_to(AuthenticationServer &authenticationServer) const;

    [[nodiscard]] const std::string &get_name() const;

    [[nodiscard]] ServerToken verify(ClientToken clientToken, ServiceTicket serviceTicket) const;

private:
    std::string name;
    std::string key;
};

#endif //PROGRAM_SERVER_HPP
