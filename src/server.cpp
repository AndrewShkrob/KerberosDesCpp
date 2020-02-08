#include "../server.hpp"
#include <string>

Server::Server(std::string name) : name(std::move(name)), key(generate_key()) {}

void Server::add_to(AuthenticationServer &authenticationServer) const {
    authenticationServer.add_server_key(name, key);
}

[[nodiscard]] const std::string &Server::get_name() const {
    return name;
}

[[nodiscard]] ServerToken Server::verify(ClientToken clientToken, ServiceTicket serviceTicket) const {
    std::cout << "Server verifies that client is correct" << std::endl;
    std::cout << "Server decrypts ServiceTicket with server key" << std::endl;
    serviceTicket = serviceTicket.decrypt(key);
    std::cout << "Server decrypts ClientToken with session key" << std::endl;
    clientToken = clientToken.decrypt(serviceTicket.sessionKey);
    std::cout << "Server checks whether ticket is expired" << std::endl;
    if (boost::posix_time::time_from_string(serviceTicket.expirationTimestamp) <
        boost::posix_time::second_clock::local_time()) {
        std::cout << "   Expired!!!" << std::endl;
        throw std::invalid_argument("Service ticket expired");
    } else {
        std::cout << "   Ok" << std::endl;
    }
    std::cout << "Server compares data from client and service ticket" << std::endl;
    if (clientToken.user_id != serviceTicket.userId) {
        std::cout << "   Incorrect data!!!" << std::endl;
        throw std::invalid_argument("clientToken.user_id != serviceTicket.userId");
    } else {
        std::cout << "   Ok" << std::endl;
    }
    std::cout << "Server sends server token to verify server on client side" << std::endl;
    return ServerToken(name).encrypt(serviceTicket.sessionKey);
}