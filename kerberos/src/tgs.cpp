#include "../tgs.hpp"

#include <string>
#include "../../key_generator.hpp"

TicketGrantingServer::TicketGrantingServer() : name("Default TGS"), key(generate_key()) {}

TicketGrantingServer::TicketGrantingServer(TicketGrantingServer &&tgs) noexcept {
    std::swap(name, tgs.name);
    std::swap(key, tgs.key);
}

[[nodiscard]] std::string TicketGrantingServer::get_name() const {
    return name;
}

void TicketGrantingServer::add_to(AuthenticationServer &authenticationServer) const {
    authenticationServer.set_tgs_key(key);
}

[[nodiscard]] TicketGrantingResultToken
TicketGrantingServer::grantServiceTicket(const TicketGrantingServerToken &ticketGrantingServerToken,
                                         const std::string &server_key) const {
    std::cout << "Ticket granting server received all tokens" << std::endl;
    TicketGrantingTicket tgt = ticketGrantingServerToken.ticketGrantingTicket.decrypt(key);
    std::cout << "Ticket granting server decrypted TicketGrantingTicket with it's key" << std::endl;
    ClientToken clientToken = ticketGrantingServerToken.clientToken.decrypt(tgt.session_key);
    std::cout << "Ticket granting server decrypted ClientToken with session key" << std::endl;
    std::cout << "Ticket granting server compares data from TGT and ClientToken" << std::endl;
    compareData(tgt, clientToken);
    std::cout << "   Data correct" << std::endl;
    std::cout << "Ticket granting server checks whether tgt expired" << std::endl;
    if (isTGTExpired(tgt)) {
        std::cout << "   Expired!!!" << std::endl;
        throw std::runtime_error("TGT expired.");
    } else {
        std::cout << "   Ok." << std::endl;
    }
    std::string session_key = generate_key();
    std::cout << "Ticket granting server generated session key: " << session_key << std::endl;
    std::string expirationTimestamp = boost::posix_time::to_simple_string(generate_expiration_timestamp());
    ServiceTicket serviceTicket = createServiceTicket(
            session_key,
            tgt.user_id,
            expirationTimestamp,
            server_key
    );
    ClientResponseToken clientResponseToken = createClientResponseToken(
            session_key,
            ticketGrantingServerToken.serverQueryToken.server_name,
            expirationTimestamp,
            tgt.session_key
    );
    std::cout << "Ticket granting server returns Service Ticket and ClientResponse" << std::endl;
    return TicketGrantingResultToken(serviceTicket, clientResponseToken);
}

void TicketGrantingServer::compareData(const TicketGrantingTicket &tgt, const ClientToken &clientToken) const {
    if (tgt.user_id != clientToken.user_id) {
        throw std::invalid_argument("tgt.user_id != clientToken.user_id");
    }
}

[[nodiscard]] bool TicketGrantingServer::isTGTExpired(const TicketGrantingTicket &tgt) const {
    using namespace boost::posix_time;
    ptime expirationTimestamp;
    try {
        expirationTimestamp = time_from_string(tgt.expiration_timestamp);
    } catch (...) {
        throw std::invalid_argument("Cannot convert expirationTimestamp from string to boost::posix_time::ptime.");
    }
    return second_clock::local_time() > expirationTimestamp;
}

[[nodiscard]] ServiceTicket TicketGrantingServer::createServiceTicket(const std::string &sessionKey,
                                                                      const std::string &userId,
                                                                      const std::string &expirationTimestamp,
                                                                      const std::string &serverKey) const {
    ServiceTicket serviceTicket(
            sessionKey,
            userId,
            expirationTimestamp
    );
    std::cout << "Ticket granting server generated ServiceTicket: " << std::endl;
    std::cout << "   sessionKey: " << serviceTicket.sessionKey << std::endl;
    std::cout << "   serverName: " << serviceTicket.userId << std::endl;
    std::cout << "   expirationTimestamp: " << serviceTicket.expirationTimestamp << std::endl;
    std::cout << "Ticket granting server encrypts ServiceTicket with server key" << std::endl;
    return serviceTicket.encrypt(serverKey);
}

[[nodiscard]] ClientResponseToken TicketGrantingServer::createClientResponseToken(const std::string &sessionKey,
                                                                                  const std::string &serverName,
                                                                                  const std::string &expirationTimestamp,
                                                                                  const std::string &prevSessionKey) const {
    ClientResponseToken clientResponseToken(
            sessionKey,
            serverName,
            expirationTimestamp
    );
    std::cout << "Ticket granting server generated ClientResponseToken: " << std::endl;
    std::cout << "   sessionKey: " << clientResponseToken.sessionKey << std::endl;
    std::cout << "   serverName: " << clientResponseToken.serverName << std::endl;
    std::cout << "   expirationTimestamp: " << clientResponseToken.expirationTimestamp << std::endl;
    std::cout << "Ticket granting server encrypts ClientResponseToken with client's session key" << std::endl;
    return clientResponseToken.encrypt(prevSessionKey);
}