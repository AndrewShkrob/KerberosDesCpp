#ifndef PROGRAM_TGS_HPP
#define PROGRAM_TGS_HPP

#include <string>
#include <boost/core/noncopyable.hpp>
#include "as.hpp"

class TicketGrantingServer : boost::noncopyable {
public:
    explicit TicketGrantingServer();

    TicketGrantingServer(TicketGrantingServer &&tgs) noexcept;

    [[nodiscard]] std::string get_name() const;

    void add_to(AuthenticationServer &authenticationServer) const;

    [[nodiscard]] TicketGrantingResultToken
    grantServiceTicket(const TicketGrantingServerToken &ticketGrantingServerToken,
                       const std::string &server_key) const;

private:
    void compareData(const TicketGrantingTicket &tgt, const ClientToken &clientToken) const;

    [[nodiscard]] bool isTGTExpired(const TicketGrantingTicket &tgt) const;

    [[nodiscard]] ServiceTicket createServiceTicket(const std::string &sessionKey,
                                                    const std::string &userId,
                                                    const std::string &expirationTimestamp,
                                                    const std::string &serverKey) const;

    [[nodiscard]] ClientResponseToken createClientResponseToken(const std::string &sessionKey,
                                                                const std::string &serverName,
                                                                const std::string &expirationTimestamp,
                                                                const std::string &prevSessionKey) const;

private:
    std::string name;
    std::string key;
};

#endif //PROGRAM_TGS_HPP
