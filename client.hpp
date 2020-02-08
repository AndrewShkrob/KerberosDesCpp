#ifndef PROGRAM_CLIENT_HPP
#define PROGRAM_CLIENT_HPP

#include <string>
#include <boost/date_time/posix_time/ptime.hpp>
#include "kerberos/as.hpp"
#include "kerberos/kdc.hpp"
#include "server.hpp"

class Client {
public:
    explicit Client(std::string login, const std::string &password, const KeyDistributionCenter &kdc);

    void add_to(AuthenticationServer &authenticationServer) const;

    bool connect(const Server &server);

private:
    void request_tgt();

    void request_service_ticket(const std::string &server_name);

    void verify_connection(const Server &server);

    [[nodiscard]] AuthenticationToken generate_auth_token() const;

    void save_tgt(TicketGrantingTicket &tgt, const std::string &expirationTimestamp);

    [[nodiscard]] ClientToken generate_client_token() const;

    ServerToken generate_server_query_token(const std::string &server_name);

    TicketGrantingServerToken generate_tgs_token(const std::string &server_name);

    [[nodiscard]] bool isTicketExpired(const boost::posix_time::ptime &time) const;

    void addServerData(const TicketGrantingResultToken &tgr);

private:
    struct TicketGrantingTicketData {
        TicketGrantingTicket ticketGrantingTicket;
        bool hasTicketGrantingTicket = false;
        boost::posix_time::ptime expirationTimestamp;
        std::string sessionKey;
    };

    struct ServerData {
        ServiceTicket serviceTicket;
        boost::posix_time::ptime expirationTimestamp;
        std::string sessionKey;
    };

private:
    std::string login;
    std::string password;
    const KeyDistributionCenter &keyDistributionCenter;

    TicketGrantingTicketData tgtData;
    std::unordered_map<std::string, ServerData> serversTickets;
};

#endif //PROGRAM_CLIENT_HPP
