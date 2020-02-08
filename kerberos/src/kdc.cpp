#include "../kdc.hpp"

#include <iostream>

KeyDistributionCenter::KeyDistributionCenter() {
    ticket_granting_server.add_to(auth_server);
}

AuthenticationResultToken
KeyDistributionCenter::authenticate(const AuthenticationToken &authenticationToken) const {
    std::cout << "Key distribution center received authentication token" << std::endl;
    std::cout << "Key distribution center chose ticket granting server: " << ticket_granting_server.get_name()
              << std::endl;
    std::cout << "Key distribution center sends authentication token and "
                 "ticket granting server name to the authentication server" << std::endl;
    AuthenticationResultToken authenticationResultToken =
            auth_server.authenticate(authenticationToken, ticket_granting_server.get_name());
    std::cout << "Key distribution center returns AuthenticationResultToken to client" << std::endl;
    return authenticationResultToken;
}

TicketGrantingResultToken
KeyDistributionCenter::grantServiceTicket(const TicketGrantingServerToken &ticketGrantingServerToken) const {
    std::cout << "Key distribution center receives TicketGrantingServerToken" << std::endl;
    std::cout << "Key distribution center sends TicketGrantingServerToken and server_key "
                 "to the ticket granting server" << std::endl;
    std::string server_key = auth_server.get_server_key(ticketGrantingServerToken.serverQueryToken.server_name);
    TicketGrantingResultToken ticketGrantingResultToken =
            ticket_granting_server.grantServiceTicket(ticketGrantingServerToken, server_key);
    std::cout << "Key distribution center returns TicketGrantingResultToken to client" << std::endl;
    return ticketGrantingResultToken;
}