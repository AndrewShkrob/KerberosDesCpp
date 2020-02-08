#ifndef PROGRAM_KDC_HPP
#define PROGRAM_KDC_HPP

#include <string>
#include <boost/core/noncopyable.hpp>

#include "as.hpp"
#include "tgs.hpp"
#include "packages.hpp"

class KeyDistributionCenter : boost::noncopyable {
public:
    KeyDistributionCenter();

    template<class Obj>
    void insert(const Obj &obj) {
        obj.add_to(auth_server);
    }

    AuthenticationResultToken authenticate(const AuthenticationToken &authenticationToken) const;

    TicketGrantingResultToken grantServiceTicket(const TicketGrantingServerToken &ticketGrantingServerToken) const;

private:
    AuthenticationServer auth_server;
    TicketGrantingServer ticket_granting_server;
};

#endif //PROGRAM_KDC_HPP
