#ifndef PROGRAM_AS_HPP
#define PROGRAM_AS_HPP

#include <unordered_map>
#include <string>
#include <boost/core/noncopyable.hpp>
#include <boost/date_time/posix_time/ptime.hpp>
#include "packages.hpp"

class AuthenticationServer : boost::noncopyable {
public:
    AuthenticationServer() = default;

    void set_tgs_key(std::string key);

    void add_client_key(std::string name, std::string key);

    void add_server_key(std::string name, std::string key);

    AuthenticationResultToken
    authenticate(const AuthenticationToken &authenticationToken, const std::string &tg_name) const;

    std::string get_server_key(const std::string &server_name) const;

private:
    TicketGrantingServerAddressToken generate_tgs_address_token(
            const std::string &session_key,
            const std::string &tg_name,
            const boost::posix_time::ptime &expiration_timestamp,
            const std::string &client_name
    ) const;

    TicketGrantingTicket generate_tgt(
            const std::string &session_key,
            const std::string &user_id,
            const boost::posix_time::ptime &expiration_timestamp
    ) const;

private:
    std::string tgs_key;
    std::unordered_map<std::string, std::string> client_keys;
    std::unordered_map<std::string, std::string> server_keys;
};

#endif //PROGRAM_AS_HPP
