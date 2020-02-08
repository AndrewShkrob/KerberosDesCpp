#include "../as.hpp"

#include <iostream>
#include "../../key_generator.hpp"

void AuthenticationServer::set_tgs_key(std::string key) {
    tgs_key = std::move(key);
}

void AuthenticationServer::add_client_key(std::string name, std::string key) {
    client_keys[std::move(name)] = std::move(key);
}

void AuthenticationServer::add_server_key(std::string name, std::string key) {
    server_keys[std::move(name)] = std::move(key);
}

AuthenticationResultToken
AuthenticationServer::authenticate(const AuthenticationToken &authenticationToken, const std::string &tg_name) const {
    std::cout << "Authentication server received auth token and TG Server name" << std::endl;
    std::cout << "Authentication server tries to decrypt auth token" << std::endl;
    std::string client_name = authenticationToken.user_id;
    std::string session_key = generate_key();
    std::cout << "Authentication server generated session key: " << session_key << std::endl;
    auto expiration_timestamp = generate_expiration_timestamp();
    std::cout << "Authentication server generated expiration timestamp: " << expiration_timestamp << std::endl;
    TicketGrantingServerAddressToken encrypted_tgs_address_token = generate_tgs_address_token(
            session_key,
            tg_name,
            expiration_timestamp,
            client_name
    );
    TicketGrantingTicket encrypted_tgt = generate_tgt(
            session_key,
            client_name,
            expiration_timestamp
    );
    std::cout << "Authentication server returns AuthenticationResultToken generated"
                 " from TicketGrantingServerAddressToken and TicketGrantingTicket" << std::endl;
    return AuthenticationResultToken(encrypted_tgs_address_token, encrypted_tgt);
}

std::string AuthenticationServer::get_server_key(const std::string &server_name) const {
    return server_keys.at(server_name);
}

TicketGrantingServerAddressToken AuthenticationServer::generate_tgs_address_token(
        const std::string &session_key,
        const std::string &tg_name,
        const boost::posix_time::ptime &expiration_timestamp,
        const std::string &client_name
) const {
    TicketGrantingServerAddressToken tgs_address_token(
            session_key,
            tg_name,
            boost::posix_time::to_simple_string(expiration_timestamp)
    );
    std::cout << "Authentication server generated TicketGrantingServerAddressToken: " << std::endl;
    std::cout << "   session_key: " << tgs_address_token.session_key << std::endl;
    std::cout << "   tgs_address: " << tgs_address_token.tgs_address << std::endl;
    std::cout << "   expiration_timestamp: " << tgs_address_token.expiration_timestamp << std::endl;
    std::cout << "Authentication server encrypts TicketGrantingServerAddressToken with client's special key"
              << std::endl;
    return tgs_address_token.encrypt(client_keys.at(client_name));
}

TicketGrantingTicket AuthenticationServer::generate_tgt(
        const std::string &session_key,
        const std::string &user_id,
        const boost::posix_time::ptime &expiration_timestamp
) const {
    TicketGrantingTicket tgt(
            session_key,
            user_id,
            boost::posix_time::to_simple_string(expiration_timestamp)
    );
    std::cout << "Authentication server generates TicketGrantingTicket: " << std::endl;
    std::cout << "   session_key: " << tgt.session_key << std::endl;
    std::cout << "   user_id: " << tgt.user_id << std::endl;
    std::cout << "   expiration_timestamp: " << tgt.expiration_timestamp << std::endl;
    std::cout << "Authentication server encrypts TicketGrantingTicket with tgs_key" << std::endl;
    return tgt.encrypt(tgs_key);
}