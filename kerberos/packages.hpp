#ifndef PROGRAM_PACKAGES_HPP
#define PROGRAM_PACKAGES_HPP

#include <string>
#include <utility>
#include "../des/des_string.hpp"

template<class Package>
struct BasicToken {
    [[nodiscard]] virtual Package encrypt(const std::string &key) const = 0;

    [[nodiscard]] virtual Package decrypt(const std::string &key) const = 0;
};

struct AuthenticationToken : public BasicToken<AuthenticationToken> {
    explicit AuthenticationToken(
            std::string user_id
    ) : user_id(std::move(user_id)) {}

    [[nodiscard]] AuthenticationToken encrypt(const std::string &key) const override {
        return *this;
    }

    [[nodiscard]] AuthenticationToken decrypt(const std::string &key) const override {
        return *this;
    }

    std::string user_id;
};

struct TicketGrantingServerAddressToken : public BasicToken<TicketGrantingServerAddressToken> {
    explicit TicketGrantingServerAddressToken(
            std::string session_key,
            std::string tgs_address,
            std::string expiration_timestamp
    ) : session_key(std::move(session_key)),
        tgs_address(std::move(tgs_address)),
        expiration_timestamp(std::move(expiration_timestamp)) {}

    [[nodiscard]] TicketGrantingServerAddressToken encrypt(const std::string &key) const override {
        TicketGrantingServerAddressToken new_token = *this;
        DesString des(key);
        new_token.session_key = des.encrypt(new_token.session_key);
        new_token.tgs_address = des.encrypt(new_token.tgs_address);
        new_token.expiration_timestamp = des.encrypt(new_token.expiration_timestamp);
        return new_token;
    }

    [[nodiscard]] TicketGrantingServerAddressToken decrypt(const std::string &key) const override {
        TicketGrantingServerAddressToken new_token = *this;
        DesString des(key);
        new_token.session_key = des.decrypt(new_token.session_key);
        new_token.tgs_address = des.decrypt(new_token.tgs_address);
        new_token.expiration_timestamp = des.decrypt(new_token.expiration_timestamp);
        return new_token;
    }

    std::string session_key;
    std::string tgs_address;
    std::string expiration_timestamp;
};

struct TicketGrantingTicket : public BasicToken<TicketGrantingTicket> {
    explicit TicketGrantingTicket() = default;

    explicit TicketGrantingTicket(
            std::string session_key,
            std::string user_id,
            std::string expiration_timestamp
    ) : session_key(std::move(session_key)),
        user_id(std::move(user_id)),
        expiration_timestamp(std::move(expiration_timestamp)) {}

    [[nodiscard]] TicketGrantingTicket encrypt(const std::string &key) const override {
        TicketGrantingTicket new_token = *this;
        DesString des(key);
        new_token.session_key = des.encrypt(new_token.session_key);
        new_token.user_id = des.encrypt(new_token.user_id);
        new_token.expiration_timestamp = des.encrypt(new_token.expiration_timestamp);
        return new_token;
    }

    [[nodiscard]] TicketGrantingTicket decrypt(const std::string &key) const override {
        TicketGrantingTicket new_token = *this;
        DesString des(key);
        new_token.session_key = des.decrypt(new_token.session_key);
        new_token.user_id = des.decrypt(new_token.user_id);
        new_token.expiration_timestamp = des.decrypt(new_token.expiration_timestamp);
        return new_token;
    }

    std::string session_key;
    std::string user_id;
    std::string expiration_timestamp;
};

struct AuthenticationResultToken : public BasicToken<AuthenticationResultToken> {
    explicit AuthenticationResultToken(
            TicketGrantingServerAddressToken ticketGrantingServerAddressToken,
            TicketGrantingTicket ticketGrantingTicket
    ) : ticketGrantingServerAddressToken(std::move(ticketGrantingServerAddressToken)),
        ticketGrantingTicket(std::move(ticketGrantingTicket)) {}

    [[nodiscard]] AuthenticationResultToken encrypt(const std::string &key) const override {
        return *this;
    }

    [[nodiscard]] AuthenticationResultToken decrypt(const std::string &key) const override {
        return *this;
    }

    TicketGrantingServerAddressToken ticketGrantingServerAddressToken;
    TicketGrantingTicket ticketGrantingTicket;
};

struct ClientToken : public BasicToken<ClientToken> {
    explicit ClientToken(
            std::string user_id
    ) : user_id(std::move(user_id)) {}

    [[nodiscard]] ClientToken encrypt(const std::string &key) const override {
        ClientToken new_token = *this;
        DesString des(key);
        new_token.user_id = des.encrypt(new_token.user_id);
        return new_token;
    }

    [[nodiscard]] ClientToken decrypt(const std::string &key) const override {
        ClientToken new_token = *this;
        DesString des(key);
        new_token.user_id = des.decrypt(new_token.user_id);
        return new_token;
    }

    std::string user_id;
};

struct ServerToken : public BasicToken<ServerToken> {
    explicit ServerToken(std::string server_name) : server_name(std::move(server_name)) {}

    [[nodiscard]] ServerToken encrypt(const std::string &key) const override {
        return *this;
    }

    [[nodiscard]] ServerToken decrypt(const std::string &key) const override {
        return *this;
    }

    std::string server_name;
};

struct TicketGrantingServerToken : public BasicToken<TicketGrantingServerToken> {
    explicit TicketGrantingServerToken(
            ClientToken clientToken,
            ServerToken serverQueryToken,
            TicketGrantingTicket ticketGrantingTicket
    ) : clientToken(std::move(clientToken)),
        serverQueryToken(std::move(serverQueryToken)),
        ticketGrantingTicket(std::move(ticketGrantingTicket)) {}

    [[nodiscard]] TicketGrantingServerToken encrypt(const std::string &key) const override {
        return *this;
    }

    [[nodiscard]] TicketGrantingServerToken decrypt(const std::string &key) const override {
        return *this;
    }

    ClientToken clientToken;
    ServerToken serverQueryToken;
    TicketGrantingTicket ticketGrantingTicket;
};

struct ServiceTicket : public BasicToken<ServiceTicket> {
    ServiceTicket() = default;

    explicit ServiceTicket(
            std::string sessionKey,
            std::string userId,
            std::string expirationTimestamp
    ) : sessionKey(std::move(sessionKey)),
        userId(std::move(userId)),
        expirationTimestamp(std::move(expirationTimestamp)) {}

    [[nodiscard]] ServiceTicket encrypt(const std::string &key) const override {
        ServiceTicket new_token = *this;
        DesString des(key);
        new_token.sessionKey = des.encrypt(new_token.sessionKey);
        new_token.userId = des.encrypt(new_token.userId);
        new_token.expirationTimestamp = des.encrypt(new_token.expirationTimestamp);
        return new_token;
    }

    [[nodiscard]] ServiceTicket decrypt(const std::string &key) const override {
        ServiceTicket new_token = *this;
        DesString des(key);
        new_token.sessionKey = des.decrypt(new_token.sessionKey);
        new_token.userId = des.decrypt(new_token.userId);
        new_token.expirationTimestamp = des.decrypt(new_token.expirationTimestamp);
        return new_token;
    }

    std::string sessionKey;
    std::string userId;
    std::string expirationTimestamp;
};

struct ClientResponseToken : public BasicToken<ClientResponseToken> {
    explicit ClientResponseToken(
            std::string sessionKey,
            std::string serverName,
            std::string expirationTimestamp
    ) : sessionKey(std::move(sessionKey)),
        serverName(std::move(serverName)),
        expirationTimestamp(std::move(expirationTimestamp)) {}

    [[nodiscard]] ClientResponseToken encrypt(const std::string &key) const override {
        ClientResponseToken new_token = *this;
        DesString des(key);
        new_token.sessionKey = des.encrypt(new_token.sessionKey);
        new_token.serverName = des.encrypt(new_token.serverName);
        new_token.expirationTimestamp = des.encrypt(new_token.expirationTimestamp);
        return new_token;
    }

    [[nodiscard]] ClientResponseToken decrypt(const std::string &key) const override {
        ClientResponseToken new_token = *this;
        DesString des(key);
        new_token.sessionKey = des.decrypt(new_token.sessionKey);
        new_token.serverName = des.decrypt(new_token.serverName);
        new_token.expirationTimestamp = des.decrypt(new_token.expirationTimestamp);
        return new_token;
    }

    std::string sessionKey;
    std::string serverName;
    std::string expirationTimestamp;
};

struct TicketGrantingResultToken : public BasicToken<TicketGrantingResultToken> {
    explicit TicketGrantingResultToken(
            ServiceTicket serviceTicket,
            ClientResponseToken clientResponseToken
    ) : serviceTicket(std::move(serviceTicket)),
        clientResponseToken(std::move(clientResponseToken)) {}

    [[nodiscard]] TicketGrantingResultToken encrypt(const std::string &key) const override {
        return *this;
    }

    [[nodiscard]] TicketGrantingResultToken decrypt(const std::string &key) const override {
        return *this;
    }

    ServiceTicket serviceTicket;
    ClientResponseToken clientResponseToken;
};

#endif //PROGRAM_PACKAGES_HPP
