#include "../client.hpp"

Client::Client(std::string login, const std::string &password, const KeyDistributionCenter &kdc)
            : login(std::move(login)), password(password.substr(0, 7)), keyDistributionCenter(kdc) {}

    void Client::add_to(AuthenticationServer &authenticationServer) const {
        authenticationServer.add_client_key(login, password);
    }

    bool Client::connect(const Server &server) {
        std::cout << "Client " << login << " tries to connect to the server " << server.get_name() << std::endl;
        if (serversTickets.find(server.get_name()) != end(serversTickets) &&
            !isTicketExpired(serversTickets[server.get_name()].expirationTimestamp)) {
            std::cout << "Client has a valid ServiceTicket for this server" << std::endl;
            verify_connection(server);
        } else {
            if (!tgtData.hasTicketGrantingTicket ||
                (tgtData.hasTicketGrantingTicket && isTicketExpired(tgtData.expirationTimestamp))) {
                request_tgt();
            } else {
                std::cout << "Client has a TicketGrantingTicket" << std::endl;
            }
            request_service_ticket(server.get_name());
            verify_connection(server);
        }
        return true;
    }

    void Client::request_tgt() {
        std::cout << "Client doesn't have valid ticket granting ticket" << std::endl;
        AuthenticationToken encryptedToken = generate_auth_token();
        std::cout << "Client sends encrypted authentication token to the key distribution center" << std::endl;
        AuthenticationResultToken authenticationResultToken = keyDistributionCenter.authenticate(encryptedToken);
        std::cout << "Client receives AuthenticationResultToken from key distribution center" << std::endl;
        std::cout << "Client decrypts TicketGrantingServerAddressToken with password hash" << std::endl;
        TicketGrantingServerAddressToken decryptedToken =
                authenticationResultToken.ticketGrantingServerAddressToken.decrypt(password);
        save_tgt(authenticationResultToken.ticketGrantingTicket, decryptedToken.expiration_timestamp);
        std::cout << "Client saves session_key for future use" << std::endl;
        tgtData.sessionKey = decryptedToken.session_key;
    }

    void Client::request_service_ticket(const std::string &server_name) {
        TicketGrantingServerToken ticketGrantingServerToken = generate_tgs_token(server_name);
        std::cout << "Client sends TicketGrantingServerToken to the key distribution center" << std::endl;
        TicketGrantingResultToken ticketGrantingResultToken = keyDistributionCenter.grantServiceTicket(
                ticketGrantingServerToken);
        std::cout << "Client received TicketGrantingResultToken from the key distribution center" << std::endl;
        ticketGrantingResultToken.clientResponseToken = ticketGrantingResultToken.clientResponseToken.decrypt(
                tgtData.sessionKey);
        std::cout << "Client decrypted TicketGrantingResultToken with the TGT session key" << std::endl;
        std::cout << "        TIME: " << ticketGrantingResultToken.clientResponseToken.expirationTimestamp << std::endl;
        std::cout << "         KEY: " << tgtData.sessionKey << std::endl;
        addServerData(ticketGrantingResultToken);
        std::cout << "Client cached ServiceTicket for the server: " << server_name << std::endl;
    }

    void Client::verify_connection(const Server &server) {
        ClientToken clientToken(login);
        std::cout << "Client verifies connection with server" << std::endl;
        ServerToken serverToken = server.verify(
                clientToken.encrypt(serversTickets[server.get_name()].sessionKey),
                serversTickets[server.get_name()].serviceTicket
        );
        serverToken = serverToken.decrypt(serversTickets[server.get_name()].sessionKey);
        if (serverToken.server_name == server.get_name()) {
            std::cout << "Connection verified!" << std::endl;
        } else {
            std::cout << "Error" << std::endl;
            throw std::invalid_argument("Connection not verified");
        }
    }

    [[nodiscard]] AuthenticationToken Client::generate_auth_token() const {
        AuthenticationToken authToken(login);
        std::cout << "Client generated authentication token: " << std::endl;
        std::cout << "   user_id: " << authToken.user_id << std::endl;
        return authToken;
    }

    void Client::save_tgt(TicketGrantingTicket &tgt, const std::string &expirationTimestamp) {
        tgtData.ticketGrantingTicket = tgt;
        try {
            tgtData.expirationTimestamp = boost::posix_time::time_from_string(expirationTimestamp);
        } catch (...) {
            throw std::invalid_argument("Cannot convert expirationTimestamp from string to boost::posix_time::ptime.");
        }
        tgtData.hasTicketGrantingTicket = true;
        std::cout << "Client saves TicketGrantingTicket for future use" << std::endl;
    }

    [[nodiscard]] ClientToken Client::generate_client_token() const {
        ClientToken clientToken(login);
        std::cout << "Client generates ClientToken:" << std::endl;
        std::cout << "   user_id: " << clientToken.user_id << std::endl;
        ClientToken encryptedToken = clientToken.encrypt(tgtData.sessionKey);
        std::cout << "Client encrypts ClientToken with session key" << std::endl;
        return encryptedToken;
    }

    ServerToken Client::generate_server_query_token(const std::string &server_name) {
        std::cout << "Client generates ServerToken" << std::endl;
        return ServerToken(server_name);
    }

    TicketGrantingServerToken Client::generate_tgs_token(const std::string &server_name) {
        std::cout << "Client generates TicketGrantingServerToken" << std::endl;
        return TicketGrantingServerToken(
                generate_client_token(),
                generate_server_query_token(server_name),
                tgtData.ticketGrantingTicket
        );
    }

    [[nodiscard]] bool Client::isTicketExpired(const boost::posix_time::ptime &time) const {
        return boost::posix_time::second_clock::local_time() > time;
    }

    void Client::addServerData(const TicketGrantingResultToken &tgr) {
        boost::posix_time::ptime expirationTimestamp = boost::posix_time::time_from_string(
                tgr.clientResponseToken.expirationTimestamp);
        ServerData serverData{tgr.serviceTicket, expirationTimestamp,
                              tgr.clientResponseToken.sessionKey};
        serversTickets.emplace(tgr.clientResponseToken.serverName, serverData);
    }