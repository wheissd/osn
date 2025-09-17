#pragma once

#include <crow.h>
#include <nlohmann/json.hpp>
#include <string>
#include <memory>
#include <optional>
#include "database.h"
#include "user.h"

namespace SocialNetwork {

class Server {
public:
    explicit Server(std::shared_ptr<Database> db, int port = 8080);
    ~Server() = default;

    // Disable copy constructor and assignment
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Server lifecycle
    void start();
    void stop();
    void setupRoutes();

    // Configuration
    void setPort(int port) { port_ = port; }
    int getPort() const { return port_; }

private:
    crow::SimpleApp app_;
    std::shared_ptr<Database> db_;
    int port_;

    // Route handlers
    crow::response handleLogin(const crow::request& req);
    crow::response handleRegister(const crow::request& req);
    crow::response handleGetUser(const crow::request& req, const std::string& user_id);

    // Middleware and utilities
    std::optional<std::string> extractBearerToken(const crow::request& req);
    std::optional<std::string> validateAuthToken(const std::string& token);
    crow::response createErrorResponse(int status_code, const std::string& message, 
                                     const std::string& request_id = "");
    crow::response createSuccessResponse(const nlohmann::json& data);
    std::string generateRequestId();

    // Request validation
    bool validateLoginRequest(const nlohmann::json& json);
    bool validateRegisterRequest(const nlohmann::json& json);
    bool isValidUUID(const std::string& uuid);
    bool isValidDateFormat(const std::string& date);

    // CORS handling
    void setupCORS();
    crow::response handlePreflight();

    // Logging
    void logRequest(const crow::request& req, const std::string& endpoint);
    void logResponse(const crow::response& res, const std::string& endpoint, 
                    const std::string& request_id);

    // Error handling
    void setupErrorHandlers();
    crow::response handleInternalError(const std::exception& e, const std::string& request_id);
    crow::response handleDatabaseError(const std::string& error, const std::string& request_id);

    // Request parsing helpers
    std::optional<nlohmann::json> parseJsonRequest(const crow::request& req);
    bool hasRequiredFields(const nlohmann::json& json, const std::vector<std::string>& fields);
    
    // HTTP method conversion helper
    std::string methodToString(crow::HTTPMethod method);
};

} // namespace SocialNetwork