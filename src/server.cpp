#include "server.h"
#include <regex>
#include <random>
#include <sstream>
#include <iostream>
#include <chrono>
#include <iomanip>

namespace SocialNetwork {

Server::Server(std::shared_ptr<Database> db, int port) 
    : db_(db), port_(port) {
    if (!db_) {
        throw std::invalid_argument("Database pointer cannot be null");
    }
    setupRoutes();
    setupCORS();
    setupErrorHandlers();
}

void Server::start() {
    std::cout << "Starting server on port " << port_ << "..." << std::endl;
    app_.port(port_).multithreaded().run();
}

void Server::stop() {
    app_.stop();
}

void Server::setupRoutes() {
    // Health check endpoint
    CROW_ROUTE(app_, "/health").methods("GET"_method)
    ([this](const crow::request& req) {
        logRequest(req, "/health");
        nlohmann::json response;
        response["status"] = "ok";
        response["timestamp"] = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();
        return createSuccessResponse(response);
    });

    // Login endpoint
    CROW_ROUTE(app_, "/login").methods("POST"_method)
    ([this](const crow::request& req) {
        logRequest(req, "/login");
        return handleLogin(req);
    });

    // User registration endpoint
    CROW_ROUTE(app_, "/user/register").methods("POST"_method)
    ([this](const crow::request& req) {
        logRequest(req, "/user/register");
        return handleRegister(req);
    });

    // Get user by ID endpoint
    CROW_ROUTE(app_, "/user/get/<string>").methods("GET"_method)
    ([this](const crow::request& req, const std::string& user_id) {
        logRequest(req, "/user/get/" + user_id);
        return handleGetUser(req, user_id);
    });

    // CORS preflight handler
    CROW_ROUTE(app_, "/<path>").methods("OPTIONS"_method)
    ([this](const crow::request& /* req */, const std::string& /* path */) {
        return handlePreflight();
    });
}

crow::response Server::handleLogin(const crow::request& req) {
    std::string request_id = generateRequestId();
    
    try {
        auto json_opt = parseJsonRequest(req);
        if (!json_opt) {
            return createErrorResponse(400, "Invalid JSON format", request_id);
        }
        
        nlohmann::json json = *json_opt;
        
        if (!validateLoginRequest(json)) {
            return createErrorResponse(400, "Missing required fields: id, password", request_id);
        }
        
        std::string user_id = json["id"].get<std::string>();
        std::string password = json["password"].get<std::string>();
        
        if (!isValidUUID(user_id)) {
            return createErrorResponse(400, "Invalid user ID format", request_id);
        }
        
        if (password.empty()) {
            return createErrorResponse(400, "Password cannot be empty", request_id);
        }
        
        auto token_opt = db_->authenticateUser(user_id, password);
        if (!token_opt) {
            return createErrorResponse(404, "User not found or invalid credentials", request_id);
        }
        
        nlohmann::json response;
        response["token"] = *token_opt;
        
        auto crow_response = createSuccessResponse(response);
        logResponse(crow_response, "/login", request_id);
        return crow_response;
        
    } catch (const std::exception& e) {
        return handleInternalError(e, request_id);
    }
}

crow::response Server::handleRegister(const crow::request& req) {
    std::string request_id = generateRequestId();
    
    try {
        auto json_opt = parseJsonRequest(req);
        if (!json_opt) {
            return createErrorResponse(400, "Invalid JSON format", request_id);
        }
        
        nlohmann::json json = *json_opt;
        
        if (!validateRegisterRequest(json)) {
            return createErrorResponse(400, "Missing required fields", request_id);
        }
        
        // Validate birthdate format
        std::string birthdate = json["birthdate"].get<std::string>();
        if (!isValidDateFormat(birthdate)) {
            return createErrorResponse(400, "Invalid birthdate format. Use YYYY-MM-DD", request_id);
        }
        
        User user = User::fromJson(json);
        
        if (!user.isValid()) {
            auto errors = user.getValidationErrors();
            std::string error_message = "Validation errors: ";
            for (size_t i = 0; i < errors.size(); ++i) {
                if (i > 0) error_message += "; ";
                error_message += errors[i];
            }
            return createErrorResponse(400, error_message, request_id);
        }
        
        std::string password = json["password"].get<std::string>();
        if (password.length() < 6) {
            return createErrorResponse(400, "Password must be at least 6 characters long", request_id);
        }
        
        std::string user_id = db_->createUser(user, password);
        
        nlohmann::json response;
        response["user_id"] = user_id;
        
        auto crow_response = createSuccessResponse(response);
        logResponse(crow_response, "/user/register", request_id);
        return crow_response;
        
    } catch (const std::invalid_argument& e) {
        return createErrorResponse(400, e.what(), request_id);
    } catch (const std::exception& e) {
        return handleInternalError(e, request_id);
    }
}

crow::response Server::handleGetUser(const crow::request& /* req */, const std::string& user_id) {
    std::string request_id = generateRequestId();
    
    try {
        if (!isValidUUID(user_id)) {
            return createErrorResponse(400, "Invalid user ID format", request_id);
        }
        
        auto user_opt = db_->getUser(user_id);
        if (!user_opt) {
            return createErrorResponse(404, "User not found", request_id);
        }
        
        nlohmann::json response = user_opt->toJson();
        
        auto crow_response = createSuccessResponse(response);
        logResponse(crow_response, "/user/get/" + user_id, request_id);
        return crow_response;
        
    } catch (const std::exception& e) {
        return handleInternalError(e, request_id);
    }
}

std::optional<std::string> Server::extractBearerToken(const crow::request& req) {
    auto auth_header = req.get_header_value("Authorization");
    if (auth_header.empty()) {
        return std::nullopt;
    }
    
    const std::string bearer_prefix = "Bearer ";
    if (auth_header.substr(0, bearer_prefix.length()) != bearer_prefix) {
        return std::nullopt;
    }
    
    std::string token = auth_header.substr(bearer_prefix.length());
    if (token.empty()) {
        return std::nullopt;
    }
    
    return token;
}

std::optional<std::string> Server::validateAuthToken(const std::string& token) {
    if (token.empty() || !isValidUUID(token)) {
        return std::nullopt;
    }
    
    return db_->validateSession(token);
}

crow::response Server::createErrorResponse(int status_code, const std::string& message, 
                                         const std::string& request_id) {
    nlohmann::json error_json;
    error_json["message"] = message;
    if (!request_id.empty()) {
        error_json["request_id"] = request_id;
    }
    error_json["code"] = status_code;
    
    crow::response response(status_code);
    response.set_header("Content-Type", "application/json");
    response.set_header("Access-Control-Allow-Origin", "*");
    response.write(error_json.dump());
    return response;
}

crow::response Server::createSuccessResponse(const nlohmann::json& data) {
    crow::response response(200);
    response.set_header("Content-Type", "application/json");
    response.set_header("Access-Control-Allow-Origin", "*");
    response.write(data.dump());
    return response;
}

std::string Server::generateRequestId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for (int i = 0; i < 8; ++i) {
        if (i == 4) ss << "-";
        ss << std::hex << dis(gen);
    }
    
    return ss.str();
}

bool Server::validateLoginRequest(const nlohmann::json& json) {
    return hasRequiredFields(json, {"id", "password"});
}

bool Server::validateRegisterRequest(const nlohmann::json& json) {
    return hasRequiredFields(json, {"first_name", "second_name", "birthdate", "city", "password"});
}

bool Server::isValidUUID(const std::string& uuid) {
    std::regex uuid_regex(
        "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    );
    return std::regex_match(uuid, uuid_regex);
}

bool Server::isValidDateFormat(const std::string& date) {
    std::regex date_regex("^\\d{4}-\\d{2}-\\d{2}$");
    return std::regex_match(date, date_regex);
}

void Server::setupCORS() {
    // CORS middleware is handled in individual route responses
}

crow::response Server::handlePreflight() {
    crow::response response(200);
    response.set_header("Access-Control-Allow-Origin", "*");
    response.set_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
    response.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
    response.set_header("Access-Control-Max-Age", "3600");
    return response;
}

std::string Server::methodToString(crow::HTTPMethod method) {
    switch (method) {
        case crow::HTTPMethod::Get: return "GET";
        case crow::HTTPMethod::Post: return "POST";
        case crow::HTTPMethod::Put: return "PUT";
        case crow::HTTPMethod::Delete: return "DELETE";
        case crow::HTTPMethod::Head: return "HEAD";
        case crow::HTTPMethod::Options: return "OPTIONS";
        case crow::HTTPMethod::Patch: return "PATCH";
        default: return "UNKNOWN";
    }
}

void Server::logRequest(const crow::request& req, const std::string& endpoint) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
              << methodToString(req.method) << " " << endpoint 
              << " from " << req.remote_ip_address << std::endl;
}

void Server::logResponse(const crow::response& res, const std::string& endpoint, 
                        const std::string& request_id) {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    std::cout << "[" << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << "] "
              << "Response " << res.code << " for " << endpoint;
    if (!request_id.empty()) {
        std::cout << " (request_id: " << request_id << ")";
    }
    std::cout << std::endl;
}

void Server::setupErrorHandlers() {
    // Error handlers are implemented in individual route handlers
}

crow::response Server::handleInternalError(const std::exception& e, const std::string& request_id) {
    std::cerr << "Internal error: " << e.what();
    if (!request_id.empty()) {
        std::cerr << " (request_id: " << request_id << ")";
    }
    std::cerr << std::endl;
    
    return createErrorResponse(500, "Internal server error", request_id);
}

crow::response Server::handleDatabaseError(const std::string& error, const std::string& request_id) {
    std::cerr << "Database error: " << error;
    if (!request_id.empty()) {
        std::cerr << " (request_id: " << request_id << ")";
    }
    std::cerr << std::endl;
    
    return createErrorResponse(503, "Service temporarily unavailable", request_id);
}

std::optional<nlohmann::json> Server::parseJsonRequest(const crow::request& req) {
    try {
        if (req.body.empty()) {
            return std::nullopt;
        }
        
        return nlohmann::json::parse(req.body);
    } catch (const nlohmann::json::exception& e) {
        std::cerr << "JSON parse error: " << e.what() << std::endl;
        return std::nullopt;
    }
}

bool Server::hasRequiredFields(const nlohmann::json& json, const std::vector<std::string>& fields) {
    for (const auto& field : fields) {
        if (!json.contains(field) || json[field].is_null()) {
            return false;
        }
        if (json[field].is_string() && json[field].get<std::string>().empty()) {
            return false;
        }
    }
    return true;
}

} // namespace SocialNetwork