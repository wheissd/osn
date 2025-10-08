#pragma once

#include <pqxx/pqxx>
#include <string>
#include <optional>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include "user.h"

namespace SocialNetwork {

class Database {
public:
    explicit Database(const std::string& connection_string, size_t pool_size = 10);
    ~Database();

    // Disable copy constructor and assignment
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // User operations
    std::string createUser(const User& user, const std::string& password);
    std::optional<User> getUser(const std::string& user_id);
    std::optional<std::string> authenticateUser(const std::string& user_id, const std::string& password);
    std::vector<User> searchUsers(const std::string& first_name, const std::string& last_name);

    // Session operations
    std::string createSession(const std::string& user_id);
    std::optional<std::string> validateSession(const std::string& token);
    void deleteSession(const std::string& token);
    void cleanupExpiredSessions();

    // Connection management
    bool isConnected() const;

private:
    std::string connection_string_;

    // Pool of connections
    size_t pool_size_;
    std::vector<std::unique_ptr<pqxx::connection>> connection_pool_;
    std::vector<bool> connection_in_use_;
    std::mutex pool_mutex_;
    std::condition_variable pool_cv_;

    // Helper methods
    pqxx::connection& acquireConnection();
    void releaseConnection(pqxx::connection& conn);

    std::string hashPassword(const std::string& password);
    bool verifyPassword(const std::string& password, const std::string& hash);
    void runMigrations();
    bool tableExists(const std::string& table_name);

    void initializePool();
    void reconnectConnection(pqxx::connection& conn);
};

} // namespace SocialNetwork