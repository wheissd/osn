#include "database.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>
#include <mutex>
#include <condition_variable>
#include <mutex>
#include <condition_variable>

namespace SocialNetwork {

Database::Database(const std::string& connection_string, size_t pool_size)
    : connection_string_(connection_string), pool_size_(pool_size) {
    initializePool();
    runMigrations();
}

Database::~Database() {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    // Just clear the pool and connection usage vectors,
    // unique_ptr destructors will clean up connections correctly.
    connection_pool_.clear();
    connection_in_use_.clear();
}



std::string Database::createUser(const User& user, const std::string& password) {
    if (!user.isValid()) {
        throw std::invalid_argument("Invalid user data");
    }

    if (password.empty() || password.length() < 6) {
        throw std::invalid_argument("Password must be at least 6 characters long");
    }

    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::work txn(conn);

        std::string password_hash = hashPassword(password);

        pqxx::result result = txn.exec_params(
            "INSERT INTO users (first_name, second_name, birthdate, biography, city, password_hash) "
            "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            user.getFirstName(),
            user.getSecondName(),
            user.getBirthdate(),
            user.getBiography(),
            user.getCity(),
            password_hash
        );

        if (result.empty()) {
            throw std::runtime_error("Failed to create user");
        }

        std::string user_id = result[0][0].as<std::string>();
        txn.commit();
        releaseConnection(conn);

        return user_id;
    } catch (const pqxx::sql_error& e) {
        releaseConnection(conn);
        std::cerr << "SQL error in createUser: " << e.what() << std::endl;
        throw std::runtime_error("Database error while creating user");
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in createUser: " << e.what() << std::endl;
        throw;
    }
}

std::optional<User> Database::getUser(const std::string& user_id) {
    if (user_id.empty()) {
        return std::nullopt;
    }

    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::nontransaction ntxn(conn);

        pqxx::result result = ntxn.exec_params(
            "SELECT id, first_name, second_name, birthdate, biography, city "
            "FROM users WHERE id = $1",
            user_id
        );

        releaseConnection(conn);

        if (result.empty()) {
            return std::nullopt;
        }

        const auto& row = result[0];
        User user(
            row["id"].as<std::string>(),
            row["first_name"].as<std::string>(),
            row["second_name"].as<std::string>(),
            row["birthdate"].as<std::string>(),
            row["biography"].is_null() ? "" : row["biography"].as<std::string>(),
            row["city"].as<std::string>()
        );

        return user;
    } catch (const pqxx::sql_error& e) {
        releaseConnection(conn);
        std::cerr << "SQL error in getUser: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in getUser: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::optional<std::string> Database::authenticateUser(const std::string& user_id, const std::string& password) {
    if (user_id.empty() || password.empty()) {
        return std::nullopt;
    }

    pqxx::connection& conn = acquireConnection();
    try {
        std::string stored_hash;

        // First, get the password hash in a separate transaction scope
        {
            pqxx::nontransaction ntxn(conn);

            pqxx::result result = ntxn.exec_params(
                "SELECT password_hash FROM users WHERE id = $1",
                user_id
            );

            if (result.empty()) {
                releaseConnection(conn);
                return std::nullopt;
            }

            stored_hash = result[0]["password_hash"].as<std::string>();
        }

        releaseConnection(conn);

        // Then verify password and create session if valid
        if (verifyPassword(password, stored_hash)) {
            return createSession(user_id);
        }

        return std::nullopt;
    } catch (const pqxx::sql_error& e) {
        releaseConnection(conn);
        std::cerr << "SQL error in authenticateUser: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in authenticateUser: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::vector<User> Database::searchUsers(const std::string& first_name, const std::string& last_name) {
    std::vector<User> users;

    if (first_name.empty() && last_name.empty()) {
        return users;
    }

    pqxx::connection& conn = acquireConnection();

    try {
        pqxx::nontransaction ntxn(conn);

        std::string query = "SELECT id, first_name, second_name, birthdate, biography, city "
                           "FROM users WHERE ";
        std::vector<std::string> conditions;
        std::vector<std::string> params;

        if (!first_name.empty()) {
            conditions.push_back("first_name LIKE $" + std::to_string(params.size() + 1));
            params.push_back(first_name + "%");
        }

        if (!last_name.empty()) {
            conditions.push_back("second_name LIKE $" + std::to_string(params.size() + 1));
            params.push_back(last_name + "%");
        }

        query += conditions[0];
        if (conditions.size() > 1) {
            query += " AND " + conditions[1];
        }

        query += " ORDER BY id LIMIT 100";

        pqxx::result result;
        if (params.size() == 1) {
            result = ntxn.exec_params(query, params[0]);
        } else if (params.size() == 2) {
            result = ntxn.exec_params(query, params[0], params[1]);
        }

        for (const auto& row : result) {
            User user(
                row["id"].as<std::string>(),
                row["first_name"].as<std::string>(),
                row["second_name"].as<std::string>(),
                row["birthdate"].as<std::string>(),
                row["biography"].is_null() ? "" : row["biography"].as<std::string>(),
                row["city"].as<std::string>()
            );
            users.push_back(user);
        }
    } catch (...) {
        releaseConnection(conn);
        throw;
    }

    releaseConnection(conn);
    return users;
}

std::string Database::createSession(const std::string& user_id) {
    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::work txn(conn);

        // Clean up expired sessions for this user first
        txn.exec_params(
            "DELETE FROM sessions WHERE user_id = $1 AND expires_at < CURRENT_TIMESTAMP",
            user_id
        );

        // Create new session (expires in 24 hours)
        pqxx::result result = txn.exec_params(
            "INSERT INTO sessions (user_id, expires_at) "
            "VALUES ($1, CURRENT_TIMESTAMP + INTERVAL '24 hours') RETURNING token",
            user_id
        );

        if (result.empty()) {
            releaseConnection(conn);
            throw std::runtime_error("Failed to create session");
        }

        std::string token = result[0]["token"].as<std::string>();
        txn.commit();
        releaseConnection(conn);

        return token;
    } catch (const pqxx::sql_error& e) {
        releaseConnection(conn);
        std::cerr << "SQL error in createSession: " << e.what() << std::endl;
        throw std::runtime_error("Database error while creating session");
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in createSession: " << e.what() << std::endl;
        throw;
    }
}

std::optional<std::string> Database::validateSession(const std::string& token) {
    if (token.empty()) {
        return std::nullopt;
    }

    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::nontransaction ntxn(conn);

        pqxx::result result = ntxn.exec_params(
            "SELECT user_id FROM sessions WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP",
            token
        );

        releaseConnection(conn);

        if (result.empty()) {
            return std::nullopt;
        }

        return result[0]["user_id"].as<std::string>();
    } catch (const pqxx::sql_error& e) {
        releaseConnection(conn);
        std::cerr << "SQL error in validateSession: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in validateSession: " << e.what() << std::endl;
        return std::nullopt;
    }
}

void Database::deleteSession(const std::string& token) {
    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::work txn(conn);
        txn.exec_params("DELETE FROM sessions WHERE token = $1", token);
        txn.commit();
        releaseConnection(conn);
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in deleteSession: " << e.what() << std::endl;
    }
}

void Database::cleanupExpiredSessions() {
    pqxx::connection& conn = acquireConnection();
    try {
        pqxx::work txn(conn);
        txn.exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP");
        txn.commit();
        releaseConnection(conn);
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error in cleanupExpiredSessions: " << e.what() << std::endl;
    }
}

bool Database::isConnected() const {
    // pool_mutex_ declared as mutable to allow locking in const methods.
    std::unique_lock<std::mutex> lock(const_cast<std::mutex&>(pool_mutex_));
    for (const auto& conn : connection_pool_) {
        if (!conn->is_open()) {
            return false;
        }
    }
    return true;
}



std::string Database::hashPassword(const std::string& password) {
    // Generate random salt
    unsigned char salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        throw std::runtime_error("Failed to generate random salt");
    }

    // Convert salt to hex string
    std::ostringstream salt_hex;
    for (int i = 0; i < 16; ++i) {
        salt_hex << std::hex << std::setw(2) << std::setfill('0') << (int)salt[i];
    }

    // Hash password with salt using SHA-256
    std::string salted_password = password + salt_hex.str();

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create hash context");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to initialize hash");
    }

    if (EVP_DigestUpdate(ctx, salted_password.c_str(), salted_password.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to update hash");
    }

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        throw std::runtime_error("Failed to finalize hash");
    }

    EVP_MD_CTX_free(ctx);

    // Convert hash to hex string
    std::ostringstream hash_hex;
    for (unsigned int i = 0; i < hash_len; ++i) {
        hash_hex << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }

    return salt_hex.str() + ":" + hash_hex.str();
}

bool Database::verifyPassword(const std::string& password, const std::string& hash) {
    // Split hash into salt and hash parts
    size_t colon_pos = hash.find(':');
    if (colon_pos == std::string::npos) {
        return false;
    }

    std::string salt_hex = hash.substr(0, colon_pos);
    std::string stored_hash = hash.substr(colon_pos + 1);

    // Hash the provided password with the stored salt
    std::string salted_password = password + salt_hex;

    unsigned char computed_hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        return false;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestUpdate(ctx, salted_password.c_str(), salted_password.length()) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    if (EVP_DigestFinal_ex(ctx, computed_hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return false;
    }

    EVP_MD_CTX_free(ctx);

    // Convert computed hash to hex string
    std::ostringstream computed_hash_hex;
    for (unsigned int i = 0; i < hash_len; ++i) {
        computed_hash_hex << std::hex << std::setw(2) << std::setfill('0') << (int)computed_hash[i];
    }

    return computed_hash_hex.str() == stored_hash;
}

void Database::runMigrations() {
    pqxx::connection& conn = acquireConnection();

    try {
        // Check if we need to run migrations
        if (tableExists("users")) {
            std::cout << "Database tables already exist, skipping migrations" << std::endl;
            releaseConnection(conn);
            return;
        }

        std::cout << "Running database migrations..." << std::endl;

        // Read and execute migration file
        std::ifstream migration_file("migrations/001_create_tables.sql");
        if (!migration_file.is_open()) {
            std::cerr << "Warning: Could not open migration file, assuming database is already set up" << std::endl;
            releaseConnection(conn);
            return;
        }

        std::ostringstream migration_content;
        migration_content << migration_file.rdbuf();
        migration_file.close();

        pqxx::work txn(conn);
        txn.exec(migration_content.str());
        txn.commit();

        std::cout << "Database migrations completed successfully" << std::endl;
        releaseConnection(conn);
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error running migrations: " << e.what() << std::endl;
        throw;
    }
}

bool Database::tableExists(const std::string& table_name) {
    pqxx::connection& conn = acquireConnection();

    try {
        pqxx::nontransaction ntxn(conn);
        pqxx::result result = ntxn.exec_params(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = $1)",
            table_name
        );

        releaseConnection(conn);
        return !result.empty() && result[0][0].as<bool>();
    } catch (const std::exception& e) {
        releaseConnection(conn);
        std::cerr << "Error checking if table exists: " << e.what() << std::endl;
        return false;
    }
}

pqxx::connection& Database::acquireConnection() {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    pool_cv_.wait(lock, [this] {
        for (bool in_use : connection_in_use_) {
            if (!in_use) return true;
        }
        return false;
    });

    for (size_t i = 0; i < pool_size_; ++i) {
        if (!connection_in_use_[i]) {
            connection_in_use_[i] = true;
            pqxx::connection& conn = *connection_pool_[i];

            if (!conn.is_open()) {
                // Destroy and recreate the connection instead of reconnectConnection call
                try {
                    connection_pool_[i].reset(new pqxx::connection(connection_string_));
                    if (!connection_pool_[i]->is_open()) {
                        throw std::runtime_error("Failed to reestablish database connection");
                    }
                } catch (const std::exception& e) {
                    connection_in_use_[i] = false;
                    pool_cv_.notify_one();
                    throw;
                }
                return *connection_pool_[i];
            }

            return conn;
        }
    }

    throw std::runtime_error("Failed to acquire database connection from pool");
}

void Database::releaseConnection(pqxx::connection& conn) {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    for (size_t i = 0; i < pool_size_; ++i) {
        if (connection_pool_[i].get() == &conn) {
            connection_in_use_[i] = false;
            lock.unlock();
            pool_cv_.notify_one();
            return;
        }
    }
    throw std::runtime_error("Released connection not found in pool");
}

void Database::reconnectConnection(pqxx::connection& conn) {
    // This function should not do anything now because we cannot reassign pqxx::connection objects.
    // Actual reconnection is managed by destroying and recreating unique_ptr in the pool.
    // So we leave it empty or remove calls to this method from acquireConnection.
}

void Database::initializePool() {
    std::unique_lock<std::mutex> lock(pool_mutex_);
    connection_pool_.clear();
    connection_in_use_.clear();

    for (size_t i = 0; i < pool_size_; ++i) {
        auto conn = std::make_unique<pqxx::connection>(connection_string_);
        if (!conn->is_open()) {
            throw std::runtime_error("Failed to open database connection in pool");
        }
        connection_pool_.push_back(std::move(conn));
        connection_in_use_.push_back(false);
    }
}

} // namespace SocialNetwork
