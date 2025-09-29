#include "database.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <stdexcept>

namespace SocialNetwork {

Database::Database(const std::string& connection_string)
    : connection_string_(connection_string) {
    initializeConnection();
    runMigrations();
}

void Database::initializeConnection() {
    try {
        conn_ = std::make_unique<pqxx::connection>(connection_string_);
        if (!conn_->is_open()) {
            throw std::runtime_error("Failed to open database connection");
        }
        std::cout << "Database connection established successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Database connection failed: " << e.what() << std::endl;
        throw;
    }
}

std::string Database::createUser(const User& user, const std::string& password) {
    if (!user.isValid()) {
        throw std::invalid_argument("Invalid user data");
    }

    if (password.empty() || password.length() < 6) {
        throw std::invalid_argument("Password must be at least 6 characters long");
    }

    try {
        pqxx::work txn(*conn_);

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

        return user_id;
    } catch (const pqxx::sql_error& e) {
        std::cerr << "SQL error in createUser: " << e.what() << std::endl;
        throw std::runtime_error("Database error while creating user");
    } catch (const std::exception& e) {
        std::cerr << "Error in createUser: " << e.what() << std::endl;
        throw;
    }
}

std::optional<User> Database::getUser(const std::string& user_id) {
    if (user_id.empty()) {
        return std::nullopt;
    }

    try {
        pqxx::nontransaction ntxn(*conn_);

        pqxx::result result = ntxn.exec_params(
            "SELECT id, first_name, second_name, birthdate, biography, city "
            "FROM users WHERE id = $1",
            user_id
        );

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
        std::cerr << "SQL error in getUser: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "Error in getUser: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::optional<std::string> Database::authenticateUser(const std::string& user_id, const std::string& password) {
    if (user_id.empty() || password.empty()) {
        return std::nullopt;
    }

    try {
        std::string stored_hash;

        // First, get the password hash in a separate transaction scope
        {
            pqxx::nontransaction ntxn(*conn_);

            pqxx::result result = ntxn.exec_params(
                "SELECT password_hash FROM users WHERE id = $1",
                user_id
            );

            if (result.empty()) {
                return std::nullopt;
            }

            stored_hash = result[0]["password_hash"].as<std::string>();
        }

        // Then verify password and create session if valid
        if (verifyPassword(password, stored_hash)) {
            return createSession(user_id);
        }

        return std::nullopt;
    } catch (const pqxx::sql_error& e) {
        std::cerr << "SQL error in authenticateUser: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "Error in authenticateUser: " << e.what() << std::endl;
        return std::nullopt;
    }
}

std::vector<User> Database::searchUsers(const std::string& first_name, const std::string& last_name) {
    std::vector<User> users;

    if (first_name.empty() && last_name.empty()) {
        return users;
    }

    try {
        pqxx::nontransaction ntxn(*conn_);

        std::string query = "SELECT id, first_name, second_name, birthdate, biography, city "
                           "FROM users WHERE ";
        std::vector<std::string> conditions;
        std::vector<std::string> params;

        if (!first_name.empty()) {
            conditions.push_back("first_name ILIKE $" + std::to_string(params.size() + 1));
            params.push_back(first_name + "%");
        }

        if (!last_name.empty()) {
            conditions.push_back("second_name ILIKE $" + std::to_string(params.size() + 1));
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

        return users;
    } catch (const pqxx::sql_error& e) {
        std::cerr << "SQL error in searchUsers: " << e.what() << std::endl;
        return users;
    } catch (const std::exception& e) {
        std::cerr << "Error in searchUsers: " << e.what() << std::endl;
        return users;
    }
}

std::string Database::createSession(const std::string& user_id) {
    try {
        pqxx::work txn(*conn_);

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
            throw std::runtime_error("Failed to create session");
        }

        std::string token = result[0]["token"].as<std::string>();
        txn.commit();

        return token;
    } catch (const pqxx::sql_error& e) {
        std::cerr << "SQL error in createSession: " << e.what() << std::endl;
        throw std::runtime_error("Database error while creating session");
    } catch (const std::exception& e) {
        std::cerr << "Error in createSession: " << e.what() << std::endl;
        throw;
    }
}

std::optional<std::string> Database::validateSession(const std::string& token) {
    if (token.empty()) {
        return std::nullopt;
    }

    try {
        pqxx::nontransaction ntxn(*conn_);

        pqxx::result result = ntxn.exec_params(
            "SELECT user_id FROM sessions WHERE token = $1 AND expires_at > CURRENT_TIMESTAMP",
            token
        );

        if (result.empty()) {
            return std::nullopt;
        }

        return result[0]["user_id"].as<std::string>();
    } catch (const pqxx::sql_error& e) {
        std::cerr << "SQL error in validateSession: " << e.what() << std::endl;
        return std::nullopt;
    } catch (const std::exception& e) {
        std::cerr << "Error in validateSession: " << e.what() << std::endl;
        return std::nullopt;
    }
}

void Database::deleteSession(const std::string& token) {
    try {
        pqxx::work txn(*conn_);
        txn.exec_params("DELETE FROM sessions WHERE token = $1", token);
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Error in deleteSession: " << e.what() << std::endl;
    }
}

void Database::cleanupExpiredSessions() {
    try {
        pqxx::work txn(*conn_);
        txn.exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP");
        txn.commit();
    } catch (const std::exception& e) {
        std::cerr << "Error in cleanupExpiredSessions: " << e.what() << std::endl;
    }
}

bool Database::isConnected() const {
    return conn_ && conn_->is_open();
}

void Database::reconnect() {
    try {
        conn_.reset();
        initializeConnection();
    } catch (const std::exception& e) {
        std::cerr << "Failed to reconnect to database: " << e.what() << std::endl;
        throw;
    }
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
    try {
        // Check if we need to run migrations
        if (tableExists("users")) {
            std::cout << "Database tables already exist, skipping migrations" << std::endl;
            return;
        }

        std::cout << "Running database migrations..." << std::endl;

        // Read and execute migration file
        std::ifstream migration_file("migrations/001_create_tables.sql");
        if (!migration_file.is_open()) {
            std::cerr << "Warning: Could not open migration file, assuming database is already set up" << std::endl;
            return;
        }

        std::ostringstream migration_content;
        migration_content << migration_file.rdbuf();
        migration_file.close();

        pqxx::work txn(*conn_);
        txn.exec(migration_content.str());
        txn.commit();

        std::cout << "Database migrations completed successfully" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Error running migrations: " << e.what() << std::endl;
        throw;
    }
}

bool Database::tableExists(const std::string& table_name) {
    try {
        pqxx::nontransaction ntxn(*conn_);
        pqxx::result result = ntxn.exec_params(
            "SELECT EXISTS (SELECT 1 FROM information_schema.tables "
            "WHERE table_schema = 'public' AND table_name = $1)",
            table_name
        );

        return !result.empty() && result[0][0].as<bool>();
    } catch (const std::exception& e) {
        std::cerr << "Error checking if table exists: " << e.what() << std::endl;
        return false;
    }
}

} // namespace SocialNetwork
