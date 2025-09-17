#include <iostream>
#include <memory>
#include <string>
#include <cstdlib>
#include <signal.h>
#include <thread>
#include <chrono>
#include "server.h"
#include "database.h"

using namespace SocialNetwork;

// Global server instance for signal handling
std::unique_ptr<Server> g_server;

void signalHandler(int signal) {
    std::cout << "\nReceived signal " << signal << ", shutting down gracefully..." << std::endl;
    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

void printUsage(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --port <port>        Server port (default: 8080)\n";
    std::cout << "  --db-host <host>     Database host (default: localhost)\n";
    std::cout << "  --db-port <port>     Database port (default: 5432)\n";
    std::cout << "  --db-name <name>     Database name (default: socialnetwork)\n";
    std::cout << "  --db-user <user>     Database user (default: postgres)\n";
    std::cout << "  --db-password <pwd>  Database password\n";
    std::cout << "  --help, -h           Show this help message\n\n";
    std::cout << "Environment variables:\n";
    std::cout << "  DB_HOST              Database host\n";
    std::cout << "  DB_PORT              Database port\n";
    std::cout << "  DB_NAME              Database name\n";
    std::cout << "  DB_USER              Database user\n";
    std::cout << "  DB_PASSWORD          Database password\n";
    std::cout << "  SERVER_PORT          Server port\n";
}

std::string getEnvVar(const std::string& name, const std::string& default_value = "") {
    const char* value = std::getenv(name.c_str());
    return value ? std::string(value) : default_value;
}

struct Config {
    int server_port = 8080;
    std::string db_host = "localhost";
    int db_port = 5432;
    std::string db_name = "socialnetwork";
    std::string db_user = "postgres";
    std::string db_password = "";
};

Config parseConfig(int argc, char* argv[]) {
    Config config;

    // Read from environment variables first
    config.server_port = std::stoi(getEnvVar("SERVER_PORT", "8080"));
    config.db_host = getEnvVar("DB_HOST", "localhost");
    config.db_port = std::stoi(getEnvVar("DB_PORT", "5432"));
    config.db_name = getEnvVar("DB_NAME", "socialnetwork");
    config.db_user = getEnvVar("DB_USER", "postgres");
    config.db_password = getEnvVar("DB_PASSWORD");

    // Parse command line arguments (override environment variables)
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            exit(0);
        } else if (arg == "--port" && i + 1 < argc) {
            config.server_port = std::stoi(argv[++i]);
        } else if (arg == "--db-host" && i + 1 < argc) {
            config.db_host = argv[++i];
        } else if (arg == "--db-port" && i + 1 < argc) {
            config.db_port = std::stoi(argv[++i]);
        } else if (arg == "--db-name" && i + 1 < argc) {
            config.db_name = argv[++i];
        } else if (arg == "--db-user" && i + 1 < argc) {
            config.db_user = argv[++i];
        } else if (arg == "--db-password" && i + 1 < argc) {
            config.db_password = argv[++i];
        } else {
            std::cerr << "Unknown argument: " << arg << std::endl;
            printUsage(argv[0]);
            exit(1);
        }
    }

    return config;
}

std::string buildConnectionString(const Config& config) {
    std::ostringstream oss;
    oss << "host=" << config.db_host
        << " port=" << config.db_port
        << " dbname=" << config.db_name
        << " user=" << config.db_user;

    if (!config.db_password.empty()) {
        oss << " password=" << config.db_password;
    }

    // Additional connection parameters for better reliability
    oss << " connect_timeout=10"
        << " application_name=social_network"
        << " client_encoding=UTF8";

    return oss.str();
}

void waitForDatabase(const std::string& connection_string, int max_retries = 30, int delay_seconds = 2) {
    std::cout << "Waiting for database to be ready..." << std::endl;

    for (int attempt = 1; attempt <= max_retries; ++attempt) {
        try {
            pqxx::connection test_conn(connection_string);
            if (test_conn.is_open()) {
                std::cout << "Database connection established successfully" << std::endl;
                return;
            }
        } catch (const std::exception& e) {
            std::cout << "Attempt " << attempt << "/" << max_retries
                      << " - Database not ready: " << e.what() << std::endl;

            if (attempt < max_retries) {
                std::this_thread::sleep_for(std::chrono::seconds(delay_seconds));
            }
        }
    }

    throw std::runtime_error("Failed to connect to database after " + std::to_string(max_retries) + " attempts");
}

void printStartupInfo(const Config& config) {
    std::cout << "\n=== Social Network Server ===" << std::endl;
    std::cout << "Server port: " << config.server_port << std::endl;
    std::cout << "Database host: " << config.db_host << std::endl;
    std::cout << "Database port: " << config.db_port << std::endl;
    std::cout << "Database name: " << config.db_name << std::endl;
    std::cout << "Database user: " << config.db_user << std::endl;
    std::cout << "============================\n" << std::endl;
}

int main(int argc, char* argv[]) {
    try {
        // Parse configuration
        Config config = parseConfig(argc, argv);
        printStartupInfo(config);

        // Build database connection string
        std::string connection_string = buildConnectionString(config);

        // Wait for database to be ready (useful in Docker environment)
        waitForDatabase(connection_string);

        // Initialize database connection
        std::cout << "Initializing database connection..." << std::endl;
        auto database = std::make_shared<Database>(connection_string);

        if (!database->isConnected()) {
            throw std::runtime_error("Failed to establish database connection");
        }

        // Setup signal handlers for graceful shutdown
        signal(SIGINT, signalHandler);
        signal(SIGTERM, signalHandler);

        // Create and configure server
        std::cout << "Creating server..." << std::endl;
        g_server = std::make_unique<Server>(database, config.server_port);

        // Start periodic cleanup of expired sessions
        std::thread cleanup_thread([database]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::hours(1));
                try {
                    database->cleanupExpiredSessions();
                } catch (const std::exception& e) {
                    std::cerr << "Error during session cleanup: " << e.what() << std::endl;
                }
            }
        });
        cleanup_thread.detach();

        // Start the server (this will block)
        std::cout << "Starting server on port " << config.server_port << "..." << std::endl;
        std::cout << "Server is ready to accept connections!" << std::endl;
        std::cout << "Press Ctrl+C to stop the server\n" << std::endl;

        g_server->start();

    } catch (const std::invalid_argument& e) {
        std::cerr << "Configuration error: " << e.what() << std::endl;
        printUsage(argv[0]);
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << std::endl;
        return 1;
    }

    std::cout << "Server shutdown complete" << std::endl;
    return 0;
}
