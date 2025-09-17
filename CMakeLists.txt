cmake_minimum_required(VERSION 3.15)
project(social_network)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Boost
find_package(Boost REQUIRED COMPONENTS system thread filesystem)

# Find libpqxx using pkg-config
pkg_check_modules(PQXX REQUIRED libpqxx)

# Find nlohmann_json
find_package(nlohmann_json REQUIRED)

# Find Crow using traditional search (installed via deb package)
find_package(Crow REQUIRED)
#find_path(CROW_INCLUDE_DIRS crow.h PATH_SUFFIXES crow REQUIRED)

# Include directories
include_directories(include)
include_directories(${CROW_INCLUDE_DIRS})
include_directories(${PQXX_INCLUDE_DIRS})

# Source files
file(GLOB_RECURSE SOURCES "src/*.cpp")
file(GLOB_RECURSE HEADERS "include/*.h")

# Create executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(${PROJECT_NAME}
    ${CROW_LIBRARIES}
    ${PQXX_LIBRARIES}
    nlohmann_json::nlohmann_json
    OpenSSL::SSL
    OpenSSL::Crypto
    Boost::system
    Boost::thread
    Boost::filesystem
    pthread
)

# Compiler options
target_compile_options(${PROJECT_NAME} PRIVATE
    $<$<CXX_COMPILER_ID:GNU>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:Clang>:-Wall -Wextra -O2>
    $<$<CXX_COMPILER_ID:MSVC>:/W4 /O2>
    ${PQXX_CFLAGS_OTHER}
)

# Link directories
target_link_directories(${PROJECT_NAME} PRIVATE ${PQXX_LIBRARY_DIRS})

# Set output directory
set_target_properties(${PROJECT_NAME} PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
)
