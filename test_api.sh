#!/bin/bash

# Social Network API Test Script
# This script tests the basic functionality of the Social Network API

set -e  # Exit on any error

# Configuration
BASE_URL="http://localhost:8080"
TEST_DATA_DIR="/tmp/sn_test"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Create temporary directory for test data
mkdir -p "$TEST_DATA_DIR"

# Function to print colored output
print_step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

# Function to check if server is running
check_server() {
    print_step "Checking if server is running..."

    if curl -s -f "$BASE_URL/health" > /dev/null; then
        print_success "Server is running"
    else
        print_error "Server is not running at $BASE_URL"
        print_info "Please start the server with: docker-compose up"
        exit 1
    fi
}

# Function to test health endpoint
test_health() {
    print_step "Testing health endpoint..."

    response=$(curl -s "$BASE_URL/health")
    echo "Response: $response"

    if echo "$response" | jq -e '.status == "ok"' > /dev/null 2>&1; then
        print_success "Health check passed"
    else
        print_error "Health check failed"
        exit 1
    fi
}

# Function to register a test user
register_user() {
    print_step "Registering test user..."

    local timestamp=$(date +%s)
    local test_data='{
        "first_name": "Тест",
        "second_name": "Пользователь",
        "birthdate": "1990-05-15",
        "biography": "Тестовый пользователь для проверки API",
        "city": "Санкт-Петербург",
        "password": "test_password_123"
    }'

    echo "Request data: $test_data"

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$test_data" \
        "$BASE_URL/user/register")

    echo "Response: $response"

    # Extract user_id
    user_id=$(echo "$response" | jq -r '.user_id')

    if [[ "$user_id" != "null" && "$user_id" != "" ]]; then
        echo "$user_id" > "$TEST_DATA_DIR/user_id"
        print_success "User registered successfully with ID: $user_id"
        return 0
    else
        print_error "User registration failed"
        echo "Response: $response"
        return 1
    fi
}

# Function to login user
login_user() {
    print_step "Logging in test user..."

    if [[ ! -f "$TEST_DATA_DIR/user_id" ]]; then
        print_error "User ID not found. Please register user first."
        return 1
    fi

    user_id=$(cat "$TEST_DATA_DIR/user_id")

    local login_data="{
        \"id\": \"$user_id\",
        \"password\": \"test_password_123\"
    }"

    echo "Request data: $login_data"

    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "$login_data" \
        "$BASE_URL/login")

    echo "Response: $response"

    # Extract token
    token=$(echo "$response" | jq -r '.token')

    if [[ "$token" != "null" && "$token" != "" ]]; then
        echo "$token" > "$TEST_DATA_DIR/token"
        print_success "Login successful, token: $token"
        return 0
    else
        print_error "Login failed"
        echo "Response: $response"
        return 1
    fi
}

# Function to get user profile
get_user_profile() {
    print_step "Getting user profile..."

    if [[ ! -f "$TEST_DATA_DIR/user_id" ]]; then
        print_error "User ID not found. Please register user first."
        return 1
    fi

    user_id=$(cat "$TEST_DATA_DIR/user_id")

    response=$(curl -s "$BASE_URL/user/get/$user_id")

    echo "Response: $response"

    # Check if response contains user data
    first_name=$(echo "$response" | jq -r '.first_name')

    if [[ "$first_name" != "null" && "$first_name" != "" ]]; then
        print_success "User profile retrieved successfully"
        echo "User: $(echo "$response" | jq -r '.first_name') $(echo "$response" | jq -r '.second_name')"
        echo "City: $(echo "$response" | jq -r '.city')"
        echo "Birthdate: $(echo "$response" | jq -r '.birthdate')"
        return 0
    else
        print_error "Failed to get user profile"
        echo "Response: $response"
        return 1
    fi
}

# Function to test invalid requests
test_invalid_requests() {
    print_step "Testing invalid requests..."

    # Test invalid registration data
    print_info "Testing registration with missing fields..."
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"first_name": "Test"}' \
        "$BASE_URL/user/register")

    if echo "$response" | jq -e '.code == 400' > /dev/null 2>&1; then
        print_success "Invalid registration properly rejected"
    else
        print_error "Invalid registration should be rejected"
    fi

    # Test invalid login
    print_info "Testing login with wrong credentials..."
    response=$(curl -s -X POST \
        -H "Content-Type: application/json" \
        -d '{"id": "00000000-0000-0000-0000-000000000000", "password": "wrong"}' \
        "$BASE_URL/login")

    if echo "$response" | jq -e '.code == 404' > /dev/null 2>&1; then
        print_success "Invalid login properly rejected"
    else
        print_error "Invalid login should be rejected"
    fi

    # Test getting non-existent user
    print_info "Testing get user with invalid ID..."
    response=$(curl -s "$BASE_URL/user/get/00000000-0000-0000-0000-000000000000")

    if echo "$response" | jq -e '.code == 404' > /dev/null 2>&1; then
        print_success "Non-existent user properly handled"
    else
        print_error "Non-existent user should return 404"
    fi
}

# Function to cleanup test data
cleanup() {
    print_step "Cleaning up test data..."
    rm -rf "$TEST_DATA_DIR"
    print_success "Cleanup completed"
}

# Main execution
main() {
    echo "==============================================="
    echo "    Social Network API Test Script"
    echo "==============================================="
    echo ""

    # Check if jq is installed
    if ! command -v jq &> /dev/null; then
        print_error "jq is not installed. Please install jq to run this script."
        print_info "Ubuntu/Debian: sudo apt-get install jq"
        print_info "macOS: brew install jq"
        exit 1
    fi

    # Run tests
    check_server
    echo ""

    test_health
    echo ""

    if register_user; then
        echo ""

        if login_user; then
            echo ""
            get_user_profile
            echo ""
        fi
    fi

    test_invalid_requests
    echo ""

    cleanup

    echo "==============================================="
    print_success "All tests completed successfully!"
    echo "==============================================="
}

# Handle script interruption
trap cleanup EXIT

# Check command line arguments
if [[ "$1" == "--help" || "$1" == "-h" ]]; then
    echo "Social Network API Test Script"
    echo ""
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message"
    echo "  --base-url URL Set base URL (default: http://localhost:8080)"
    echo ""
    echo "This script tests the Social Network API endpoints:"
    echo "  - Health check"
    echo "  - User registration"
    echo "  - User login"
    echo "  - Get user profile"
    echo "  - Invalid request handling"
    echo ""
    echo "Prerequisites:"
    echo "  - jq (JSON processor)"
    echo "  - curl"
    echo "  - Social Network API server running"
    exit 0
fi

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --base-url)
            BASE_URL="$2"
            shift 2
            ;;
        *)
            print_error "Unknown option: $1"
            print_info "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Run main function
main
