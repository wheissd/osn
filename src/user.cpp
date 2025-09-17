#include "user.h"
#include <regex>
#include <sstream>

#include <chrono>

namespace SocialNetwork {

// Constructor with all fields
User::User(const std::string& id,
           const std::string& first_name,
           const std::string& second_name,
           const std::string& birthdate,
           const std::string& biography,
           const std::string& city)
    : id_(id), first_name_(first_name), second_name_(second_name),
      birthdate_(birthdate), biography_(biography), city_(city) {
}

// Constructor without ID (for creation)
User::User(const std::string& first_name,
           const std::string& second_name,
           const std::string& birthdate,
           const std::string& biography,
           const std::string& city)
    : first_name_(first_name), second_name_(second_name),
      birthdate_(birthdate), biography_(biography), city_(city) {
}

nlohmann::json User::toJson() const {
    nlohmann::json j;
    j["id"] = id_;
    j["first_name"] = first_name_;
    j["second_name"] = second_name_;
    j["birthdate"] = birthdate_;
    j["biography"] = biography_;
    j["city"] = city_;
    return j;
}

User User::fromJson(const nlohmann::json& json) {
    User user;

    if (json.contains("id") && !json["id"].is_null()) {
        user.setId(json["id"].get<std::string>());
    }

    if (json.contains("first_name") && !json["first_name"].is_null()) {
        user.setFirstName(json["first_name"].get<std::string>());
    }

    if (json.contains("second_name") && !json["second_name"].is_null()) {
        user.setSecondName(json["second_name"].get<std::string>());
    }

    if (json.contains("birthdate") && !json["birthdate"].is_null()) {
        user.setBirthdate(json["birthdate"].get<std::string>());
    }

    if (json.contains("biography") && !json["biography"].is_null()) {
        user.setBiography(json["biography"].get<std::string>());
    }

    if (json.contains("city") && !json["city"].is_null()) {
        user.setCity(json["city"].get<std::string>());
    }

    return user;
}

bool User::isValid() const {
    auto errors = getValidationErrors();
    return errors.empty();
}

std::vector<std::string> User::getValidationErrors() const {
    std::vector<std::string> errors;

    if (!isValidName(first_name_)) {
        errors.push_back("Invalid first name: must be 1-100 characters and contain only letters, spaces, and hyphens");
    }

    if (!isValidName(second_name_)) {
        errors.push_back("Invalid second name: must be 1-100 characters and contain only letters, spaces, and hyphens");
    }

    if (!isValidDate(birthdate_)) {
        errors.push_back("Invalid birthdate: must be in YYYY-MM-DD format and be a valid date");
    }

    if (city_.empty() || city_.length() > 100) {
        errors.push_back("Invalid city: must be 1-100 characters");
    }

    if (biography_.length() > 1000) {
        errors.push_back("Invalid biography: must be no more than 1000 characters");
    }

    return errors;
}

std::string User::getFullName() const {
    if (first_name_.empty() && second_name_.empty()) {
        return "";
    }

    if (first_name_.empty()) {
        return second_name_;
    }

    if (second_name_.empty()) {
        return first_name_;
    }

    return first_name_ + " " + second_name_;
}

bool User::isEmpty() const {
    return first_name_.empty() && second_name_.empty() &&
           birthdate_.empty() && biography_.empty() && city_.empty();
}

bool User::isValidDate(const std::string& date) const {
    if (date.empty()) {
        return false;
    }

    // Check format YYYY-MM-DD
    std::regex date_regex(R"(^\d{4}-\d{2}-\d{2}$)");
    if (!std::regex_match(date, date_regex)) {
        return false;
    }

    // Parse date components
    std::istringstream iss(date);
    std::string year_str, month_str, day_str;

    std::getline(iss, year_str, '-');
    std::getline(iss, month_str, '-');
    std::getline(iss, day_str);

    try {
        int year = std::stoi(year_str);
        int month = std::stoi(month_str);
        int day = std::stoi(day_str);

        // Basic validation
        if (year < 1900 || year > 2100) return false;
        if (month < 1 || month > 12) return false;
        if (day < 1 || day > 31) return false;

        // Days in month validation
        std::vector<int> days_in_month = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

        // Check for leap year
        bool is_leap = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0);
        if (is_leap) {
            days_in_month[1] = 29;
        }

        if (day > days_in_month[month - 1]) {
            return false;
        }

        // Check that date is not in the future
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        auto tm = *std::localtime(&time_t);
        int current_year = tm.tm_year + 1900;
        int current_month = tm.tm_mon + 1;
        int current_day = tm.tm_mday;

        if (year > current_year ||
            (year == current_year && month > current_month) ||
            (year == current_year && month == current_month && day > current_day)) {
            return false;
        }

        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool User::isValidName(const std::string& name) const {
    if (name.empty() || name.length() > 100) {
        return false;
    }

    // Check for invalid characters instead of trying to whitelist all valid Unicode ranges
    // This approach is more reliable with UTF-8 and various character encodings
    for (char c : name) {
        // Allow printable ASCII characters (letters, spaces, hyphens, apostrophes)
        if (c > 0 && c <= 127) {
            if (!std::isalnum(c) && c != ' ' && c != '-' && c != '\'') {
                return false;
            }
        }
        // For non-ASCII characters (including Cyrillic), we allow them through
        // as long as they're not control characters
        else if (c >= 0 && c < 32) {
            // Reject control characters
            return false;
        }
    }

    // Check that name doesn't start or end with whitespace
    if (name.front() == ' ' || name.back() == ' ') {
        return false;
    }

    // Check that name doesn't have multiple consecutive spaces
    for (size_t i = 1; i < name.length(); ++i) {
        if (name[i] == ' ' && name[i-1] == ' ') {
            return false;
        }
    }

    return true;
}

// Global JSON serialization functions
void to_json(nlohmann::json& j, const User& user) {
    j = user.toJson();
}

void from_json(const nlohmann::json& j, User& user) {
    user = User::fromJson(j);
}

} // namespace SocialNetwork
