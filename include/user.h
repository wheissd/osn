#pragma once

#include <string>
#include <optional>
#include <nlohmann/json.hpp>

namespace SocialNetwork {

class User {
public:
    // Default constructor
    User() = default;
    
    // Constructor with all fields
    User(const std::string& id,
         const std::string& first_name,
         const std::string& second_name,
         const std::string& birthdate,
         const std::string& biography,
         const std::string& city);

    // Constructor without ID (for creation)
    User(const std::string& first_name,
         const std::string& second_name,
         const std::string& birthdate,
         const std::string& biography,
         const std::string& city);

    // Getters
    const std::string& getId() const { return id_; }
    const std::string& getFirstName() const { return first_name_; }
    const std::string& getSecondName() const { return second_name_; }
    const std::string& getBirthdate() const { return birthdate_; }
    const std::string& getBiography() const { return biography_; }
    const std::string& getCity() const { return city_; }

    // Setters
    void setId(const std::string& id) { id_ = id; }
    void setFirstName(const std::string& first_name) { first_name_ = first_name; }
    void setSecondName(const std::string& second_name) { second_name_ = second_name; }
    void setBirthdate(const std::string& birthdate) { birthdate_ = birthdate; }
    void setBiography(const std::string& biography) { biography_ = biography; }
    void setCity(const std::string& city) { city_ = city; }

    // JSON serialization
    nlohmann::json toJson() const;
    static User fromJson(const nlohmann::json& json);

    // Validation
    bool isValid() const;
    std::vector<std::string> getValidationErrors() const;

    // Utility methods
    std::string getFullName() const;
    bool isEmpty() const;

private:
    std::string id_;
    std::string first_name_;
    std::string second_name_;
    std::string birthdate_;  // Format: YYYY-MM-DD
    std::string biography_;
    std::string city_;

    // Helper validation methods
    bool isValidDate(const std::string& date) const;
    bool isValidName(const std::string& name) const;
};

// JSON serialization support for nlohmann::json
void to_json(nlohmann::json& j, const User& user);
void from_json(const nlohmann::json& j, User& user);

} // namespace SocialNetwork