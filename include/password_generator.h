#ifndef PASSWORD_MANAGER_PASSWORD_GENERATOR_H
#define PASSWORD_MANAGER_PASSWORD_GENERATOR_H

#include <string>
#include <vector>
#include "types.h"

namespace pwdmgr {

// Password generator with customizable options
class PasswordGenerator {
public:
    PasswordGenerator() = default;

    // Generate a random password
    Result<std::string> generate(const PasswordGeneratorOptions& options);

    // Generate with default options
    Result<std::string> generate_default();

    // Validate password strength
    static Result<bool> validate_strength(const std::string& password);

    // Get password strength score (0-100)
    static Result<int> get_strength_score(const std::string& password);

    // Get strength description
    static std::string get_strength_description(int score);

    // Check if password is compromised (simulated - in production, use a real API)
    static bool is_compromised(const std::string& password);

private:
    // Character sets
    static constexpr const char* LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
    static constexpr const char* UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static constexpr const char* DIGITS = "0123456789";
    static constexpr const char* SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";
    static constexpr const char* AMBIGUOUS = "0O1lI";

    // Build character pool based on options
    std::string build_pool(const PasswordGeneratorOptions& options);

    // Generate pronounceable password
    Result<std::string> generate_pronounceable(size_t length, bool avoid_ambiguous);

    // Syllables for pronounceable passwords
    static constexpr const char* SYLLABLES[] = {
        "ba", "be", "bi", "bo", "bu", "by",
        "ca", "ce", "ci", "co", "cu", "cy",
        "da", "de", "di", "do", "du", "dy",
        "fa", "fe", "fi", "fo", "fu", "fy",
        "ga", "ge", "gi", "go", "gu", "gy",
        "ha", "he", "hi", "ho", "hu", "hy",
        "ja", "je", "ji", "jo", "ju", "jy",
        "ka", "ke", "ki", "ko", "ku", "ky",
        "la", "le", "li", "lo", "lu", "ly",
        "ma", "me", "mi", "mo", "mu", "my",
        "na", "ne", "ni", "no", "nu", "ny",
        "pa", "pe", "pi", "po", "pu", "py",
        "ra", "re", "ri", "ro", "ru", "ry",
        "sa", "se", "si", "so", "su", "sy",
        "ta", "te", "ti", "to", "tu", "ty",
        "va", "ve", "vi", "vo", "vu", "vy",
        "wa", "we", "wi", "wo", "wu", "wy",
        "xa", "xe", "xi", "xo", "xu", "xy",
        "ya", "ye", "yi", "yo", "yu", "yy",
        "za", "ze", "zi", "zo", "zu", "zy"
    };
    static constexpr size_t NUM_SYLLABLES = sizeof(SYLLABLES) / sizeof(SYLLABLES[0]);
};

// Passphrase generator for memorable passwords
class PassphraseGenerator {
public:
    // Generate a passphrase
    static Result<std::string> generate(size_t word_count = 4, const std::string& separator = " ");

    // Generate with custom word list
    static Result<std::string> generate_with_wordlist(const std::vector<std::string>& words,
                                                       size_t word_count = 4,
                                                       const std::string& separator = " ");

    // Get default word list
    static std::vector<std::string> get_default_wordlist();

private:
    // Default word list (eff diceware)
    static std::vector<std::string> default_wordlist;
    static bool wordlist_initialized;
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_PASSWORD_GENERATOR_H