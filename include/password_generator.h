/**
 * @file password_generator.h
 * @brief Password and passphrase generation utilities.
 *
 * This header provides tools for generating secure random passwords and
 * passphrases with configurable complexity options. The generator uses
 * cryptographically secure random number generation (via SecureMemory)
 * to ensure unpredictability.
 *
 * Features:
 * - Configurable character sets (uppercase, lowercase, digits, special)
 * - Ambiguous character exclusion (0, O, 1, l, I)
 * - Pronounceable password generation
 * - Passphrase generation (word-based passwords)
 * - Password strength scoring
 * - Common password detection
 *
 * Security Considerations:
 * - Uses SecureMemory::random_bytes() for cryptographically secure randomness
 * - Never uses predictable sources like rand() or time()
 * - Pronounceable passwords still use random selection from syllables
 * - Passphrases use EFF Dice Roll wordlist for security
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_PASSWORD_GENERATOR_H
#define PASSWORD_MANAGER_PASSWORD_GENERATOR_H

#include <string>
#include <vector>
#include "types.h"

namespace pwdmgr {

// =============================================================================
// PasswordGenerator Class
// =============================================================================

/**
 * @class PasswordGenerator
 * @brief Generates secure random passwords with configurable options.
 *
 * This class provides methods for generating cryptographically secure
 * passwords with various options for length, character sets, and
 * pronounceability.
 *
 * Password Generation Methods:
 * 1. Standard: Random selection from specified character sets
 * 2. Pronounceable: Alternating consonant-vowel syllables
 * 3. Passphrase: Random word combinations (via PassphraseGenerator)
 *
 * Strength Scoring:
 * - Length contribution (up to 40 points)
 * - Character variety (up to 30 points)
 * - Uniqueness ratio (up to 20 points)
 * - Pattern penalties (up to -20 points)
 *
 * @code
 * // Generate a default password
 * PasswordGenerator gen;
 * auto result = gen.generate_default();
 * std::cout << "Password: " << result.value << std::endl;
 *
 * // Generate with custom options
 * PasswordGeneratorOptions opts;
 * opts.length = 24;
 * opts.use_special = true;
 * opts.avoid_ambiguous = true;
 * auto pwd = gen.generate(opts);
 *
 * // Check password strength
 * int score = gen.get_strength_score(pwd.value).value;
 * @endcode
 */
class PasswordGenerator {
public:
    /**
     * @brief Default constructor.
     */
    PasswordGenerator() = default;

    // -------------------------------------------------------------------------
    // Password Generation
    // -------------------------------------------------------------------------

    /**
     * @brief Generates a password with the specified options.
     *
     * Creates a new random password based on the provided configuration.
     * The password will include characters from all enabled character sets.
     *
     * @param options Configuration for password generation
     * @return Result containing the generated password on success
     *
     * @throws Returns error if:
     *         - length < 8
     *         - no character types are enabled
     *         - random generation fails
     */
    Result<std::string> generate(const PasswordGeneratorOptions& options);

    /**
     * @brief Generates a password with default options.
     *
     * Creates a 16-character password with uppercase, lowercase, digits,
     * and special characters, avoiding ambiguous characters.
     *
     * @return Result containing the generated password on success
     */
    Result<std::string> generate_default();

    // -------------------------------------------------------------------------
    // Password Analysis
    // -------------------------------------------------------------------------

    /**
     * @brief Validates if a password meets minimum strength requirements.
     *
     * Checks if the password's strength score meets or exceeds 60
     * (considered "Fair" or better).
     *
     * @param password The password to validate
     * @return Result containing true if valid, false otherwise
     */
    static Result<bool> validate_strength(const std::string& password);

    /**
     * @brief Calculates a password's strength score.
     *
     * Computes a score from 0-100 based on:
     * - Length (0-40 points)
     * - Character variety (0-30 points)
     * - Character uniqueness (0-20 points)
     * - Pattern penalties (0-20 points deducted)
     *
     * @param password The password to analyze
     * @return Result containing the score (0-100) on success
     */
    static Result<int> get_strength_score(const std::string& password);

    /**
     * @brief Gets a human-readable strength description.
     *
     * Converts a numerical score to a descriptive string.
     *
     * @param score The score from get_strength_score()
     * @return Description string: "Very Weak", "Weak", "Fair", "Strong", "Very Strong"
     */
    static std::string get_strength_description(int score);

    /**
     * @brief Checks if a password appears in known breach lists.
     *
     * This is currently a placeholder that always returns false.
     * In production, this should integrate with a breach database API
     * like "Have I Been Pwned".
     *
     * @param password The password to check
     * @return true if password is known to be compromised
     *
     * @note Currently returns false as a placeholder.
     *       TODO: Implement actual breach checking.
     */
    static bool is_compromised(const std::string& password);

private:
    // -------------------------------------------------------------------------
    // Character Sets
    // -------------------------------------------------------------------------

    /** @brief Lowercase alphabet characters. */
    static constexpr const char* LOWERCASE = "abcdefghijklmnopqrstuvwxyz";

    /** @brief Uppercase alphabet characters. */
    static constexpr const char* UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /** @brief Digit characters. */
    static constexpr const char* DIGITS = "0123456789";

    /** @brief Special/punctuation characters. */
    static constexpr const char* SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?";

    /** @brief Characters that may be confused with each other. */
    static constexpr const char* AMBIGUOUS = "0O1lI";

    // -------------------------------------------------------------------------
    // Pronounceable Password Support
    // -------------------------------------------------------------------------

    /**
     * @brief Syllables for pronounceable password generation.
     *
     * Common two-letter consonant-vowel combinations that are easy to
     * pronounce while still providing good entropy through random selection.
     */
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

    /** @brief Number of syllables in the SYLLABLES array. */
    static constexpr size_t NUM_SYLLABLES = sizeof(SYLLABLES) / sizeof(SYLLABLES[0]);

    // -------------------------------------------------------------------------
    // Private Helper Methods
    // -------------------------------------------------------------------------

    /**
     * @brief Builds the character pool for password generation.
     *
     * Combines enabled character sets based on the options, optionally
     * removing ambiguous characters.
     *
     * @param options The password generation options
     * @return String containing all characters to choose from
     */
    std::string build_pool(const PasswordGeneratorOptions& options);

    /**
     * @brief Generates a pronounceable password.
     *
     * Creates a password from randomly selected syllables with alternating
     * case, plus optional digits and special characters.
     *
     * @param length Desired password length
     * @param avoid_ambiguous Whether to exclude ambiguous characters
     * @return Result containing the generated password on success
     */
    Result<std::string> generate_pronounceable(size_t length, bool avoid_ambiguous);
};

// =============================================================================
// PassphraseGenerator Class
// =============================================================================

/**
 * @class PassphraseGenerator
 * @brief Generates memorable passphrases from word lists.
 *
 * Creates passphrases by randomly selecting words from a dictionary.
 * This approach produces passwords that are:
 * - Easy to remember
 * - Highly secure (high entropy)
 * - Easy to type
 *
 * The default wordlist is based on the EFF Dice Roll list, designed
 * specifically for passphrase generation with words that are:
 * - Recognizable
 * - Easy to spell
 * - Not offensive
 *
 * @code
 * // Generate a 4-word passphrase
 * auto phrase = PassphraseGenerator::generate();
 * std::cout << "Passphrase: " << phrase.value << std::endl;
 *
 * // Generate a 6-word passphrase with hyphen separator
 * auto phrase = PassphraseGenerator::generate(6, "-");
 * @endcode
 *
 * Security Note:
 * A 4-word passphrase from a 7776-word list has about 51 bits of entropy.
 * Adding more words significantly increases security (6 words = ~77 bits).
 */
class PassphraseGenerator {
public:
    /**
     * @brief Generates a passphrase with default options.
     *
     * Creates a passphrase from randomly selected words using the
     * default wordlist.
     *
     * @param word_count Number of words to include (default: 4)
     * @param separator String to separate words (default: " ")
     * @return Result containing the passphrase on success
     */
    static Result<std::string> generate(size_t word_count = 4, const std::string& separator = " ");

    /**
     * @brief Generates a passphrase from a custom word list.
     *
     * Uses the provided word list instead of the default EFF list.
     * This allows for custom dictionaries or localization.
     *
     * @param words Vector of words to choose from
     * @param word_count Number of words to include
     * @param separator String to separate words
     * @return Result containing the passphrase on success
     *
     * @warning The entropy of the passphrase depends on the size of the
     *          word list. Use a list with at least 2048 words for good security.
     */
    static Result<std::string> generate_with_wordlist(const std::vector<std::string>& words,
                                                       size_t word_count = 4,
                                                       const std::string& separator = " ");

    /**
     * @brief Gets the default word list.
     *
     * Returns a subset of the EFF Dice Roll wordlist, providing
     * words that are easy to remember and type.
     *
     * @return Vector of words for passphrase generation
     */
    static std::vector<std::string> get_default_wordlist();

private:
    /** @brief Default word list (initialized on first use). */
    static std::vector<std::string> default_wordlist;

    /** @brief Flag indicating if wordlist has been initialized. */
    static bool wordlist_initialized;
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_PASSWORD_GENERATOR_H