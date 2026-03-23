/**
 * @file types.h
 * @brief Core type definitions and constants for the Password Manager.
 *
 * This header defines the fundamental data structures, constants, and type
 * aliases used throughout the password manager application. It includes:
 * - Security constants (key sizes, iteration counts)
 * - Database schema constants
 * - Data structures for password entries and encrypted data
 * - Result type for error handling
 * - CLI command enumerations
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_TYPES_H
#define PASSWORD_MANAGER_TYPES_H

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace pwdmgr {

// =============================================================================
// Database Version
// =============================================================================

/**
 * @brief Current database schema version.
 *
 * This version number is stored in the database's meta table and is used
 * to determine if migration is needed when opening databases created with
 * older versions of the application.
 *
 * Version History:
 * - v1: Initial schema with password_entries and meta tables
 */
constexpr uint32_t DATABASE_VERSION = 1;

// =============================================================================
// Security Constants
// =============================================================================

/**
 * @defgroup SecurityConstants Security Constants
 * @brief Cryptographic parameters used throughout the application.
 * @{
 */

/** @brief AES-256 key size in bytes (256 bits / 8). */
constexpr size_t AES_KEY_SIZE = 32;

/** @brief AES initialization vector size in bytes (128 bits / 8). */
constexpr size_t AES_IV_SIZE = 16;

/** @brief AES-GCM authentication tag size in bytes (128 bits / 8). */
constexpr size_t AES_TAG_SIZE = 16;

/**
 * @brief Number of PBKDF2 iterations for key derivation.
 *
 * A higher iteration count increases security against brute-force attacks
 * but also increases the time required to derive keys. 100,000 iterations
 * provides a good balance between security and usability as of 2024.
 *
 * @note This value should be reviewed periodically and increased as
 *       computational power improves.
 */
constexpr size_t PBKDF2_ITERATIONS = 100000;

/**
 * @brief Salt size for PBKDF2 key derivation in bytes (256 bits / 8).
 *
 * A 256-bit (32-byte) salt provides strong protection against rainbow table
 * attacks and ensures uniqueness of derived keys even for identical passwords.
 */
constexpr size_t PBKDF2_SALT_SIZE = 32;

/**
 * @brief Master key size in bytes (256 bits / 8).
 *
 * The master key is derived from the user's password using PBKDF2 and is
 * used for all encryption operations within the application.
 */
constexpr size_t MASTER_KEY_SIZE = 32;

/** @} */ // End of SecurityConstants group

// =============================================================================
// Database Field Limits
// =============================================================================

/**
 * @defgroup DatabaseLimits Database Field Limits
 * @brief Maximum sizes for database fields.
 * @{
 */

/** @brief Maximum length for service/website names. */
constexpr size_t MAX_SERVICE_NAME = 256;

/** @brief Maximum length for usernames. */
constexpr size_t MAX_USERNAME = 256;

/** @brief Maximum length for passwords. */
constexpr size_t MAX_PASSWORD = 1024;

/** @brief Maximum length for URL fields. */
constexpr size_t MAX_URL = 512;

/** @brief Maximum length for notes fields. */
constexpr size_t MAX_NOTES = 2048;

/** @} */ // End of DatabaseLimits group

// =============================================================================
// Default Paths
// =============================================================================

/**
 * @brief Default database file path.
 *
 * This path is used when no database path is specified via command line
 * or environment variable. Expands to ~/.pwdmgr/passwords.db on Unix-like
 * systems.
 */
constexpr const char* DEFAULT_DB_PATH = "~/.pwdmgr/passwords.db";

// =============================================================================
// Data Structures
// =============================================================================

/**
 * @struct PasswordEntry
 * @brief Represents a single password entry in the database.
 *
 * This structure holds all information associated with a stored password,
 * including metadata such as creation and modification timestamps.
 * The password itself is stored in encrypted form and must be decrypted
 * using the CryptUtils class before use.
 *
 * @note The encrypted_password field contains base64-encoded ciphertext,
 *       IV, and authentication tag in the format: base64(IV || tag || ciphertext)
 */
struct PasswordEntry {
    int64_t id = 0;                              ///< Unique database identifier (auto-generated)
    std::string service_name;                    ///< Name of the service/website (e.g., "github")
    std::string username;                        ///< Username or email for the service
    std::string encrypted_password;              ///< Encrypted password (base64-encoded)
    std::string url;                             ///< Optional URL for the service
    std::string notes;                           ///< Optional additional notes
    std::chrono::system_clock::time_point created_at;  ///< Entry creation timestamp
    std::chrono::system_clock::time_point updated_at;  ///< Last modification timestamp
};

/**
 * @struct MasterPasswordData
 * @brief Contains data needed to verify the master password.
 *
 * This structure stores the cryptographic material required to verify a
 * user's master password without storing the password itself. The salt
 * is used for PBKDF2 key derivation, and the verification hash allows
 * comparing derived keys in constant time.
 *
 * @note Both the salt and verification hash should be treated as sensitive
 *       data and protected appropriately.
 */
struct MasterPasswordData {
    std::vector<uint8_t> salt;                   ///< Random salt for PBKDF2 (32 bytes)
    std::vector<uint8_t> verification_hash;       ///< SHA-256 hash of derived key for verification
};

/**
 * @struct EncryptedData
 * @brief Container for AES-256-GCM encrypted data.
 *
 * This structure holds the components of AES-GCM encrypted data:
 * - The initialization vector (IV) ensures uniqueness for each encryption
 * - The authentication tag (TAG) provides integrity verification
 * - The ciphertext is the encrypted plaintext
 *
 * @note All components are stored in raw binary form. Use Encoding::base64_encode
 *       to convert to string format for storage.
 */
struct EncryptedData {
    std::vector<uint8_t> ciphertext;              ///< Encrypted data
    std::vector<uint8_t> iv;                      ///< Initialization vector (16 bytes)
    std::vector<uint8_t> tag;                     ///< Authentication tag (16 bytes)
};

/**
 * @struct PasswordGeneratorOptions
 * @brief Configuration options for password generation.
 *
 * This structure allows customization of generated passwords, including
 * length, character sets used, and special generation modes like
 * pronounceable passwords or passphrases.
 */
struct PasswordGeneratorOptions {
    size_t length = 16;                           ///< Desired password length (default: 16)
    bool use_uppercase = true;                    ///< Include uppercase letters (A-Z)
    bool use_lowercase = true;                     ///< Include lowercase letters (a-z)
    bool use_digits = true;                        ///< Include digits (0-9)
    bool use_special = true;                       ///< Include special characters (!@#$%^&*...)
    bool avoid_ambiguous = true;                   ///< Exclude ambiguous chars (0, O, 1, l, I)
    bool pronounceable = false;                    ///< Generate pronounceable password
};

/**
 * @struct BackupMetadata
 * @brief Metadata describing a backup file.
 *
 * This structure contains information about a backup file, used for
 * listing, verifying, and restoring backups. The checksum is a SHA-256
 * hash of the backup data for integrity verification.
 */
struct BackupMetadata {
    std::string backup_id;                        ///< Unique identifier for the backup
    std::string original_db_path;                 ///< Path to the original database
    std::chrono::system_clock::time_point timestamp;  ///< Backup creation time
    uint32_t version;                             ///< Database version at backup time
    std::string checksum;                         ///< SHA-256 checksum for integrity
};

// =============================================================================
// Command and Option Types
// =============================================================================

/**
 * @enum Command
 * @brief Enumeration of all supported CLI commands.
 *
 * Each command corresponds to a specific password manager operation,
 * such as adding a password entry, generating a new password, or
 * creating a backup.
 */
enum class Command {
    NONE,            ///< No command specified
    INIT,            ///< Initialize a new password database
    ADD,             ///< Add a new password entry
    GET,             ///< Retrieve a password entry
    LIST,            ///< List all password entries
    SEARCH,          ///< Search for password entries
    UPDATE,          ///< Update an existing password entry
    DELETE,          ///< Delete a password entry
    GENERATE,        ///< Generate a random password
    EXPORT,          ///< Export database to encrypted backup
    IMPORT,          ///< Import from encrypted backup
    BACKUP,          ///< Create automatic backup
    RESTORE,         ///< Restore from backup
    CHANGE_MASTER,   ///< Change master password
    VERSION,         ///< Display version information
    HELP             ///< Display help message
};

/**
 * @struct CliOptions
 * @brief Container for parsed command-line options.
 *
 * This structure holds all possible command-line options after parsing.
 * Only fields relevant to the specified command will be populated.
 */
struct CliOptions {
    Command command = Command::NONE;              ///< The command to execute
    std::string service;                          ///< Service name for get/update/delete
    std::string username;                         ///< Username for add/update
    std::string password;                         ///< Password for add/update
    std::string url;                              ///< URL for add/update
    std::string notes;                            ///< Notes for add/update
    std::string output_file;                      ///< Output file for export
    std::string input_file;                       ///< Input file for import
    std::string pattern;                           ///< Search pattern
    PasswordGeneratorOptions generator_opts;      ///< Password generation options
    bool verbose = false;                         ///< Enable verbose output
    bool force = false;                           ///< Force operation without confirmation
    bool no_mask = false;                          ///< Disable password masking (insecure)
    bool copy_to_clipboard = false;               ///< Copy password to clipboard
    bool show_password = false;                   ///< Show password in plaintext
};

// =============================================================================
// Result Type
// =============================================================================

/**
 * @brief Template for operation results with error handling.
 *
 * This template provides a unified way to return either a successful
 * result or an error message. It follows a pattern similar to Rust's
 * Result type or C++23's std::expected.
 *
 * @tparam T The type of the success value
 *
 * @code
 * // Creating a successful result
 * auto result = Result<int>::ok(42);
 * if (result.success) {
 *     std::cout << "Value: " << result.value << std::endl;
 * }
 *
 * // Creating an error result
 * auto error = Result<int>::error("Something went wrong");
 * if (!error.success) {
 *     std::cerr << "Error: " << error.error_message << std::endl;
 * }
 * @endcode
 */
template<typename T>
struct Result {
    bool success;                                 ///< True if operation succeeded
    T value;                                      ///< Result value (valid only if success is true)
    std::string error_message;                    ///< Error description (valid only if success is false)

    /**
     * @brief Creates a successful result with a value.
     *
     * @param value The result value to store
     * @return Result with success=true and the provided value
     */
    static Result ok(T value) {
        return Result{true, std::move(value), ""};
    }

    /**
     * @brief Creates a failed result with an error message.
     *
     * @param message Description of what went wrong
     * @return Result with success=false and the error message
     */
    static Result error(std::string message) {
        return Result{false, T{}, std::move(message)};
    }
};

/**
 * @brief Specialization of Result for void operations.
 *
 * This specialization is used for operations that don't return a value
 * but may still fail (e.g., database operations, file writes).
 */
template<>
struct Result<void> {
    bool success;                                 ///< True if operation succeeded
    std::string error_message;                    ///< Error description (valid only if success is false)

    /**
     * @brief Creates a successful void result.
     *
     * @return Result with success=true and empty error message
     */
    static Result ok() {
        return Result{true, ""};
    }

    /**
     * @brief Creates a failed void result with an error message.
     *
     * @param message Description of what went wrong
     * @return Result with success=false and the error message
     */
    static Result error(std::string message) {
        return Result{false, std::move(message)};
    }
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_TYPES_H