#ifndef PASSWORD_MANAGER_TYPES_H
#define PASSWORD_MANAGER_TYPES_H

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>

namespace pwdmgr {

// Version for database compatibility
constexpr uint32_t DATABASE_VERSION = 1;

// Security constants
constexpr size_t AES_KEY_SIZE = 32;        // 256 bits
constexpr size_t AES_IV_SIZE = 16;         // 128 bits
constexpr size_t AES_TAG_SIZE = 16;        // 128 bits
constexpr size_t PBKDF2_ITERATIONS = 100000;
constexpr size_t PBKDF2_SALT_SIZE = 32;    // 256 bits
constexpr size_t MASTER_KEY_SIZE = 32;     // 256 bits

// Database constants
constexpr size_t MAX_SERVICE_NAME = 256;
constexpr size_t MAX_USERNAME = 256;
constexpr size_t MAX_PASSWORD = 1024;
constexpr size_t MAX_URL = 512;
constexpr size_t MAX_NOTES = 2048;

// Default database path
constexpr const char* DEFAULT_DB_PATH = "~/.pwdmgr/passwords.db";

// Password entry structure
struct PasswordEntry {
    int64_t id = 0;
    std::string service_name;
    std::string username;
    std::string encrypted_password;
    std::string url;
    std::string notes;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
};

// Master password data
struct MasterPasswordData {
    std::vector<uint8_t> salt;
    std::vector<uint8_t> verification_hash;
};

// Encrypted data wrapper
struct EncryptedData {
    std::vector<uint8_t> ciphertext;
    std::vector<uint8_t> iv;
    std::vector<uint8_t> tag;
};

// Password generator options
struct PasswordGeneratorOptions {
    size_t length = 16;
    bool use_uppercase = true;
    bool use_lowercase = true;
    bool use_digits = true;
    bool use_special = true;
    bool avoid_ambiguous = true;
    bool pronounceable = false;
};

// Backup metadata
struct BackupMetadata {
    std::string backup_id;
    std::string original_db_path;
    std::chrono::system_clock::time_point timestamp;
    uint32_t version;
    std::string checksum;
};

// CLI commands
enum class Command {
    NONE,
    INIT,
    ADD,
    GET,
    LIST,
    SEARCH,
    UPDATE,
    DELETE,
    GENERATE,
    EXPORT,
    IMPORT,
    BACKUP,
    RESTORE,
    CHANGE_MASTER,
    VERSION,
    HELP
};

// CLI options
struct CliOptions {
    Command command = Command::NONE;
    std::string service;
    std::string username;
    std::string password;
    std::string url;
    std::string notes;
    std::string output_file;
    std::string input_file;
    std::string pattern;
    PasswordGeneratorOptions generator_opts;
    bool verbose = false;
    bool force = false;
    bool no_mask = false;
    bool copy_to_clipboard = false;
    bool show_password = false;
};

// Result type for operations
template<typename T>
struct Result {
    bool success;
    T value;
    std::string error_message;

    static Result ok(T value) {
        return Result{true, std::move(value), ""};
    }

    static Result error(std::string message) {
        return Result{false, T{}, std::move(message)};
    }
};

// Specialization for void
template<>
struct Result<void> {
    bool success;
    std::string error_message;

    static Result ok() {
        return Result{true, ""};
    }

    static Result error(std::string message) {
        return Result{false, std::move(message)};
    }
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_TYPES_H