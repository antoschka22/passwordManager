#ifndef PASSWORD_MANAGER_DATABASE_H
#define PASSWORD_MANAGER_DATABASE_H

#include <string>
#include <vector>
#include <memory>
#include <sqlite3.h>
#include <chrono>
#include "types.h"
#include "crypt_utils.h"

namespace pwdmgr {

// Database manager for encrypted password storage
class Database {
public:
    Database() = default;
    ~Database();

    // Initialize database with encryption
    Result<void> initialize(const std::string& db_path, CryptUtils& crypt_utils);

    // Open existing database
    Result<void> open(const std::string& db_path, const std::string& master_password);

    // Create new database
    Result<void> create(const std::string& db_path, const std::string& master_password);

    // Close database
    void close();

    // Check if database exists
    static bool exists(const std::string& db_path);

    // Verify master password
    Result<bool> verify_master_password(const std::string& master_password);

    // Change master password
    Result<void> change_master_password(const std::string& old_password,
                                         const std::string& new_password);

    // Add a password entry
    Result<int64_t> add_entry(const PasswordEntry& entry);

    // Get entry by ID
    Result<PasswordEntry> get_entry(int64_t id);

    // Get entry by service name
    Result<PasswordEntry> get_entry_by_service(const std::string& service_name);

    // Get decrypted password by service name
    Result<std::string> get_password_by_service(const std::string& service_name);

    // Update entry
    Result<void> update_entry(const PasswordEntry& entry);

    // Delete entry by ID
    Result<void> delete_entry(int64_t id);

    // Delete entry by service name
    Result<void> delete_entry_by_service(const std::string& service_name);

    // List all entries
    Result<std::vector<PasswordEntry>> list_entries();

    // Search entries by pattern
    Result<std::vector<PasswordEntry>> search_entries(const std::string& pattern);

    // Get entry count
    Result<int> get_entry_count();

    // Get database version
    Result<uint32_t> get_version();

    // Check if database is initialized
    bool is_open() const { return db_ != nullptr; }

    // Get database path
    const std::string& get_path() const { return db_path_; }

    // Secure database (vacuum and reindex)
    Result<void> vacuum();

    // Export database to encrypted file
    Result<void> export_encrypted(const std::string& output_file);

    // Import from encrypted file
    Result<void> import_encrypted(const std::string& input_file,
                                   const std::string& master_password);

private:
    struct SQLiteStmt_Deleter {
        void operator()(sqlite3_stmt* stmt) const {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
        }
    };

    using SQLiteStmt_Ptr = std::unique_ptr<sqlite3_stmt, SQLiteStmt_Deleter>;

    // Initialize database schema
    Result<void> create_schema();

    // Prepare statement
    Result<SQLiteStmt_Ptr> prepare_statement(const std::string& sql);

    // Execute statement
    Result<void> execute_statement(const std::string& sql);

    // Begin transaction
    Result<void> begin_transaction();

    // Commit transaction
    Result<void> commit_transaction();

    // Rollback transaction
    void rollback_transaction();

    // Convert time_point to timestamp
    static int64_t time_to_timestamp(const std::chrono::system_clock::time_point& tp);

    // Convert timestamp to time_point
    static std::chrono::system_clock::time_point timestamp_to_time(int64_t ts);

    // Load master password data from database
    Result<MasterPasswordData> load_master_data();

    // Save master password data to database
    Result<void> save_master_data(const MasterPasswordData& data);

    // Get decrypted password from entry
    Result<std::string> decrypt_password(const std::string& encrypted_password);

    // Encrypt password for storage
    Result<std::string> encrypt_password(const std::string& password);

    sqlite3* db_ = nullptr;
    std::string db_path_;
    CryptUtils* crypt_utils_ = nullptr;
    bool in_transaction_ = false;

    // Secure cleanup
    void secure_cleanup();
};

// Database migration manager
class DatabaseMigrator {
public:
    // Check if migration is needed
    static bool needs_migration(uint32_t current_version);

    // Migrate database to latest version
    static Result<void> migrate(Database& db, uint32_t current_version);

    // Get latest version
    static uint32_t get_latest_version() { return DATABASE_VERSION; }

private:
    // Migration functions for each version
    static Result<void> migrate_to_v1(Database& db);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_DATABASE_H