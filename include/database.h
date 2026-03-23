/**
 * @file database.h
 * @brief SQLite database management for encrypted password storage.
 *
 * This header provides the database layer for the password manager, handling
 * all persistent storage operations. Passwords are stored in encrypted form
 * using the CryptUtils class, and the database file itself can be backed up
 * and restored.
 *
 * Database Schema:
 * - meta: Key-value store for database metadata (version, salt, hash)
 * - password_entries: Stores encrypted password entries
 *
 * Security Features:
 * - All passwords stored in encrypted form (AES-256-GCM)
 * - Master password verified via PBKDF2-derived key hash
 * - SQLite prepared statements prevent SQL injection
 * - Secure cleanup on destruction
 *
 * @author Password Manager Team
 * @version 1.0
 */

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

// =============================================================================
// Database Class
// =============================================================================

/**
 * @class Database
 * @brief SQLite database manager for encrypted password storage.
 *
 * This class provides a high-level interface for managing password entries
 * in an SQLite database. All passwords are encrypted before storage and
 * decrypted on retrieval using the provided CryptUtils instance.
 *
 * Key Operations:
 * - Database initialization and master password setup
 * - Password entry CRUD operations
 * - Master password verification and change
 * - Database import/export for backups
 *
 * Thread Safety:
 * - This class is NOT thread-safe. External synchronization is required
 *   when accessing the same Database instance from multiple threads.
 *
 * @code
 * Database db;
 * CryptUtils crypto;
 *
 * // Initialize with master password
 * auto master_data = KeyManager::generate_master_data(master_pwd);
 * crypto.initialize(master_pwd, master_data.value.salt);
 * db.create("passwords.db", master_pwd);
 *
 * // Add an entry
 * PasswordEntry entry;
 * entry.service_name = "github";
 * entry.username = "user@example.com";
 * entry.encrypted_password = "my_secret"; // Will be encrypted
 * db.add_entry(entry);
 *
 * // Retrieve and decrypt
 * auto password = db.get_password_by_service("github");
 * @endcode
 */
class Database {
public:
    // -------------------------------------------------------------------------
    // Constructors and Destructor
    // -------------------------------------------------------------------------

    /**
     * @brief Default constructor.
     *
     * Creates an uninitialized database instance. Call create() or open()
     * before using other methods.
     */
    Database() = default;

    /**
     * @brief Destructor - closes database and cleans up sensitive data.
     *
     * Closes any open database connection and securely clears the
     * CryptUtils reference.
     */
    ~Database();

    // -------------------------------------------------------------------------
    // Database Lifecycle
    // -------------------------------------------------------------------------

    /**
     * @brief Initializes the database with encryption utilities.
     *
     * Sets up the database path and prepares for operations that don't
     * require immediate password verification (like listing).
     *
     * @param db_path Path to the SQLite database file
     * @param crypt_utils Reference to initialized CryptUtils instance
     * @return Result indicating success or containing an error message
     */
    Result<void> initialize(const std::string& db_path, CryptUtils& crypt_utils);

    /**
     * @brief Opens an existing database.
     *
     * Opens the database file and optionally verifies the master password.
     * If a password is provided, it will be used to initialize the encryption
     * utilities.
     *
     * @param db_path Path to the SQLite database file
     * @param master_password The master password (empty to skip verification)
     * @return Result indicating success or containing an error message
     */
    Result<void> open(const std::string& db_path, const std::string& master_password);

    /**
     * @brief Creates a new database with the given master password.
     *
     * Creates a new database file, initializes the schema, and stores the
     * master password verification data. Fails if the file already exists.
     *
     * @param db_path Path for the new database file
     * @param master_password The master password to set
     * @return Result indicating success or containing an error message
     *
     * @warning This will fail if the file already exists. Use open() for
     *          existing databases.
     */
    Result<void> create(const std::string& db_path, const std::string& master_password);

    /**
     * @brief Closes the database connection.
     *
     * Safely closes the database, rolling back any active transactions
     * and clearing the CryptUtils reference.
     */
    void close();

    /**
     * @brief Checks if a database file exists.
     *
     * @param db_path Path to check
     * @return true if the file exists and is readable
     */
    static bool exists(const std::string& db_path);

    // -------------------------------------------------------------------------
    // Authentication
    // -------------------------------------------------------------------------

    /**
     * @brief Verifies a master password against the stored hash.
     *
     * Derives a key from the password and compares it against the stored
     * verification hash using constant-time comparison.
     *
     * @param master_password The password to verify
     * @return Result containing true if password is correct
     */
    Result<bool> verify_master_password(const std::string& master_password);

    /**
     * @brief Changes the master password.
     *
     * Verifies the old password, re-encrypts all stored passwords with
     * a new key derived from the new password, and updates the stored
     * verification data.
     *
     * @param old_password The current master password
     * @param new_password The new master password
     * @return Result indicating success or containing an error message
     *
     * @warning This is an expensive operation that re-encrypts all
     *          passwords in the database.
     */
    Result<void> change_master_password(const std::string& old_password,
                                         const std::string& new_password);

    // -------------------------------------------------------------------------
    // Entry Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Adds a new password entry.
     *
     * Encrypts the password and stores the entry in the database.
     * The service_name must be unique.
     *
     * @param entry The entry to add (password will be encrypted)
     * @return Result containing the new entry's ID on success
     *
     * @note The entry's encrypted_password field should contain the plaintext
     *       password. It will be encrypted before storage.
     */
    Result<int64_t> add_entry(const PasswordEntry& entry);

    /**
     * @brief Retrieves an entry by its ID.
     *
     * @param id The database ID of the entry
     * @return Result containing the entry on success
     *
     * @note The returned entry contains the encrypted password. Use
     *       get_password_by_service() to get the decrypted password.
     */
    Result<PasswordEntry> get_entry(int64_t id);

    /**
     * @brief Retrieves an entry by its service name.
     *
     * @param service_name The service name to search for
     * @return Result containing the entry on success
     *
     * @note Service names are unique in the database.
     */
    Result<PasswordEntry> get_entry_by_service(const std::string& service_name);

    /**
     * @brief Retrieves and decrypts a password by service name.
     *
     * Finds the entry by service name and decrypts the password.
     *
     * @param service_name The service name to search for
     * @return Result containing the decrypted password on success
     */
    Result<std::string> get_password_by_service(const std::string& service_name);

    /**
     * @brief Updates an existing entry.
     *
     * Updates all fields of the entry, re-encrypting the password.
     * The entry's ID is used to identify which entry to update.
     *
     * @param entry The entry with updated values
     * @return Result indicating success or containing an error message
     */
    Result<void> update_entry(const PasswordEntry& entry);

    /**
     * @brief Deletes an entry by its ID.
     *
     * @param id The database ID of the entry to delete
     * @return Result indicating success or containing an error message
     */
    Result<void> delete_entry(int64_t id);

    /**
     * @brief Deletes an entry by its service name.
     *
     * @param service_name The service name of the entry to delete
     * @return Result indicating success or containing an error message
     */
    Result<void> delete_entry_by_service(const std::string& service_name);

    /**
     * @brief Lists all password entries.
     *
     * Returns all entries sorted alphabetically by service name.
     *
     * @return Result containing a vector of entries on success
     *
     * @note Passwords in returned entries are encrypted.
     */
    Result<std::vector<PasswordEntry>> list_entries();

    /**
     * @brief Searches for entries matching a pattern.
     *
     * Searches service name, username, and URL fields for the pattern.
     *
     * @param pattern The search pattern (SQL LIKE syntax with % wildcards)
     * @return Result containing matching entries on success
     */
    Result<std::vector<PasswordEntry>> search_entries(const std::string& pattern);

    /**
     * @brief Gets the total number of entries.
     *
     * @return Result containing the count on success
     */
    Result<int> get_entry_count();

    // -------------------------------------------------------------------------
    // Database Information
    // -------------------------------------------------------------------------

    /**
     * @brief Gets the database schema version.
     *
     * @return Result containing the version number on success
     */
    Result<uint32_t> get_version();

    /**
     * @brief Checks if the database is currently open.
     *
     * @return true if the database connection is active
     */
    bool is_open() const { return db_ != nullptr; }

    /**
     * @brief Gets the database file path.
     *
     * @return The path to the database file
     */
    const std::string& get_path() const { return db_path_; }

    // -------------------------------------------------------------------------
    // Maintenance Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Vacuums the database to reclaim space.
     *
     * Runs SQLite's VACUUM command to compact the database file.
     * This can reduce file size after deleting entries.
     *
     * @return Result indicating success or containing an error message
     */
    Result<void> vacuum();

    /**
     * @brief Exports the database to an encrypted backup file.
     *
     * Creates a backup file containing the entire database with
     * metadata (version, checksum, timestamp).
     *
     * @param output_file Path for the backup file
     * @return Result indicating success or containing an error message
     */
    Result<void> export_encrypted(const std::string& output_file);

    /**
     * @brief Imports a database from an encrypted backup file.
     *
     * Restores the database from a backup file after verifying integrity.
     * The current database is backed up before replacement.
     *
     * @param input_file Path to the backup file
     * @param master_password The password for the backup file
     * @return Result indicating success or containing an error message
     */
    Result<void> import_encrypted(const std::string& input_file,
                                   const std::string& master_password);

private:
    // -------------------------------------------------------------------------
    // SQLite Helper Types
    // -------------------------------------------------------------------------

    /**
     * @brief Custom deleter for sqlite3_stmt pointers.
     *
     * Ensures SQLite statements are properly finalized when the
     * unique_ptr goes out of scope.
     */
    struct SQLiteStmt_Deleter {
        void operator()(sqlite3_stmt* stmt) const {
            if (stmt) {
                sqlite3_finalize(stmt);
            }
        }
    };

    /** @brief Type alias for unique_ptr with SQLite statement deleter. */
    using SQLiteStmt_Ptr = std::unique_ptr<sqlite3_stmt, SQLiteStmt_Deleter>;

    // -------------------------------------------------------------------------
    // Private Helper Methods
    // -------------------------------------------------------------------------

    /**
     * @brief Creates the database schema.
     *
     * Creates the meta and password_entries tables with appropriate
     * indexes. Called during database creation.
     *
     * @return Result indicating success or containing an error message
     */
    Result<void> create_schema();

    /**
     * @brief Prepares a SQLite statement.
     *
     * @param sql The SQL query string
     * @return Result containing the prepared statement on success
     */
    Result<SQLiteStmt_Ptr> prepare_statement(const std::string& sql);

    /**
     * @brief Executes a SQL statement.
     *
     * Prepares and executes a statement that doesn't return results.
     *
     * @param sql The SQL statement to execute
     * @return Result indicating success or containing an error message
     */
    Result<void> execute_statement(const std::string& sql);

    /**
     * @brief Begins a database transaction.
     *
     * @return Result indicating success or containing an error message
     */
    Result<void> begin_transaction();

    /**
     * @brief Commits the current transaction.
     *
     * @return Result indicating success or containing an error message
     */
    Result<void> commit_transaction();

    /**
     * @brief Rolls back the current transaction.
     *
     * Safe to call even if no transaction is active.
     */
    void rollback_transaction();

    /**
     * @brief Converts time_point to Unix timestamp.
     *
     * @param tp The time point to convert
     * @return Unix timestamp in seconds
     */
    static int64_t time_to_timestamp(const std::chrono::system_clock::time_point& tp);

    /**
     * @brief Converts Unix timestamp to time_point.
     *
     * @param ts Unix timestamp in seconds
     * @return time_point representing the timestamp
     */
    static std::chrono::system_clock::time_point timestamp_to_time(int64_t ts);

    /**
     * @brief Loads master password data from the database.
     *
     * Retrieves the salt and verification hash stored in the meta table.
     *
     * @return Result containing MasterPasswordData on success
     */
    Result<MasterPasswordData> load_master_data();

    /**
     * @brief Saves master password data to the database.
     *
     * Stores the salt and verification hash in the meta table.
     *
     * @param data The master password data to save
     * @return Result indicating success or containing an error message
     */
    Result<void> save_master_data(const MasterPasswordData& data);

    /**
     * @brief Decrypts a password stored in the database.
     *
     * Parses the stored format (IV:tag:ciphertext, base64 encoded)
     * and decrypts using CryptUtils.
     *
     * @param encrypted_password The base64-encoded encrypted password
     * @return Result containing the plaintext password on success
     */
    Result<std::string> decrypt_password(const std::string& encrypted_password);

    /**
     * @brief Encrypts a password for storage.
     *
     * Encrypts the password and formats it for storage as
     * base64(IV:tag:ciphertext).
     *
     * @param password The plaintext password
     * @return Result containing the encrypted string on success
     */
    Result<std::string> encrypt_password(const std::string& password);

    /**
     * @brief Performs secure cleanup on destruction.
     *
     * Closes the database and clears any sensitive data.
     */
    void secure_cleanup();

    // -------------------------------------------------------------------------
    // Member Variables
    // -------------------------------------------------------------------------

    sqlite3* db_ = nullptr;              ///< SQLite database connection
    std::string db_path_;                 ///< Path to database file
    CryptUtils* crypt_utils_ = nullptr;   ///< Encryption utilities (not owned)
    bool in_transaction_ = false;         ///< Transaction state tracking
};

// =============================================================================
// DatabaseMigrator Class
// =============================================================================

/**
 * @class DatabaseMigrator
 * @brief Handles database schema migrations between versions.
 *
 * This class provides static methods for checking if migrations are needed
 * and performing the necessary schema updates when opening databases from
 * older versions of the application.
 *
 * Migration Strategy:
 * - Check current version against DATABASE_VERSION
 * - Apply migrations sequentially from current to target version
 * - Each migration is atomic (all-or-nothing)
 */
class DatabaseMigrator {
public:
    /**
     * @brief Checks if a database needs migration.
     *
     * @param current_version The database's current schema version
     * @return true if migration to DATABASE_VERSION is needed
     */
    static bool needs_migration(uint32_t current_version);

    /**
     * @brief Migrates a database to the latest version.
     *
     * Applies all necessary migrations to bring the database schema
     * up to DATABASE_VERSION.
     *
     * @param db Reference to the open database
     * @param current_version The database's current schema version
     * @return Result indicating success or containing an error message
     */
    static Result<void> migrate(Database& db, uint32_t current_version);

    /**
     * @brief Gets the latest supported database version.
     *
     * @return The current DATABASE_VERSION constant
     */
    static uint32_t get_latest_version() { return DATABASE_VERSION; }

private:
    /**
     * @brief Migration to version 1 (initial schema).
     *
     * Creates the initial database schema. For databases that
     * already have content, this is a no-op.
     *
     * @param db Reference to the database
     * @return Result indicating success or containing an error message
     */
    static Result<void> migrate_to_v1(Database& db);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_DATABASE_H