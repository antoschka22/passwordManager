/**
 * @file backup_manager.h
 * @brief Backup and recovery management for the password database.
 *
 * This header provides utilities for creating, restoring, and managing
 * encrypted backups of the password database. Backups include metadata
 * for integrity verification and version tracking.
 *
 * Features:
 * - Encrypted backup export/import
 * - Automatic timestamp-based backup naming
 * - Backup integrity verification (SHA-256 checksums)
 * - Backup versioning and tagging
 * - Recovery key generation
 *
 * Backup Format:
 * - Header line: "PWDMGR_BACKUP"
 * - Metadata: VERSION, BACKUP_ID, TIMESTAMP, CHECKSUM
 * - Data marker: "DATA_START:"
 * - Raw database content
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_BACKUP_MANAGER_H
#define PASSWORD_MANAGER_BACKUP_MANAGER_H

#include <string>
#include <vector>
#include <chrono>
#include "types.h"
#include "database.h"

namespace pwdmgr {

// =============================================================================
// BackupManager Class
// =============================================================================

/**
 * @class BackupManager
 * @brief Manages database backup creation, restoration, and verification.
 *
 * This class provides comprehensive backup management functionality including:
 * - Exporting databases to timestamped backup files
 * - Importing and restoring from backup files
 * - Verifying backup integrity
 * - Managing backup retention policies
 *
 * All backups are encrypted copies of the SQLite database file, protected
 * by the same master password used for the database.
 *
 * @code
 * Database db;
 * // ... initialize database ...
 *
 * BackupManager backup_mgr(db);
 *
 * // Create a backup
 * auto result = backup_mgr.create_auto_backup("/path/to/backups");
 * if (result.success) {
 *     std::cout << "Backup created: " << result.value << std::endl;
 * }
 *
 * // Restore from backup
 * auto restore = backup_mgr.restore_backup("/path/to/backup.pwdb", master_pwd);
 * @endcode
 */
class BackupManager {
public:
    /**
     * @brief Constructs a BackupManager for the given database.
     *
     * @param db Reference to an open Database instance
     */
    BackupManager(Database& db) : db_(db) {}

    // -------------------------------------------------------------------------
    // Backup Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Exports the database to an encrypted backup file.
     *
     * Creates a complete backup of the database including all metadata.
     * The backup file contains the raw database content plus a header
     * with version and checksum information.
     *
     * @param output_file Path for the backup file
     * @return Result indicating success or containing an error message
     *
     * @note The backup file is a complete copy of the database, protected
     *       by the same master password. No additional encryption is applied.
     */
    Result<void> export_backup(const std::string& output_file);

    /**
     * @brief Imports a database from an encrypted backup file.
     *
     * Restores the database from a backup file after verifying the
     * master password. The current database is NOT replaced; this
     * method opens the backup for reading.
     *
     * @param input_file Path to the backup file
     * @param master_password The master password for the backup
     * @return Result indicating success or containing an error message
     *
     * @see restore_backup() for complete database replacement
     */
    Result<void> import_backup(const std::string& input_file,
                               const std::string& master_password);

    /**
     * @brief Lists all backup files in a directory.
     *
     * Scans the specified directory for valid backup files and returns
     * their metadata. Results are sorted by timestamp (newest first).
     *
     * @param directory Path to scan for backups
     * @return Result containing vector of BackupMetadata on success
     */
    Result<std::vector<BackupMetadata>> list_backups(const std::string& directory);

    /**
     * @brief Gets metadata from a backup file.
     *
     * Extracts and returns the metadata header from a backup file
     * without loading the entire database.
     *
     * @param backup_file Path to the backup file
     * @return Result containing BackupMetadata on success
     */
    Result<BackupMetadata> get_backup_metadata(const std::string& backup_file);

    /**
     * @brief Restores the database from a backup file.
     *
     * Verifies the backup integrity and replaces the current database
     * with the backup content. Optionally requires confirmation.
     *
     * @param backup_file Path to the backup file
     * @param master_password The master password for the backup
     * @param force If true, skip integrity verification
     * @return Result indicating success or containing an error message
     *
     * @warning This operation replaces the current database. Always create
     *          a backup before calling this method.
     */
    Result<void> restore_backup(const std::string& backup_file,
                                const std::string& master_password,
                                bool force = false);

    /**
     * @brief Creates an automatic timestamped backup.
     *
     * Generates a backup file with automatic naming in the format:
     * pwdmgr_backup_YYYYMMDD_HHMMSS.pwdb
     *
     * @param backup_dir Directory to store the backup
     * @return Result containing the backup file path on success
     */
    Result<std::string> create_auto_backup(const std::string& backup_dir);

    /**
     * @brief Removes old backups, keeping only the most recent.
     *
     * Deletes backup files beyond the retention count, starting with
     * the oldest files.
     *
     * @param backup_dir Directory containing backups
     * @param keep_count Number of recent backups to preserve (default: 5)
     * @return Result containing the number of deleted backups on success
     */
    Result<int> clean_old_backups(const std::string& backup_dir,
                                  size_t keep_count = 5);

    /**
     * @brief Verifies the integrity of a backup file.
     *
     * Checks that:
     * - The file format is valid
     * - Required metadata fields are present
     * - The SHA-256 checksum matches the data
     *
     * @param backup_file Path to the backup file
     * @return Result containing true if backup is valid
     */
    Result<bool> verify_backup(const std::string& backup_file);

    /**
     * @brief Gets the default backup directory path.
     *
     * Returns the platform-specific default location for backup storage.
     * On Unix-like systems, this is ~/.pwdmgr/backups.
     *
     * @return Path to the default backup directory
     */
    static std::string get_default_backup_dir();

private:
    Database& db_;  ///< Reference to the database to backup/restore

    /**
     * @brief Generates a backup filename with timestamp.
     *
     * Creates a filename in the format: pwdmgr_backup_YYYYMMDD_HHMMSS.pwdb
     *
     * @return Generated filename (not full path)
     */
    std::string generate_backup_filename();

    /**
     * @brief Extracts metadata from a backup file.
     *
     * Parses the backup header and returns the metadata fields.
     *
     * @param backup_file Path to the backup file
     * @return Result containing BackupMetadata on success
     */
    Result<BackupMetadata> extract_metadata(const std::string& backup_file);

    /**
     * @brief Validates the backup file format.
     *
     * Checks that the file has the correct header and all required
     * metadata fields.
     *
     * @param backup_file Path to the backup file
     * @return Result containing true if format is valid
     */
    Result<bool> validate_format(const std::string& backup_file);
};

// =============================================================================
// RecoveryKeyGenerator Class
// =============================================================================

/**
 * @class RecoveryKeyGenerator
 * @brief Generates and validates recovery keys for emergency access.
 *
 * Recovery keys provide a backup method for accessing the password database
 * if the master password is forgotten. Each key is a random 128-bit value
 * formatted as groups of hex digits for easy transcription.
 *
 * Key Format:
 * - 16 bytes (128 bits) of random data
 * - Encoded as 32 hex characters
 * - Formatted as 4 groups of 8 characters: XXXXXXXX-XXXXXXXX-XXXXXXXX-XXXXXXXX
 *
 * Security Considerations:
 * - Keys should be stored separately from the database
 * - Each key should be used only once
 * - Lost keys cannot be recovered (by design)
 */
class RecoveryKeyGenerator {
public:
    /**
     * @brief Generates a new recovery key.
     *
     * Creates a cryptographically random 128-bit key and formats it
     * for easy reading and transcription.
     *
     * @return Result containing the formatted key string on success
     *
     * @code
     * auto key = RecoveryKeyGenerator::generate_recovery_key();
     * // key.value = "A1B2C3D4-E5F67890-12345678-ABCDEF00"
     * @endcode
     */
    static Result<std::string> generate_recovery_key();

    /**
     * @brief Validates a recovery key format.
     *
     * Checks that the key is properly formatted and has the correct length.
     * Does NOT verify that the key exists in any database.
     *
     * @param key The recovery key to validate (formatted or stripped)
     * @return true if format is valid, false otherwise
     */
    static bool validate_recovery_key(const std::string& key);

    /**
     * @brief Formats a recovery key with dashes.
     *
     * Takes a raw hex string and inserts dashes to create the
     * standard format.
     *
     * @param key The raw hex key (32 characters)
     * @return Formatted key with dashes
     */
    static std::string format_recovery_key(const std::string& key);

    /**
     * @brief Removes formatting from a recovery key.
     *
     * Strips dashes and spaces from a formatted key to get the
     * raw hex string.
     *
     * @param key The formatted key
     * @return Raw hex key
     */
    static std::string strip_recovery_key_format(const std::string& key);

private:
    /** @brief Size of recovery key in bytes (128 bits). */
    static constexpr size_t RECOVERY_KEY_BYTES = 16;

    /** @brief Number of groups in formatted key. */
    static constexpr size_t RECOVERY_KEY_GROUPS = 4;

    /** @brief Characters per group in formatted key. */
    static constexpr size_t RECOVERY_KEY_GROUP_SIZE = 4;
};

// =============================================================================
// BackupVersionManager Class
// =============================================================================

/**
 * @class BackupVersionManager
 * @brief Manages backup version history and tagging.
 *
 * This class provides static utilities for tracking backup versions
 * and applying custom tags for organization and identification.
 *
 * Version tracking helps identify:
 * - When each backup was created
 * - What database version it was created from
 * - Custom labels for important backups
 */
class BackupVersionManager {
public:
    /**
     * @brief Gets the version history for a backup directory.
     *
     * Returns a list of all backups with their creation times
     * and database versions.
     *
     * @param backup_dir Directory to scan for backups
     * @return Result containing vector of (filename, version) pairs
     */
    static Result<std::vector<std::pair<std::string, uint32_t>>> get_version_history(
        const std::string& backup_dir);

    /**
     * @brief Applies a custom tag to a backup file.
     *
     * Creates a .tag file alongside the backup containing the tag text.
     * This allows for meaningful labels like "before_migration" or
     * "pre_upgrade".
     *
     * @param backup_file Path to the backup file
     * @param tag The tag text to apply
     * @return Result indicating success or containing an error message
     */
    static Result<void> tag_backup(const std::string& backup_file,
                                   const std::string& tag);

    /**
     * @brief Gets the tag for a backup file.
     *
     * @param backup_file Path to the backup file
     * @return Result containing the tag string on success
     */
    static Result<std::string> get_backup_tag(const std::string& backup_file);

    /**
     * @brief Lists all backups that have tags.
     *
     * @param backup_dir Directory to scan for tagged backups
     * @return Result containing vector of (filename, tag) pairs
     */
    static Result<std::vector<std::pair<std::string, std::string>>> list_tagged_backups(
        const std::string& backup_dir);

private:
    /**
     * @brief Gets the path to the version tracking file.
     *
     * @param backup_dir Backup directory path
     * @return Path to the .versions file
     */
    static std::string get_version_file_path(const std::string& backup_dir);

    /**
     * @brief Saves version information to disk.
     *
     * @param backup_dir Backup directory path
     * @param versions Vector of version information
     * @return Result indicating success or containing an error message
     */
    static Result<void> save_version_info(const std::string& backup_dir,
                                          const std::vector<std::pair<std::string, uint32_t>>& versions);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_BACKUP_MANAGER_H