#ifndef PASSWORD_MANAGER_BACKUP_MANAGER_H
#define PASSWORD_MANAGER_BACKUP_MANAGER_H

#include <string>
#include <vector>
#include <chrono>
#include "types.h"
#include "database.h"

namespace pwdmgr {

// Backup manager for export/import operations
class BackupManager {
public:
    BackupManager(Database& db) : db_(db) {}

    // Export database to encrypted backup file
    Result<void> export_backup(const std::string& output_file);

    // Import from encrypted backup file
    Result<void> import_backup(const std::string& input_file,
                               const std::string& master_password);

    // List available backups in a directory
    Result<std::vector<BackupMetadata>> list_backups(const std::string& directory);

    // Get backup metadata from file
    Result<BackupMetadata> get_backup_metadata(const std::string& backup_file);

    // Restore from backup
    Result<void> restore_backup(const std::string& backup_file,
                                const std::string& master_password,
                                bool force = false);

    // Create automatic backup (with timestamp)
    Result<std::string> create_auto_backup(const std::string& backup_dir);

    // Clean old backups
    Result<int> clean_old_backups(const std::string& backup_dir,
                                  size_t keep_count = 5);

    // Verify backup integrity
    Result<bool> verify_backup(const std::string& backup_file);

    // Get backup directory path
    static std::string get_default_backup_dir();

private:
    Database& db_;

    // Generate backup filename with timestamp
    std::string generate_backup_filename();

    // Extract backup metadata from file
    Result<BackupMetadata> extract_metadata(const std::string& backup_file);

    // Validate backup file format
    Result<bool> validate_format(const std::string& backup_file);
};

// Recovery key generator for emergency access
class RecoveryKeyGenerator {
public:
    // Generate recovery key
    static Result<std::string> generate_recovery_key();

    // Validate recovery key format
    static bool validate_recovery_key(const std::string& key);

    // Format recovery key with dashes
    static std::string format_recovery_key(const std::string& key);

    // Remove formatting from recovery key
    static std::string strip_recovery_key_format(const std::string& key);

private:
    static constexpr size_t RECOVERY_KEY_BYTES = 16; // 128 bits
    static constexpr size_t RECOVERY_KEY_GROUPS = 4;
    static constexpr size_t RECOVERY_KEY_GROUP_SIZE = 4;
};

// Version management for backups
class BackupVersionManager {
public:
    // Get version history
    static Result<std::vector<std::pair<std::string, uint32_t>>> get_version_history(
        const std::string& backup_dir);

    // Tag a backup version
    static Result<void> tag_backup(const std::string& backup_file,
                                   const std::string& tag);

    // Get backup tag
    static Result<std::string> get_backup_tag(const std::string& backup_file);

    // List tagged backups
    static Result<std::vector<std::pair<std::string, std::string>>> list_tagged_backups(
        const std::string& backup_dir);

private:
    // Version file path
    static std::string get_version_file_path(const std::string& backup_dir);

    // Save version info
    static Result<void> save_version_info(const std::string& backup_dir,
                                          const std::vector<std::pair<std::string, uint32_t>>& versions);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_BACKUP_MANAGER_H