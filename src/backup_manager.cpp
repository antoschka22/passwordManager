#include "backup_manager.h"
#include "crypt_utils.h"
#include "secure_memory.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <ctime>

namespace pwdmgr {

namespace fs = std::filesystem;

// BackupManager implementation

Result<void> BackupManager::export_backup(const std::string& output_file) {
    return db_.export_encrypted(output_file);
}

Result<void> BackupManager::import_backup(const std::string& input_file,
                                           const std::string& master_password) {
    return db_.import_encrypted(input_file, master_password);
}

Result<std::vector<BackupMetadata>> BackupManager::list_backups(const std::string& directory) {
    if (!fs::exists(directory)) {
        return Result<std::vector<BackupMetadata>>::error("Backup directory does not exist");
    }

    std::vector<BackupMetadata> backups;

    try {
        for (const auto& entry : fs::directory_iterator(directory)) {
            if (entry.is_regular_file()) {
                auto metadata_result = get_backup_metadata(entry.path().string());
                if (metadata_result.success) {
                    backups.push_back(metadata_result.value);
                }
            }
        }
    } catch (const fs::filesystem_error& e) {
        return Result<std::vector<BackupMetadata>>::error(e.what());
    }

    // Sort by timestamp (newest first)
    std::sort(backups.begin(), backups.end(),
              [](const BackupMetadata& a, const BackupMetadata& b) {
                  return a.timestamp > b.timestamp;
              });

    return Result<std::vector<BackupMetadata>>::ok(std::move(backups));
}

Result<BackupMetadata> BackupManager::get_backup_metadata(const std::string& backup_file) {
    return extract_metadata(backup_file);
}

Result<void> BackupManager::restore_backup(const std::string& backup_file,
                                           const std::string& master_password,
                                           bool force) {
    if (!force) {
        auto verify_result = verify_backup(backup_file);
        if (!verify_result.success || !verify_result.value) {
            return Result<void>::error("Backup verification failed");
        }
    }

    return db_.import_encrypted(backup_file, master_password);
}

Result<std::string> BackupManager::create_auto_backup(const std::string& backup_dir) {
    // Create backup directory if it doesn't exist
    if (!fs::exists(backup_dir)) {
        try {
            fs::create_directories(backup_dir);
        } catch (const fs::filesystem_error& e) {
            return Result<std::string>::error(e.what());
        }
    }

    // Generate backup filename
    std::string backup_file = backup_dir + "/" + generate_backup_filename();

    // Export backup
    auto export_result = export_backup(backup_file);
    if (!export_result.success) {
        return Result<std::string>::error(export_result.error_message);
    }

    // Update version history
    auto metadata_result = get_backup_metadata(backup_file);
    if (metadata_result.success) {
        BackupVersionManager::get_version_history(backup_dir); // This will create/update version file
    }

    return Result<std::string>::ok(backup_file);
}

Result<int> BackupManager::clean_old_backups(const std::string& backup_dir,
                                              size_t keep_count) {
    auto backups_result = list_backups(backup_dir);
    if (!backups_result.success) {
        return Result<int>::error(backups_result.error_message);
    }

    auto backups = backups_result.value;
    int deleted_count = 0;

    // Keep only the most recent backups
    for (size_t i = keep_count; i < backups.size(); ++i) {
        try {
            if (fs::remove(backups[i].original_db_path)) {
                deleted_count++;
            }
        } catch (const fs::filesystem_error& e) {
            // Continue with next backup
        }
    }

    return Result<int>::ok(deleted_count);
}

Result<bool> BackupManager::verify_backup(const std::string& backup_file) {
    // Check if file exists
    if (!fs::exists(backup_file)) {
        return Result<bool>::error("Backup file does not exist");
    }

    // Verify format
    auto format_result = validate_format(backup_file);
    if (!format_result.success || !format_result.value) {
        return Result<bool>::error("Invalid backup format");
    }

    // Extract and verify metadata
    auto metadata_result = extract_metadata(backup_file);
    if (!metadata_result.success) {
        return Result<bool>::error(metadata_result.error_message);
    }

    const auto& metadata = metadata_result.value;

    // Verify checksum
    std::ifstream file(backup_file, std::ios::binary);
    if (!file) {
        return Result<bool>::error("Failed to open backup file");
    }

    // Skip to data section
    std::string line;
    bool found_data_start = false;
    while (std::getline(file, line)) {
        if (line == "DATA_START:") {
            found_data_start = true;
            break;
        }
    }

    if (!found_data_start) {
        return Result<bool>::error("Invalid backup file: missing data section");
    }

    // Read database data
    std::streampos data_start = file.tellg();
    file.seekg(0, std::ios::end);
    std::streampos file_end = file.tellg();
    size_t data_size = file_end - data_start;

    file.seekg(data_start);
    std::vector<uint8_t> db_data(data_size);
    file.read(reinterpret_cast<char*>(db_data.data()), data_size);
    file.close();

    // Verify checksum
    bool checksum_valid = Checksum::verify_sha256(db_data, metadata.checksum);

    // Securely zero the data
    SecureMemory::secure_zero(db_data.data(), db_data.size());

    return Result<bool>::ok(checksum_valid);
}

std::string BackupManager::get_default_backup_dir() {
    // Use ~/.pwdmgr/backups as default
    const char* home = std::getenv("HOME");
    if (!home) {
        return "/tmp/pwdmgr_backups";
    }
    return std::string(home) + "/.pwdmgr/backups";
}

std::string BackupManager::generate_backup_filename() {
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);

    std::ostringstream oss;
    oss << "pwdmgr_backup_";

    // Format: YYYYMMDD_HHMMSS
    char time_str[20];
    std::strftime(time_str, sizeof(time_str), "%Y%m%d_%H%M%S", std::localtime(&time_t));
    oss << time_str;

    oss << ".pwdb";

    return oss.str();
}

Result<BackupMetadata> BackupManager::extract_metadata(const std::string& backup_file) {
    std::ifstream file(backup_file);
    if (!file) {
        return Result<BackupMetadata>::error("Failed to open backup file");
    }

    std::string line;
    BackupMetadata metadata;

    // Verify header
    if (!std::getline(file, line) || line != "PWDMGR_BACKUP") {
        return Result<BackupMetadata>::error("Invalid backup file format");
    }

    metadata.original_db_path = backup_file;

    // Parse metadata
    while (std::getline(file, line) && line != "DATA_START:") {
        size_t pos = line.find(':');
        if (pos == std::string::npos) continue;

        std::string key = line.substr(0, pos);
        std::string value = line.substr(pos + 1);

        if (key == "VERSION") {
            metadata.version = std::stoul(value);
        } else if (key == "BACKUP_ID") {
            metadata.backup_id = value;
        } else if (key == "TIMESTAMP") {
            metadata.timestamp = std::chrono::system_clock::from_time_t(std::stoll(value));
        } else if (key == "CHECKSUM") {
            metadata.checksum = value;
        }
    }

    return Result<BackupMetadata>::ok(std::move(metadata));
}

Result<bool> BackupManager::validate_format(const std::string& backup_file) {
    std::ifstream file(backup_file);
    if (!file) {
        return Result<bool>::error("Failed to open backup file");
    }

    std::string line;
    if (!std::getline(file, line) || line != "PWDMGR_BACKUP") {
        return Result<bool>::ok(false);
    }

    // Check for required fields
    bool has_version = false;
    bool has_backup_id = false;
    bool has_timestamp = false;
    bool has_checksum = false;
    bool has_data_start = false;

    while (std::getline(file, line)) {
        if (line == "DATA_START:") {
            has_data_start = true;
            break;
        }

        size_t pos = line.find(':');
        if (pos != std::string::npos) {
            std::string key = line.substr(0, pos);
            if (key == "VERSION") has_version = true;
            else if (key == "BACKUP_ID") has_backup_id = true;
            else if (key == "TIMESTAMP") has_timestamp = true;
            else if (key == "CHECKSUM") has_checksum = true;
        }
    }

    return Result<bool>::ok(has_version && has_backup_id && has_timestamp &&
                            has_checksum && has_data_start);
}

// RecoveryKeyGenerator implementation

Result<std::string> RecoveryKeyGenerator::generate_recovery_key() {
    auto random_result = SecureMemory::random_bytes(RECOVERY_KEY_BYTES);
    if (!random_result.success) {
        return Result<std::string>::error("Failed to generate recovery key");
    }

    const std::vector<uint8_t>& random_bytes = random_result.value;

    // Convert to hex string
    std::string hex_key = Encoding::hex_encode(random_bytes);

    // Securely zero the random bytes
    SecureMemory::secure_zero((void*)random_bytes.data(), random_bytes.size());

    return Result<std::string>::ok(format_recovery_key(hex_key));
}

bool RecoveryKeyGenerator::validate_recovery_key(const std::string& key) {
    std::string stripped = strip_recovery_key_format(key);

    // Check length (should be RECOVERY_KEY_BYTES * 2 hex chars)
    if (stripped.length() != RECOVERY_KEY_BYTES * 2) {
        return false;
    }

    // Check if all characters are valid hex
    for (char c : stripped) {
        if (!std::isxdigit(c)) {
            return false;
        }
    }

    return true;
}

std::string RecoveryKeyGenerator::format_recovery_key(const std::string& key) {
    std::string formatted;
    size_t group_count = 0;

    for (size_t i = 0; i < key.length(); ++i) {
        if (i > 0 && i % RECOVERY_KEY_GROUP_SIZE == 0 && group_count < RECOVERY_KEY_GROUPS - 1) {
            formatted += '-';
            group_count++;
        }
        formatted += key[i];
    }

    return formatted;
}

std::string RecoveryKeyGenerator::strip_recovery_key_format(const std::string& key) {
    std::string stripped;
    stripped.reserve(key.length());

    for (char c : key) {
        if (c != '-' && c != ' ') {
            stripped += c;
        }
    }

    return stripped;
}

// BackupVersionManager implementation

Result<std::vector<std::pair<std::string, uint32_t>>> BackupVersionManager::get_version_history(
    const std::string& backup_dir) {
    std::string version_file = get_version_file_path(backup_dir);

    std::vector<std::pair<std::string, uint32_t>> versions;

    if (!fs::exists(version_file)) {
        return Result<std::vector<std::pair<std::string, uint32_t>>>::ok(versions);
    }

    std::ifstream file(version_file);
    if (!file) {
        return Result<std::vector<std::pair<std::string, uint32_t>>>::error("Failed to read version file");
    }

    std::string line;
    while (std::getline(file, line)) {
        size_t pos = line.find('|');
        if (pos != std::string::npos) {
            std::string backup_file = line.substr(0, pos);
            std::string version_str = line.substr(pos + 1);
            uint32_t version = std::stoul(version_str);
            versions.push_back({backup_file, version});
        }
    }

    return Result<std::vector<std::pair<std::string, uint32_t>>>::ok(std::move(versions));
}

Result<void> BackupVersionManager::tag_backup(const std::string& backup_file,
                                               const std::string& tag) {
    // Store tag in a separate file
    std::string tag_file = backup_file + ".tag";
    std::ofstream file(tag_file);
    if (!file) {
        return Result<void>::error("Failed to create tag file");
    }

    file << tag;
    file.close();

    return Result<void>::ok();
}

Result<std::string> BackupVersionManager::get_backup_tag(const std::string& backup_file) {
    std::string tag_file = backup_file + ".tag";

    if (!fs::exists(tag_file)) {
        return Result<std::string>::error("No tag found for this backup");
    }

    std::ifstream file(tag_file);
    if (!file) {
        return Result<std::string>::error("Failed to read tag file");
    }

    std::string tag;
    std::getline(file, tag);
    file.close();

    return Result<std::string>::ok(tag);
}

Result<std::vector<std::pair<std::string, std::string>>> BackupVersionManager::list_tagged_backups(
    const std::string& backup_dir) {
    std::vector<std::pair<std::string, std::string>> tagged_backups;

    try {
        for (const auto& entry : fs::directory_iterator(backup_dir)) {
            if (entry.is_regular_file() && entry.path().extension() == ".tag") {
                std::string backup_file = entry.path().stem().string();
                auto tag_result = get_backup_tag(backup_file);
                if (tag_result.success) {
                    tagged_backups.push_back({backup_file, tag_result.value});
                }
            }
        }
    } catch (const fs::filesystem_error& e) {
        return Result<std::vector<std::pair<std::string, std::string>>>::error(e.what());
    }

    return Result<std::vector<std::pair<std::string, std::string>>>::ok(std::move(tagged_backups));
}

std::string BackupVersionManager::get_version_file_path(const std::string& backup_dir) {
    return backup_dir + "/.versions";
}

Result<void> BackupVersionManager::save_version_info(
    const std::string& backup_dir,
    const std::vector<std::pair<std::string, uint32_t>>& versions) {
    std::string version_file = get_version_file_path(backup_dir);

    std::ofstream file(version_file);
    if (!file) {
        return Result<void>::error("Failed to create version file");
    }

    for (const auto& [backup_file, version] : versions) {
        file << backup_file << "|" << version << "\n";
    }

    file.close();

    return Result<void>::ok();
}

} // namespace pwdmgr