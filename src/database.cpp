#include "database.h"
#include "crypt_utils.h"
#include "secure_memory.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cstring>
#include <cstdlib>

namespace pwdmgr {

Database::~Database() {
    close();
}

Result<void> Database::initialize(const std::string& db_path, CryptUtils& crypt_utils) {
    db_path_ = db_path;
    crypt_utils_ = &crypt_utils;

    if (exists(db_path)) {
        return open(db_path, ""); // Will verify master password separately
    }

    return Result<void>::ok();
}

Result<void> Database::open(const std::string& db_path, const std::string& master_password) {
    if (db_) {
        return Result<void>::error("Database already open");
    }

    db_path_ = db_path;

    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        return Result<void>::error("Failed to open database: " + std::string(sqlite3_errmsg(db_)));
    }

    // Set secure mode for SQLite
    sqlite3_busy_timeout(db_, 5000);

    // Check database version
    auto version_result = get_version();
    if (!version_result.success) {
        close();
        return Result<void>::error(version_result.error_message);
    }

    // Check if migration is needed
    if (version_result.value != DATABASE_VERSION) {
        if (DatabaseMigrator::needs_migration(version_result.value)) {
            auto migrate_result = DatabaseMigrator::migrate(*this, version_result.value);
            if (!migrate_result.success) {
                close();
                return Result<void>::error("Database migration failed: " + migrate_result.error_message);
            }
        }
    }

    // Initialize crypt utils with master password if provided
    if (!master_password.empty()) {
        auto master_data = load_master_data();
        if (!master_data.success) {
            close();
            return Result<void>::error("Failed to load master password data");
        }

        auto init_result = crypt_utils_->initialize(master_password, master_data.value.salt);
        if (!init_result.success) {
            close();
            return Result<void>::error(init_result.error_message);
        }
    }

    return Result<void>::ok();
}

Result<void> Database::create(const std::string& db_path, const std::string& master_password) {
    if (exists(db_path)) {
        return Result<void>::error("Database already exists");
    }

    // Generate master password data
    auto master_data = KeyManager::generate_master_data(master_password);
    if (!master_data.success) {
        return Result<void>::error("Failed to generate master password data: " + master_data.error_message);
    }

    // Open database
    int rc = sqlite3_open(db_path.c_str(), &db_);
    if (rc != SQLITE_OK) {
        return Result<void>::error("Failed to create database: " + std::string(sqlite3_errmsg(db_)));
    }

    db_path_ = db_path;

    // Set secure mode
    sqlite3_busy_timeout(db_, 5000);

    // Create schema
    auto schema_result = create_schema();
    if (!schema_result.success) {
        close();
        return Result<void>::error(schema_result.error_message);
    }

    // Save master password data
    auto save_result = save_master_data(master_data.value);
    if (!save_result.success) {
        close();
        return Result<void>::error(save_result.error_message);
    }

    return Result<void>::ok();
}

void Database::close() {
    if (db_) {
        if (in_transaction_) {
            rollback_transaction();
        }
        sqlite3_close(db_);
        db_ = nullptr;
    }
    db_path_.clear();
    crypt_utils_ = nullptr;
}

bool Database::exists(const std::string& db_path) {
    std::ifstream file(db_path);
    return file.good();
}

Result<bool> Database::verify_master_password(const std::string& master_password) {
    auto master_data = load_master_data();
    if (!master_data.success) {
        return Result<bool>::error(master_data.error_message);
    }

    return KeyManager::verify_master_password(master_password, master_data.value);
}

Result<void> Database::change_master_password(const std::string& old_password,
                                               const std::string& new_password) {
    // Verify old password
    auto verify_result = verify_master_password(old_password);
    if (!verify_result.success || !verify_result.value) {
        return Result<void>::error("Invalid master password");
    }

    // Get all entries with their decrypted passwords
    auto entries_result = list_entries();
    if (!entries_result.success) {
        return Result<void>::error(entries_result.error_message);
    }

    std::vector<PasswordEntry> entries = entries_result.value;

    // Decrypt all passwords
    std::vector<std::pair<PasswordEntry, std::string>> decrypted_entries;
    for (auto& entry : entries) {
        auto decrypt_result = decrypt_password(entry.encrypted_password);
        if (!decrypt_result.success) {
            return Result<void>::error("Failed to decrypt entry: " + entry.service_name);
        }
        decrypted_entries.push_back({entry, decrypt_result.value});
    }

    // Delete all entries
    auto delete_result = execute_statement("DELETE FROM password_entries");
    if (!delete_result.success) {
        return Result<void>::error(delete_result.error_message);
    }

    // Generate new master password data
    auto new_master_data = KeyManager::generate_master_data(new_password);
    if (!new_master_data.success) {
        return Result<void>::error("Failed to generate new master password data");
    }

    // Save new master password data
    auto save_result = save_master_data(new_master_data.value);
    if (!save_result.success) {
        return Result<void>::error(save_result.error_message);
    }

    // Re-initialize crypt utils with new password
    if (crypt_utils_) {
        auto init_result = crypt_utils_->initialize(new_password, new_master_data.value.salt);
        if (!init_result.success) {
            return Result<void>::error(init_result.error_message);
        }
    }

    // Re-add all entries with new encryption
    for (auto& [entry, password] : decrypted_entries) {
        entry.encrypted_password = password;
        auto add_result = add_entry(entry);
        if (!add_result.success) {
            return Result<void>::error("Failed to re-encrypt entries: " + add_result.error_message);
        }
        // Securely zero the password
        SecureMemory::secure_zero((void*)password.data(), password.size());
    }

    return Result<void>::ok();
}

Result<int64_t> Database::add_entry(const PasswordEntry& entry) {
    if (!db_) {
        return Result<int64_t>::error("Database not open");
    }

    // Encrypt password
    auto encrypted_pwd = encrypt_password(entry.encrypted_password);
    if (!encrypted_pwd.success) {
        return Result<int64_t>::error(encrypted_pwd.error_message);
    }

    const std::string sql =
        "INSERT INTO password_entries "
        "(service_name, username, encrypted_password, url, notes, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<int64_t>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    int64_t now = time_to_timestamp(std::chrono::system_clock::now());

    sqlite3_bind_text(stmt.get(), 1, entry.service_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, entry.username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, encrypted_pwd.value.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 4, entry.url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 5, entry.notes.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 6, now);
    sqlite3_bind_int64(stmt.get(), 7, now);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        SecureMemory::secure_zero((void*)encrypted_pwd.value.data(), encrypted_pwd.value.size());
        return Result<int64_t>::error("Failed to insert entry: " + std::string(sqlite3_errmsg(db_)));
    }

    int64_t id = sqlite3_last_insert_rowid(db_);

    // Securely zero the encrypted password from memory
    SecureMemory::secure_zero((void*)encrypted_pwd.value.data(), encrypted_pwd.value.size());

    return Result<int64_t>::ok(id);
}

Result<PasswordEntry> Database::get_entry(int64_t id) {
    if (!db_) {
        return Result<PasswordEntry>::error("Database not open");
    }

    const std::string sql = "SELECT id, service_name, username, encrypted_password, url, notes, created_at, updated_at "
                            "FROM password_entries WHERE id = ?";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<PasswordEntry>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;
    sqlite3_bind_int64(stmt.get(), 1, id);

    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
        return Result<PasswordEntry>::error("Entry not found");
    }
    if (rc != SQLITE_ROW) {
        return Result<PasswordEntry>::error("Failed to get entry: " + std::string(sqlite3_errmsg(db_)));
    }

    PasswordEntry entry;
    entry.id = sqlite3_column_int64(stmt.get(), 0);
    entry.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
    entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
    entry.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
    entry.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
    entry.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
    entry.created_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 6));
    entry.updated_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 7));

    return Result<PasswordEntry>::ok(entry);
}

Result<PasswordEntry> Database::get_entry_by_service(const std::string& service_name) {
    if (!db_) {
        return Result<PasswordEntry>::error("Database not open");
    }

    const std::string sql = "SELECT id, service_name, username, encrypted_password, url, notes, created_at, updated_at "
                            "FROM password_entries WHERE service_name = ? LIMIT 1";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<PasswordEntry>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;
    sqlite3_bind_text(stmt.get(), 1, service_name.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt.get());
    if (rc == SQLITE_DONE) {
        return Result<PasswordEntry>::error("Entry not found");
    }
    if (rc != SQLITE_ROW) {
        return Result<PasswordEntry>::error("Failed to get entry: " + std::string(sqlite3_errmsg(db_)));
    }

    PasswordEntry entry;
    entry.id = sqlite3_column_int64(stmt.get(), 0);
    entry.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
    entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
    entry.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
    entry.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
    entry.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
    entry.created_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 6));
    entry.updated_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 7));

    return Result<PasswordEntry>::ok(entry);
}

Result<std::string> Database::get_password_by_service(const std::string& service_name) {
    auto entry_result = get_entry_by_service(service_name);
    if (!entry_result.success) {
        return Result<std::string>::error(entry_result.error_message);
    }

    return decrypt_password(entry_result.value.encrypted_password);
}

Result<void> Database::update_entry(const PasswordEntry& entry) {
    if (!db_) {
        return Result<void>::error("Database not open");
    }

    // Encrypt password
    auto encrypted_pwd = encrypt_password(entry.encrypted_password);
    if (!encrypted_pwd.success) {
        return Result<void>::error(encrypted_pwd.error_message);
    }

    const std::string sql =
        "UPDATE password_entries "
        "SET service_name = ?, username = ?, encrypted_password = ?, url = ?, notes = ?, updated_at = ? "
        "WHERE id = ?";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    int64_t now = time_to_timestamp(std::chrono::system_clock::now());

    sqlite3_bind_text(stmt.get(), 1, entry.service_name.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, entry.username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, encrypted_pwd.value.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 4, entry.url.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 5, entry.notes.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt.get(), 6, now);
    sqlite3_bind_int64(stmt.get(), 7, entry.id);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        SecureMemory::secure_zero((void*)encrypted_pwd.value.data(), encrypted_pwd.value.size());
        return Result<void>::error("Failed to update entry: " + std::string(sqlite3_errmsg(db_)));
    }

    // Securely zero the encrypted password from memory
    SecureMemory::secure_zero((void*)encrypted_pwd.value.data(), encrypted_pwd.value.size());

    return Result<void>::ok();
}

Result<void> Database::delete_entry(int64_t id) {
    if (!db_) {
        return Result<void>::error("Database not open");
    }

    const std::string sql = "DELETE FROM password_entries WHERE id = ?";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;
    sqlite3_bind_int64(stmt.get(), 1, id);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        return Result<void>::error("Failed to delete entry: " + std::string(sqlite3_errmsg(db_)));
    }

    return Result<void>::ok();
}

Result<void> Database::delete_entry_by_service(const std::string& service_name) {
    if (!db_) {
        return Result<void>::error("Database not open");
    }

    const std::string sql = "DELETE FROM password_entries WHERE service_name = ?";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;
    sqlite3_bind_text(stmt.get(), 1, service_name.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        return Result<void>::error("Failed to delete entry: " + std::string(sqlite3_errmsg(db_)));
    }

    return Result<void>::ok();
}

Result<std::vector<PasswordEntry>> Database::list_entries() {
    if (!db_) {
        return Result<std::vector<PasswordEntry>>::error("Database not open");
    }

    const std::string sql = "SELECT id, service_name, username, encrypted_password, url, notes, created_at, updated_at "
                            "FROM password_entries ORDER BY service_name ASC";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<std::vector<PasswordEntry>>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    std::vector<PasswordEntry> entries;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        PasswordEntry entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        entry.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        entry.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        entry.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
        entry.created_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 6));
        entry.updated_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 7));
        entries.push_back(std::move(entry));
    }

    return Result<std::vector<PasswordEntry>>::ok(std::move(entries));
}

Result<std::vector<PasswordEntry>> Database::search_entries(const std::string& pattern) {
    if (!db_) {
        return Result<std::vector<PasswordEntry>>::error("Database not open");
    }

    const std::string sql = "SELECT id, service_name, username, encrypted_password, url, notes, created_at, updated_at "
                            "FROM password_entries "
                            "WHERE service_name LIKE ? OR username LIKE ? OR url LIKE ? "
                            "ORDER BY service_name ASC";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<std::vector<PasswordEntry>>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    std::string search_pattern = "%" + pattern + "%";
    sqlite3_bind_text(stmt.get(), 1, search_pattern.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, search_pattern.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 3, search_pattern.c_str(), -1, SQLITE_STATIC);

    std::vector<PasswordEntry> entries;
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        PasswordEntry entry;
        entry.id = sqlite3_column_int64(stmt.get(), 0);
        entry.service_name = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 1));
        entry.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 2));
        entry.encrypted_password = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 3));
        entry.url = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 4));
        entry.notes = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 5));
        entry.created_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 6));
        entry.updated_at = timestamp_to_time(sqlite3_column_int64(stmt.get(), 7));
        entries.push_back(std::move(entry));
    }

    return Result<std::vector<PasswordEntry>>::ok(std::move(entries));
}

Result<int> Database::get_entry_count() {
    if (!db_) {
        return Result<int>::error("Database not open");
    }

    const std::string sql = "SELECT COUNT(*) FROM password_entries";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<int>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_ROW) {
        return Result<int>::error("Failed to get entry count");
    }

    int count = sqlite3_column_int(stmt.get(), 0);
    return Result<int>::ok(count);
}

Result<uint32_t> Database::get_version() {
    if (!db_) {
        return Result<uint32_t>::error("Database not open");
    }

    // Check if version table exists
    const std::string check_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='meta'";
    auto check_stmt = prepare_statement(check_sql);
    if (!check_stmt.success) {
        return Result<uint32_t>::ok(0); // Assume version 0 if no meta table
    }

    if (sqlite3_step(check_stmt.value.get()) != SQLITE_ROW) {
        return Result<uint32_t>::ok(0);
    }

    // Get version from meta table
    const std::string sql = "SELECT value FROM meta WHERE key = 'database_version'";
    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<uint32_t>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_ROW) {
        return Result<uint32_t>::ok(0);
    }

    uint32_t version = static_cast<uint32_t>(sqlite3_column_int(stmt.get(), 0));
    return Result<uint32_t>::ok(version);
}

Result<void> Database::vacuum() {
    if (!db_) {
        return Result<void>::error("Database not open");
    }

    return execute_statement("VACUUM");
}

Result<void> Database::export_encrypted(const std::string& output_file) {
    if (!db_) {
        return Result<void>::error("Database not open");
    }

    // Read entire database into memory
    std::ifstream file(db_path_, std::ios::binary);
    if (!file) {
        return Result<void>::error("Failed to open database for export");
    }

    std::vector<uint8_t> db_data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    file.close();

    // Create backup metadata
    BackupMetadata metadata;
    auto rand_result = SecureMemory::random_bytes(16);
    if (!rand_result.success) {
        return Result<void>::error(rand_result.error_message);
    }
    metadata.backup_id = Encoding::hex_encode(rand_result.value);
    metadata.original_db_path = db_path_;
    metadata.timestamp = std::chrono::system_clock::now();
    metadata.version = DATABASE_VERSION;

    auto checksum_result = Checksum::compute_sha256(db_data);
    if (!checksum_result.success) {
        return Result<void>::error(checksum_result.error_message);
    }
    metadata.checksum = checksum_result.value;

    // Serialize metadata
    std::ostringstream metadata_stream;
    metadata_stream << "PWDMGR_BACKUP\n"
                    << "VERSION:" << metadata.version << "\n"
                    << "BACKUP_ID:" << metadata.backup_id << "\n"
                    << "TIMESTAMP:" << std::chrono::system_clock::to_time_t(metadata.timestamp) << "\n"
                    << "CHECKSUM:" << metadata.checksum << "\n"
                    << "DATA_START:\n";

    std::string metadata_str = metadata_stream.str();

    // Write to output file
    std::ofstream out(output_file, std::ios::binary);
    if (!out) {
        return Result<void>::error("Failed to create output file");
    }

    out << metadata_str;
    out.write(reinterpret_cast<const char*>(db_data.data()), db_data.size());
    out.close();

    return Result<void>::ok();
}

Result<void> Database::import_encrypted(const std::string& input_file,
                                        const std::string& master_password) {
    // Read input file
    std::ifstream file(input_file, std::ios::binary);
    if (!file) {
        return Result<void>::error("Failed to open backup file");
    }

    // Read and parse metadata
    std::string line;
    BackupMetadata metadata;

    if (!std::getline(file, line) || line != "PWDMGR_BACKUP") {
        return Result<void>::error("Invalid backup file format");
    }

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

    // Read database data
    std::vector<uint8_t> db_data((std::istreambuf_iterator<char>(file)),
                                  std::istreambuf_iterator<char>());
    file.close();

    // Verify checksum
    if (!Checksum::verify_sha256(db_data, metadata.checksum)) {
        return Result<void>::error("Backup file corrupted: checksum mismatch");
    }

    // Verify version compatibility
    if (metadata.version > DATABASE_VERSION) {
        return Result<void>::error("Backup version is newer than current database version");
    }

    // Verify master password against backup
    // For simplicity, we'll import to a temporary database first
    std::string temp_db_path = db_path_ + ".import";

    // Write backup to temporary file
    std::ofstream temp_db(temp_db_path, std::ios::binary);
    if (!temp_db) {
        return Result<void>::error("Failed to create temporary database");
    }
    temp_db.write(reinterpret_cast<const char*>(db_data.data()), db_data.size());
    temp_db.close();

    // Try to open with master password
    Database temp_db_obj;
    auto open_result = temp_db_obj.open(temp_db_path, master_password);
    if (!open_result.success) {
        // Clean up
        std::remove(temp_db_path.c_str());
        return Result<void>::error("Failed to open backup: " + open_result.error_message);
    }

    // Backup current database if it exists
    if (exists(db_path_)) {
        std::string backup_path = db_path_ + ".backup";
        auto export_result = export_encrypted(backup_path);
        if (!export_result.success) {
            temp_db_obj.close();
            std::remove(temp_db_path.c_str());
            return Result<void>::error("Failed to backup current database");
        }
    }

    // Close current database
    close();

    // Move temp database to main database
    if (std::rename(temp_db_path.c_str(), db_path_.c_str()) != 0) {
        // Try copy instead
        std::ifstream src(temp_db_path, std::ios::binary);
        std::ofstream dst(db_path_, std::ios::binary);
        dst << src.rdbuf();
        std::remove(temp_db_path.c_str());
    }

    // Reopen database
    auto reopen_result = open(db_path_, master_password);
    if (!reopen_result.success) {
        return Result<void>::error("Failed to reopen database after import");
    }

    return Result<void>::ok();
}

// Private methods

Result<void> Database::create_schema() {
    // Meta table for database version and other metadata
    const std::string meta_sql =
        "CREATE TABLE IF NOT EXISTS meta ("
        "key TEXT PRIMARY KEY,"
        "value TEXT NOT NULL"
        ")";

    auto meta_result = execute_statement(meta_sql);
    if (!meta_result.success) {
        return Result<void>::error("Failed to create meta table");
    }

    // Insert database version
    const std::string version_sql =
        "INSERT OR REPLACE INTO meta (key, value) VALUES ('database_version', ?)";

    auto stmt_result = prepare_statement(version_sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;
    sqlite3_bind_int(stmt.get(), 1, DATABASE_VERSION);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        return Result<void>::error("Failed to insert database version");
    }

    // Password entries table
    const std::string entries_sql =
        "CREATE TABLE IF NOT EXISTS password_entries ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "service_name TEXT NOT NULL UNIQUE,"
        "username TEXT NOT NULL,"
        "encrypted_password BLOB NOT NULL,"
        "url TEXT,"
        "notes TEXT,"
        "created_at INTEGER NOT NULL,"
        "updated_at INTEGER NOT NULL"
        ")";

    auto entries_result = execute_statement(entries_sql);
    if (!entries_result.success) {
        return Result<void>::error("Failed to create password_entries table");
    }

    // Create indexes for better search performance
    execute_statement("CREATE INDEX IF NOT EXISTS idx_service_name ON password_entries(service_name)");
    execute_statement("CREATE INDEX IF NOT EXISTS idx_username ON password_entries(username)");
    execute_statement("CREATE INDEX IF NOT EXISTS idx_url ON password_entries(url)");

    return Result<void>::ok();
}

Result<Database::SQLiteStmt_Ptr> Database::prepare_statement(const std::string& sql) {
    if (!db_) {
        return Result<SQLiteStmt_Ptr>::error("Database not open");
    }

    sqlite3_stmt* stmt = nullptr;
    int rc = sqlite3_prepare_v2(db_, sql.c_str(), -1, &stmt, nullptr);
    if (rc != SQLITE_OK) {
        return Result<SQLiteStmt_Ptr>::error("Failed to prepare statement: " + std::string(sqlite3_errmsg(db_)));
    }

    return Result<SQLiteStmt_Ptr>::ok(SQLiteStmt_Ptr(stmt));
}

Result<void> Database::execute_statement(const std::string& sql) {
    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    int rc = sqlite3_step(stmt_result.value.get());
    if (rc != SQLITE_DONE && rc != SQLITE_ROW) {
        return Result<void>::error("Failed to execute statement: " + std::string(sqlite3_errmsg(db_)));
    }

    return Result<void>::ok();
}

Result<void> Database::begin_transaction() {
    if (in_transaction_) {
        return Result<void>::error("Transaction already in progress");
    }

    auto result = execute_statement("BEGIN TRANSACTION");
    if (!result.success) {
        return result;
    }

    in_transaction_ = true;
    return Result<void>::ok();
}

Result<void> Database::commit_transaction() {
    if (!in_transaction_) {
        return Result<void>::error("No transaction in progress");
    }

    auto result = execute_statement("COMMIT");
    if (!result.success) {
        rollback_transaction();
        return result;
    }

    in_transaction_ = false;
    return Result<void>::ok();
}

void Database::rollback_transaction() {
    if (in_transaction_) {
        execute_statement("ROLLBACK");
        in_transaction_ = false;
    }
}

int64_t Database::time_to_timestamp(const std::chrono::system_clock::time_point& tp) {
    return std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
}

std::chrono::system_clock::time_point Database::timestamp_to_time(int64_t ts) {
    return std::chrono::system_clock::time_point(std::chrono::seconds(ts));
}

Result<MasterPasswordData> Database::load_master_data() {
    const std::string sql = "SELECT value FROM meta WHERE key = ?";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<MasterPasswordData>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    MasterPasswordData data;

    // Load salt
    sqlite3_bind_text(stmt.get(), 1, "master_salt", -1, SQLITE_STATIC);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const char* salt_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        auto salt_result = Encoding::hex_decode(salt_hex);
        if (!salt_result.success) {
            return Result<MasterPasswordData>::error("Failed to decode salt");
        }
        data.salt = salt_result.value;
    }
    sqlite3_reset(stmt.get());

    // Load verification hash
    sqlite3_bind_text(stmt.get(), 1, "master_hash", -1, SQLITE_STATIC);
    if (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const char* hash_hex = reinterpret_cast<const char*>(sqlite3_column_text(stmt.get(), 0));
        auto hash_result = Encoding::hex_decode(hash_hex);
        if (!hash_result.success) {
            return Result<MasterPasswordData>::error("Failed to decode verification hash");
        }
        data.verification_hash = hash_result.value;
    }

    return Result<MasterPasswordData>::ok(std::move(data));
}

Result<void> Database::save_master_data(const MasterPasswordData& data) {
    const std::string sql = "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)";

    auto stmt_result = prepare_statement(sql);
    if (!stmt_result.success) {
        return Result<void>::error(stmt_result.error_message);
    }

    SQLiteStmt_Ptr& stmt = stmt_result.value;

    // Save salt
    std::string salt_hex = Encoding::hex_encode(data.salt);
    sqlite3_bind_text(stmt.get(), 1, "master_salt", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, salt_hex.c_str(), -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        return Result<void>::error("Failed to save salt");
    }
    sqlite3_reset(stmt.get());

    // Save verification hash
    std::string hash_hex = Encoding::hex_encode(data.verification_hash);
    sqlite3_bind_text(stmt.get(), 1, "master_hash", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt.get(), 2, hash_hex.c_str(), -1, SQLITE_STATIC);

    rc = sqlite3_step(stmt.get());
    if (rc != SQLITE_DONE) {
        return Result<void>::error("Failed to save verification hash");
    }

    return Result<void>::ok();
}

Result<std::string> Database::decrypt_password(const std::string& encrypted_password) {
    if (!crypt_utils_) {
        return Result<std::string>::error("CryptUtils not initialized");
    }

    // Parse encrypted password format: base64(iv:tag:ciphertext)
    auto decoded = Encoding::base64_decode(encrypted_password);
    if (!decoded.success) {
        return Result<std::string>::error("Failed to decode encrypted password");
    }

    const std::vector<uint8_t>& data = decoded.value;

    // Extract IV, tag, and ciphertext
    if (data.size() < AES_IV_SIZE + AES_TAG_SIZE) {
        return Result<std::string>::error("Invalid encrypted password format");
    }

    std::vector<uint8_t> iv(data.begin(), data.begin() + AES_IV_SIZE);
    std::vector<uint8_t> tag(data.begin() + AES_IV_SIZE, data.begin() + AES_IV_SIZE + AES_TAG_SIZE);
    std::vector<uint8_t> ciphertext(data.begin() + AES_IV_SIZE + AES_TAG_SIZE, data.end());

    EncryptedData encrypted;
    encrypted.iv = iv;
    encrypted.tag = tag;
    encrypted.ciphertext = ciphertext;

    return crypt_utils_->decrypt(encrypted);
}

Result<std::string> Database::encrypt_password(const std::string& password) {
    if (!crypt_utils_) {
        return Result<std::string>::error("CryptUtils not initialized");
    }

    auto encrypted = crypt_utils_->encrypt(password);
    if (!encrypted.success) {
        return Result<std::string>::error(encrypted.error_message);
    }

    // Combine IV, tag, and ciphertext
    std::vector<uint8_t> combined;
    combined.reserve(AES_IV_SIZE + AES_TAG_SIZE + encrypted.value.ciphertext.size());
    combined.insert(combined.end(), encrypted.value.iv.begin(), encrypted.value.iv.end());
    combined.insert(combined.end(), encrypted.value.tag.begin(), encrypted.value.tag.end());
    combined.insert(combined.end(), encrypted.value.ciphertext.begin(), encrypted.value.ciphertext.end());

    // Encode to base64
    std::string encoded = Encoding::base64_encode(combined);

    // Securely clear sensitive data
    SecureMemory::secure_zero(encrypted.value.iv.data(), encrypted.value.iv.size());
    SecureMemory::secure_zero(encrypted.value.tag.data(), encrypted.value.tag.size());
    SecureMemory::secure_zero(encrypted.value.ciphertext.data(), encrypted.value.ciphertext.size());
    SecureMemory::secure_zero(combined.data(), combined.size());

    return Result<std::string>::ok(encoded);
}

void Database::secure_cleanup() {
    if (db_) {
        close();
    }
}

// DatabaseMigrator implementation

bool DatabaseMigrator::needs_migration(uint32_t current_version) {
    return current_version < DATABASE_VERSION;
}

Result<void> DatabaseMigrator::migrate(Database& db, uint32_t current_version) {
    switch (current_version) {
        case 0:
            return migrate_to_v1(db);
        default:
            return Result<void>::error("Unsupported database version");
    }
}

Result<void> DatabaseMigrator::migrate_to_v1(Database& db) {
    // This is the initial schema creation
    // It's handled by Database::create_schema()
    return Result<void>::ok();
}

} // namespace pwdmgr