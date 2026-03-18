#include <iostream>
#include <memory>
#include <cstdlib>
#include <filesystem>
#include <cstdlib>

#include "types.h"
#include "cli_utils.h"
#include "crypt_utils.h"
#include "database.h"
#include "password_generator.h"
#include "backup_manager.h"
#include "secure_memory.h"

namespace pwdmgr {
namespace fs = std::filesystem;

// Application class to manage the password manager
class PasswordManagerApp {
public:
    PasswordManagerApp(int argc, char* argv[])
        : parser_(argc, argv) {}

    int run() {
        // Parse command line arguments
        auto options_result = parser_.parse();
        if (!options_result.success) {
            CliUtils::error(options_result.error_message);
            return EXIT_FAILURE;
        }

        options_ = std::move(options_result.value);

        // Handle commands that don't require database
        if (options_.command == Command::VERSION) {
            CliUtils::display_version();
            return EXIT_SUCCESS;
        }

        if (options_.command == Command::HELP) {
            CliUtils::display_help();
            return EXIT_SUCCESS;
        }

        if (options_.command == Command::GENERATE) {
            return handle_generate();
        }

        // Get database path
        std::string db_path = get_db_path();

        // Initialize database if needed
        auto init_result = init_database(db_path);
        if (!init_result.success) {
            CliUtils::error(init_result.error_message);
            return EXIT_FAILURE;
        }

        // Handle database-dependent commands
        switch (options_.command) {
            case Command::INIT:
                return handle_init();
            case Command::ADD:
                return handle_add();
            case Command::GET:
                return handle_get();
            case Command::LIST:
                return handle_list();
            case Command::SEARCH:
                return handle_search();
            case Command::UPDATE:
                return handle_update();
            case Command::DELETE:
                return handle_delete();
            case Command::EXPORT:
                return handle_export();
            case Command::IMPORT:
                return handle_import();
            case Command::BACKUP:
                return handle_backup();
            case Command::RESTORE:
                return handle_restore();
            case Command::CHANGE_MASTER:
                return handle_change_master();
            default:
                CliUtils::display_help();
                return EXIT_SUCCESS;
        }
    }

private:
    CommandLineParser parser_;
    CliOptions options_;
    std::unique_ptr<Database> db_;
    std::unique_ptr<CryptUtils> crypt_utils_;
    std::string master_password_;

    // Get database path from environment or default
    std::string get_db_path() {
        const char* db_env = std::getenv("PWDMGR_DB");
        if (db_env) {
            return db_env;
        }

        // Check for --db option in remaining args
        for (size_t i = 0; i < parser_.get_remaining_args().size(); ++i) {
            if (parser_.get_remaining_args()[i] == "--db" &&
                i + 1 < parser_.get_remaining_args().size()) {
                return parser_.get_remaining_args()[i + 1];
            }
        }

        // Use default path
        const char* home = std::getenv("HOME");
        if (!home) {
            home = "/tmp";
        }

        std::string db_dir = std::string(home) + "/.pwdmgr";
        if (!fs::exists(db_dir)) {
            try {
                fs::create_directories(db_dir);
            } catch (const fs::filesystem_error& e) {
                CliUtils::error(std::string("Failed to create database directory: ") + e.what());
                return "/tmp/pwdmgr.db";
            }
        }

        return db_dir + "/passwords.db";
    }

    // Initialize database
    Result<void> init_database(const std::string& db_path) {
        db_ = std::make_unique<Database>();
        crypt_utils_ = std::make_unique<CryptUtils>();

        if (Database::exists(db_path)) {
            // Open existing database
            auto open_result = db_->open(db_path, "");
            if (!open_result.success) {
                return Result<void>::error(open_result.error_message);
            }

            return Result<void>::ok();
        }

        // Database doesn't exist yet
        return Result<void>::ok();
    }

    // Authenticate user
    Result<void> authenticate() {
        auto password_result = CliUtils::get_password("Master password: ");
        if (!password_result.success) {
            return Result<void>::error(password_result.error_message);
        }

        master_password_ = password_result.value;

        auto verify_result = db_->verify_master_password(master_password_);
        if (!verify_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            return Result<void>::error(verify_result.error_message);
        }

        if (!verify_result.value) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            return Result<void>::error("Invalid master password");
        }

        // Initialize crypt utils
        auto master_data = KeyManager::generate_master_data(master_password_);
        auto init_result = crypt_utils_->initialize(master_password_, master_data.value.salt);
        if (!init_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            return Result<void>::error(init_result.error_message);
        }

        // Re-open database with password
        db_->close();
        auto open_result = db_->open(db_->get_path(), master_password_);
        if (!open_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            return Result<void>::error(open_result.error_message);
        }

        return Result<void>::ok();
    }

    // Handle init command
    int handle_init() {
        std::string db_path = db_->get_path();

        if (Database::exists(db_path)) {
            if (!options_.force) {
                if (!CliUtils::confirm_action("Database already exists. Reinitialize?", false)) {
                    CliUtils::info("Operation cancelled.");
                    return EXIT_SUCCESS;
                }
            }
            fs::remove(db_path);
        }

        // Get new master password
        auto password_result = CliUtils::get_password_with_confirmation(
            "Enter new master password: ",
            "Confirm master password: ");

        if (!password_result.success) {
            CliUtils::error(password_result.error_message);
            return EXIT_FAILURE;
        }

        master_password_ = password_result.value;

        // Create database
        auto create_result = db_->create(db_path, master_password_);
        if (!create_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            CliUtils::error(create_result.error_message);
            return EXIT_FAILURE;
        }

        // Initialize crypt utils
        auto master_data = KeyManager::generate_master_data(master_password_);
        auto init_result = crypt_utils_->initialize(master_password_, master_data.value.salt);
        if (!init_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            CliUtils::error(init_result.error_message);
            return EXIT_FAILURE;
        }

        SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
        SecureMemory::secure_zero((void*)master_data.value.salt.data(), master_data.value.salt.size());
        SecureMemory::secure_zero((void*)master_data.value.verification_hash.data(),
                                   master_data.value.verification_hash.size());

        CliUtils::success("Database initialized successfully!");
        return EXIT_SUCCESS;
    }

    // Handle add command
    int handle_add() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        // Get service name
        auto service_result = CliUtils::get_input("Service name");
        if (!service_result.success) {
            cleanup_auth();
            return EXIT_FAILURE;
        }

        // Check if service already exists
        auto existing_result = db_->get_entry_by_service(service_result.value);
        if (existing_result.success) {
            if (!options_.force) {
                if (!CliUtils::confirm_action("Service already exists. Overwrite?", false)) {
                    cleanup_auth();
                    return EXIT_SUCCESS;
                }
            }
        }

        // Get username
        auto username_result = CliUtils::get_input("Username");
        if (!username_result.success) {
            cleanup_auth();
            return EXIT_FAILURE;
        }

        // Get password (optionally generate)
        std::string password;
        if (options_.password.empty()) {
            auto gen_confirm = CliUtils::confirm_action("Generate random password?", true);
            if (gen_confirm) {
                auto gen_result = PasswordGenerator::generate(options_.generator_opts);
                if (!gen_result.success) {
                    cleanup_auth();
                    CliUtils::error(gen_result.error_message);
                    return EXIT_FAILURE;
                }
                password = gen_result.value;
                std::cout << "Generated password: " << password << std::endl;
                CliUtils::display_password_strength(password);
            } else {
                auto pwd_result = CliUtils::get_password("Password: ");
                if (!pwd_result.success) {
                    cleanup_auth();
                    return EXIT_FAILURE;
                }
                password = pwd_result.value;
                CliUtils::display_password_strength(password);
            }
        } else {
            password = options_.password;
        }

        // Get optional fields
        auto url_result = CliUtils::get_input("URL", true);
        auto notes_result = CliUtils::get_input("Notes", true);

        // Create entry
        PasswordEntry entry;
        entry.service_name = service_result.value;
        entry.username = username_result.value;
        entry.encrypted_password = password;
        entry.url = url_result.success ? url_result.value : "";
        entry.notes = notes_result.success ? notes_result.value : "";

        // Add to database
        auto add_result = db_->add_entry(entry);
        if (!add_result.success) {
            SecureMemory::secure_zero((void*)password.data(), password.size());
            cleanup_auth();
            CliUtils::error(add_result.error_message);
            return EXIT_FAILURE;
        }

        SecureMemory::secure_zero((void*)password.data(), password.size());
        cleanup_auth();
        CliUtils::success("Password entry added successfully!");
        return EXIT_SUCCESS;
    }

    // Handle get command
    int handle_get() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        if (options_.service.empty()) {
            auto service_result = CliUtils::get_input("Service name");
            if (!service_result.success) {
                cleanup_auth();
                return EXIT_FAILURE;
            }
            options_.service = service_result.value;
        }

        // Get entry
        auto entry_result = db_->get_entry_by_service(options_.service);
        if (!entry_result.success) {
            cleanup_auth();
            CliUtils::error(entry_result.error_message);
            return EXIT_FAILURE;
        }

        // Decrypt password
        auto password_result = db_->get_password_by_service(options_.service);
        if (!password_result.success) {
            cleanup_auth();
            CliUtils::error(password_result.error_message);
            return EXIT_FAILURE;
        }

        const auto& entry = entry_result.value;
        const std::string& password = password_result.value;

        if (options_.show_password) {
            // Display full entry with password
            CliUtils::display_entry(entry, true);
        } else {
            // Copy to clipboard
            auto copy_result = CliUtils::copy_to_clipboard(password);
            if (!copy_result.success) {
                SecureMemory::secure_zero((void*)password.data(), password.size());
                cleanup_auth();
                CliUtils::error(copy_result.error_message);
                return EXIT_FAILURE;
            }

            std::cout << "Password for '" << entry.service_name << "' copied to clipboard." << std::endl;
            std::cout << "Username: " << entry.username << std::endl;
            if (!entry.url.empty()) {
                std::cout << "URL: " << entry.url << std::endl;
            }
        }

        // Securely zero the password
        SecureMemory::secure_zero((void*)password.data(), password.size());
        cleanup_auth();
        return EXIT_SUCCESS;
    }

    // Handle list command
    int handle_list() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        auto entries_result = db_->list_entries();
        if (!entries_result.success) {
            cleanup_auth();
            CliUtils::error(entries_result.error_message);
            return EXIT_FAILURE;
        }

        CliUtils::display_entries(entries_result.value);
        cleanup_auth();
        return EXIT_SUCCESS;
    }

    // Handle search command
    int handle_search() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        if (options_.pattern.empty()) {
            auto pattern_result = CliUtils::get_input("Search pattern");
            if (!pattern_result.success) {
                cleanup_auth();
                return EXIT_FAILURE;
            }
            options_.pattern = pattern_result.value;
        }

        auto entries_result = db_->search_entries(options_.pattern);
        if (!entries_result.success) {
            cleanup_auth();
            CliUtils::error(entries_result.error_message);
            return EXIT_FAILURE;
        }

        if (entries_result.value.empty()) {
            CliUtils::info("No matching entries found.");
        } else {
            std::cout << "Found " << entries_result.value.size() << " matching entries:" << std::endl;
            CliUtils::display_entries(entries_result.value);
        }

        cleanup_auth();
        return EXIT_SUCCESS;
    }

    // Handle update command
    int handle_update() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        if (options_.service.empty()) {
            auto service_result = CliUtils::get_input("Service name to update");
            if (!service_result.success) {
                cleanup_auth();
                return EXIT_FAILURE;
            }
            options_.service = service_result.value;
        }

        // Get existing entry
        auto entry_result = db_->get_entry_by_service(options_.service);
        if (!entry_result.success) {
            cleanup_auth();
            CliUtils::error(entry_result.error_message);
            return EXIT_FAILURE;
        }

        PasswordEntry entry = entry_result.value;

        // Update fields
        if (!options_.username.empty()) {
            entry.username = options_.username;
        } else {
            auto result = CliUtils::get_input_with_default("Username", entry.username);
            if (result.success) {
                entry.username = result.value;
            }
        }

        if (!options_.password.empty()) {
            entry.encrypted_password = options_.password;
        } else {
            auto update_pwd = CliUtils::confirm_action("Update password?", false);
            if (update_pwd) {
                auto pwd_result = CliUtils::get_password("New password: ");
                if (pwd_result.success) {
                    entry.encrypted_password = pwd_result.value;
                }
            }
        }

        if (!options_.url.empty()) {
            entry.url = options_.url;
        } else {
            auto result = CliUtils::get_input_with_default("URL", entry.url);
            if (result.success && !result.value.empty()) {
                entry.url = result.value;
            }
        }

        if (!options_.notes.empty()) {
            entry.notes = options_.notes;
        } else {
            auto result = CliUtils::get_input_with_default("Notes", entry.notes);
            if (result.success && !result.value.empty()) {
                entry.notes = result.value;
            }
        }

        // Update entry
        auto update_result = db_->update_entry(entry);
        if (!update_result.success) {
            cleanup_auth();
            CliUtils::error(update_result.error_message);
            return EXIT_FAILURE;
        }

        cleanup_auth();
        CliUtils::success("Password entry updated successfully!");
        return EXIT_SUCCESS;
    }

    // Handle delete command
    int handle_delete() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        if (options_.service.empty()) {
            auto service_result = CliUtils::get_input("Service name to delete");
            if (!service_result.success) {
                cleanup_auth();
                return EXIT_FAILURE;
            }
            options_.service = service_result.value;
        }

        // Show entry to confirm
        auto entry_result = db_->get_entry_by_service(options_.service);
        if (!entry_result.success) {
            cleanup_auth();
            CliUtils::error(entry_result.error_message);
            return EXIT_FAILURE;
        }

        CliUtils::display_entry(entry_result.value, false);

        if (!options_.force) {
            if (!CliUtils::confirm_action("Delete this entry?", false)) {
                cleanup_auth();
                CliUtils::info("Operation cancelled.");
                return EXIT_SUCCESS;
            }
        }

        // Delete entry
        auto delete_result = db_->delete_entry_by_service(options_.service);
        if (!delete_result.success) {
            cleanup_auth();
            CliUtils::error(delete_result.error_message);
            return EXIT_FAILURE;
        }

        cleanup_auth();
        CliUtils::success("Password entry deleted successfully!");
        return EXIT_SUCCESS;
    }

    // Handle generate command
    int handle_generate() {
        // Display generated password
        auto gen_result = PasswordGenerator::generate(options_.generator_opts);
        if (!gen_result.success) {
            CliUtils::error(gen_result.error_message);
            return EXIT_FAILURE;
        }

        const std::string& password = gen_result.value;

        CliUtils::print_header("Generated Password");
        std::cout << ColorOutput::colorize("Password:", Color::Cyan) << "  " << password << std::endl;
        CliUtils::display_password_strength(password);

        // Ask to copy to clipboard
        if (CliUtils::confirm_action("Copy to clipboard?", true)) {
            auto copy_result = CliUtils::copy_to_clipboard(password);
            if (!copy_result.success) {
                CliUtils::warning("Failed to copy to clipboard: " + copy_result.error_message);
            } else {
                CliUtils::success("Password copied to clipboard!");
            }
        }

        // Securely zero the password
        SecureMemory::secure_zero((void*)password.data(), password.size());
        return EXIT_SUCCESS;
    }

    // Handle export command
    int handle_export() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        std::string output_file;
        if (options_.output_file.empty()) {
            auto result = CliUtils::get_input("Output file path");
            if (!result.success) {
                cleanup_auth();
                return EXIT_FAILURE;
            }
            output_file = result.value;
        } else {
            output_file = options_.output_file;
        }

        BackupManager backup_manager(*db_);
        auto export_result = backup_manager.export_backup(output_file);
        if (!export_result.success) {
            cleanup_auth();
            CliUtils::error(export_result.error_message);
            return EXIT_FAILURE;
        }

        cleanup_auth();
        CliUtils::success("Backup exported successfully to: " + output_file);
        return EXIT_SUCCESS;
    }

    // Handle import command
    int handle_import() {
        if (options_.input_file.empty()) {
            auto result = CliUtils::get_input("Backup file path");
            if (!result.success) {
                return EXIT_FAILURE;
            }
            options_.input_file = result.value;
        }

        // Get master password for the backup
        auto password_result = CliUtils::get_password("Backup master password: ");
        if (!password_result.success) {
            return EXIT_FAILURE;
        }

        master_password_ = password_result.value;

        // Verify the backup can be opened
        std::string temp_db = db_->get_path() + ".temp";
        auto temp_db_obj = std::make_unique<Database>();
        auto open_result = temp_db_obj->open(options_.input_file, master_password_);
        if (!open_result.success) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            CliUtils::error(open_result.error_message);
            return EXIT_FAILURE;
        }
        temp_db_obj->close();

        // Backup current database if it exists
        if (Database::exists(db_->get_path())) {
            if (!options_.force) {
                if (!CliUtils::confirm_action("This will replace your current database. Continue?", false)) {
                    SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
                    CliUtils::info("Operation cancelled.");
                    return EXIT_SUCCESS;
                }
            }

            // Create automatic backup
            BackupManager backup_manager(*db_);
            auto backup_result = backup_manager.create_auto_backup(BackupManager::get_default_backup_dir());
            if (!backup_result.success) {
                CliUtils::warning("Failed to create automatic backup: " + backup_result.error_message);
            } else {
                CliUtils::info("Current database backed up to: " + backup_result.value);
            }
        }

        // Import backup
        db_->close();
        auto import_result = db_->import_encrypted(options_.input_file, master_password_);
        SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());

        if (!import_result.success) {
            CliUtils::error(import_result.error_message);
            return EXIT_FAILURE;
        }

        CliUtils::success("Backup imported successfully!");
        return EXIT_SUCCESS;
    }

    // Handle backup command
    int handle_backup() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        BackupManager backup_manager(*db_);
        auto result = backup_manager.create_auto_backup(BackupManager::get_default_backup_dir());

        cleanup_auth();

        if (!result.success) {
            CliUtils::error(result.error_message);
            return EXIT_FAILURE;
        }

        CliUtils::success("Backup created: " + result.value);
        return EXIT_SUCCESS;
    }

    // Handle restore command
    int handle_restore() {
        return handle_import(); // Same as import
    }

    // Handle change master password command
    int handle_change_master() {
        auto auth_result = authenticate();
        if (!auth_result.success) {
            return EXIT_FAILURE;
        }

        // Get old password (already verified in authenticate)

        // Get new password
        auto new_pwd_result = CliUtils::get_password_with_confirmation(
            "New master password: ",
            "Confirm new master password: ");

        if (!new_pwd_result.success) {
            cleanup_auth();
            CliUtils::error(new_pwd_result.error_message);
            return EXIT_FAILURE;
        }

        std::string new_password = new_pwd_result.value;

        // Change master password
        auto change_result = db_->change_master_password(master_password_, new_password);

        // Zero both passwords
        SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
        SecureMemory::secure_zero((void*)new_password.data(), new_password.size());

        if (!change_result.success) {
            CliUtils::error(change_result.error_message);
            return EXIT_FAILURE;
        }

        cleanup_auth();
        CliUtils::success("Master password changed successfully!");
        return EXIT_SUCCESS;
    }

    // Clean up authentication data
    void cleanup_auth() {
        if (!master_password_.empty()) {
            SecureMemory::secure_zero((void*)master_password_.data(), master_password_.size());
            master_password_.clear();
        }
    }
};

} // namespace pwdmgr

int main(int argc, char* argv[]) {
    pwdmgr::PasswordManagerApp app(argc, argv);
    return app.run();
}