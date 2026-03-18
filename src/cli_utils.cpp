#include "cli_utils.h"
#include "password_generator.h"
#include "secure_memory.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstring>

#ifdef __APPLE__
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#elif defined(_WIN32)
#include <windows.h>
#include <conio.h>
#else
#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#endif

namespace pwdmgr {

// ColorOutput implementation
bool ColorOutput::enabled_ = true;

std::string ColorOutput::get_color_code(Color color) {
    if (!enabled_) return "";

    switch (color) {
        case Color::Reset:       return "\033[0m";
        case Color::Red:         return "\033[31m";
        case Color::Green:       return "\033[32m";
        case Color::Yellow:      return "\033[33m";
        case Color::Blue:        return "\033[34m";
        case Color::Magenta:     return "\033[35m";
        case Color::Cyan:        return "\033[36m";
        case Color::White:       return "\033[37m";
        case Color::BrightRed:   return "\033[91m";
        case Color::BrightGreen: return "\033[92m";
        case Color::BrightYellow:return "\033[93m";
        case Color::BrightBlue:  return "\033[94m";
        case Color::BrightMagenta:return "\033[95m";
        case Color::BrightCyan:  return "\033[96m";
        case Color::BrightWhite: return "\033[97m";
        default:                 return "";
    }
}

std::string ColorOutput::colorize(const std::string& text, Color color) {
    return get_color_code(color) + text + get_color_code(Color::Reset);
}

void ColorOutput::print(Color color, const std::string& text) {
    std::cout << colorize(text, color) << std::endl;
}

void ColorOutput::print_error(const std::string& text) {
    print(Color::BrightRed, "Error: " + text);
}

void ColorOutput::print_success(const std::string& text) {
    print(Color::BrightGreen, "✓ " + text);
}

void ColorOutput::print_warning(const std::string& text) {
    print(Color::BrightYellow, "⚠ " + text);
}

void ColorOutput::print_info(const std::string& text) {
    print(Color::BrightCyan, "ℹ " + text);
}

// CliUtils implementation

Result<std::string> CliUtils::get_password(const std::string& prompt) {
    return PasswordInput::read_password(prompt);
}

Result<std::string> CliUtils::get_password_with_confirmation(
    const std::string& prompt,
    const std::string& confirm_prompt) {

    auto password_result = get_password(prompt);
    if (!password_result.success) {
        return Result<std::string>::error(password_result.error_message);
    }

    auto confirm_result = get_password(confirm_prompt);
    if (!confirm_result.success) {
        SecureMemory::secure_zero((void*)password_result.value.data(), password_result.value.size());
        return Result<std::string>::error(confirm_result.error_message);
    }

    if (password_result.value != confirm_result.value) {
        SecureMemory::secure_zero((void*)password_result.value.data(), password_result.value.size());
        SecureMemory::secure_zero((void*)confirm_result.value.data(), confirm_result.value.size());
        return Result<std::string>::error("Passwords do not match");
    }

    // Zero confirm password (we'll return the original)
    SecureMemory::secure_zero((void*)confirm_result.value.data(), confirm_result.value.size());

    return Result<std::string>::ok(std::move(password_result.value));
}

Result<std::string> CliUtils::get_masked_input(const std::string& prompt) {
    return get_password(prompt);
}

Result<std::string> CliUtils::get_input(const std::string& prompt, bool optional) {
    std::cout << prompt;
    if (optional) {
        std::cout << " (press Enter to skip)";
    }
    std::cout << ": ";
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);

    if (input.empty() && !optional) {
        return Result<std::string>::error("Input cannot be empty");
    }

    return Result<std::string>::ok(input);
}

Result<std::string> CliUtils::get_input_with_default(
    const std::string& prompt,
    const std::string& default_value) {

    std::cout << prompt << " [" << default_value << "]: ";
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);

    return Result<std::string>::ok(input.empty() ? default_value : input);
}

bool CliUtils::confirm_action(const std::string& message, bool default_yes) {
    std::string prompt = message + " (";
    prompt += default_yes ? "Y/n" : "y/N";
    prompt += "): ";

    std::cout << prompt;
    std::cout.flush();

    std::string input;
    std::getline(std::cin, input);

    if (input.empty()) {
        return default_yes;
    }

    std::string lower_input = input;
    std::transform(lower_input.begin(), lower_input.end(), lower_input.begin(), ::tolower);

    return lower_input == "y" || lower_input == "yes";
}

void CliUtils::error(const std::string& message) {
    ColorOutput::print_error(message);
}

void CliUtils::warning(const std::string& message) {
    ColorOutput::print_warning(message);
}

void CliUtils::info(const std::string& message) {
    ColorOutput::print_info(message);
}

void CliUtils::success(const std::string& message) {
    ColorOutput::print_success(message);
}

void CliUtils::display_entry(const PasswordEntry& entry, bool show_password) {
    print_header("Password Entry");

    std::cout << ColorOutput::colorize("Service Name:", Color::Cyan) << "  " << entry.service_name << std::endl;
    std::cout << ColorOutput::colorize("Username:", Color::Cyan) << "       " << entry.username << std::endl;

    if (show_password) {
        std::cout << ColorOutput::colorize("Password:", Color::Cyan) << "       " << entry.encrypted_password << std::endl;
    } else {
        std::cout << ColorOutput::colorize("Password:", Color::Cyan) << "       " << "********" << std::endl;
    }

    if (!entry.url.empty()) {
        std::cout << ColorOutput::colorize("URL:", Color::Cyan) << "            " << entry.url << std::endl;
    }

    if (!entry.notes.empty()) {
        std::cout << ColorOutput::colorize("Notes:", Color::Cyan) << "          " << entry.notes << std::endl;
    }

    auto created_time = std::chrono::system_clock::to_time_t(entry.created_at);
    std::cout << ColorOutput::colorize("Created:", Color::Cyan) << "        " << std::ctime(&created_time);

    print_separator();
}

void CliUtils::display_entries(const std::vector<PasswordEntry>& entries) {
    if (entries.empty()) {
        info("No password entries found.");
        return;
    }

    print_header("Password Entries (" + std::to_string(entries.size()) + ")");

    // Calculate column widths
    const int service_width = 30;
    const int username_width = 25;
    const int url_width = 30;

    // Print header
    std::cout << ColorOutput::colorize("Service", Color::Cyan);
    std::cout << std::setw(service_width - 7) << " ";
    std::cout << ColorOutput::colorize("Username", Color::Cyan);
    std::cout << std::setw(username_width - 8) << " ";
    std::cout << ColorOutput::colorize("URL", Color::Cyan) << std::endl;
    print_separator('-', 80);

    // Print entries
    for (const auto& entry : entries) {
        std::string service = entry.service_name;
        std::string username = entry.username;
        std::string url = entry.url;

        // Truncate if too long
        if (service.length() > service_width - 1) {
            service = service.substr(0, service_width - 4) + "...";
        }
        if (username.length() > username_width - 1) {
            username = username.substr(0, username_width - 4) + "...";
        }
        if (url.length() > url_width - 1) {
            url = url.substr(0, url_width - 4) + "...";
        }

        std::cout << std::left << std::setw(service_width) << service
                  << std::setw(username_width) << username
                  << url << std::endl;
    }

    print_separator();
}

void CliUtils::display_backup(const BackupMetadata& backup) {
    auto time_t = std::chrono::system_clock::to_time_t(backup.timestamp);
    std::string time_str = std::ctime(&time_t);
    time_str.pop_back(); // Remove newline

    print_header("Backup Information");
    std::cout << ColorOutput::colorize("Backup ID:", Color::Cyan) << "    " << backup.backup_id << std::endl;
    std::cout << ColorOutput::colorize("Created:", Color::Cyan) << "       " << time_str << std::endl;
    std::cout << ColorOutput::colorize("Version:", Color::Cyan) << "       " << backup.version << std::endl;
    std::cout << ColorOutput::colorize("File:", Color::Cyan) << "          " << backup.original_db_path << std::endl;
    print_separator();
}

void CliUtils::display_backups(const std::vector<BackupMetadata>& backups) {
    if (backups.empty()) {
        info("No backups found.");
        return;
    }

    print_header("Backups (" + std::to_string(backups.size()) + ")");

    for (const auto& backup : backups) {
        auto time_t = std::chrono::system_clock::to_time_t(backup.timestamp);
        std::string time_str = std::ctime(&time_t);
        time_str.pop_back(); // Remove newline

        std::cout << ColorOutput::colorize("•", Color::Cyan) << " " << backup.backup_id
                  << " - " << time_str << " (v" << backup.version << ")" << std::endl;
    }

    print_separator();
}

void CliUtils::display_password_strength(const std::string& password) {
    auto score_result = PasswordGenerator::get_strength_score(password);
    if (!score_result.success) {
        return;
    }

    int score = score_result.value;
    std::string description = PasswordGenerator::get_strength_description(score);

    ColorOutput::Color color;
    if (score < 20) color = ColorOutput::Color::BrightRed;
    else if (score < 40) color = ColorOutput::Color::Red;
    else if (score < 60) color = ColorOutput::Color::Yellow;
    else if (score < 80) color = ColorOutput::Color::Green;
    else color = ColorOutput::Color::BrightGreen;

    std::cout << ColorOutput::colorize("Password Strength:", Color::Cyan) << " ";
    std::cout << ColorOutput::colorize(description, color);
    std::cout << " (" << score << "/100)" << std::endl;

    // Display strength bar
    std::cout << "[";
    for (int i = 0; i < 10; ++i) {
        if (i * 10 < score) {
            std::cout << ColorOutput::colorize("█", color);
        } else {
            std::cout << "░";
        }
    }
    std::cout << "]" << std::endl;
}

void CliUtils::display_version() {
    print_header("Password Manager CLI");
    std::cout << ColorOutput::colorize("Version:", Color::Cyan) << " 1.0.0" << std::endl;
    std::cout << ColorOutput::colorize("Database:", Color::Cyan) << " v" << DATABASE_VERSION << std::endl;
    std::cout << ColorOutput::colorize("Encryption:", Color::Cyan) << " AES-256-GCM" << std::endl;
    std::cout << ColorOutput::colorize("KDF:", Color::Cyan) << " PBKDF2-HMAC-SHA256 (" << PBKDF2_ITERATIONS << " iterations)" << std::endl;
    print_separator();
}

void CliUtils::display_help() {
    print_header("Password Manager - Help");

    std::cout << ColorOutput::colorize("Usage:", Color::BrightYellow) << std::endl;
    std::cout << "  pwdmgr <command> [options]" << std::endl;
    std::cout << std::endl;

    std::cout << ColorOutput::colorize("Commands:", Color::BrightYellow) << std::endl;
    std::cout << "  init              Initialize a new password database" << std::endl;
    std::cout << "  add               Add a new password entry" << std::endl;
    std::cout << "  get <service>     Get password for a service" << std::endl;
    std::cout << "  list              List all password entries" << std::endl;
    std::cout << "  search <pattern>  Search for password entries" << std::endl;
    std::cout << "  update <service>  Update a password entry" << std::endl;
    std::cout << "  delete <service>  Delete a password entry" << std::endl;
    std::cout << "  generate          Generate a random password" << std::endl;
    std::cout << "  export <file>     Export encrypted backup" << std::endl;
    std::cout << "  import <file>     Import encrypted backup" << std::endl;
    std::cout << "  backup            Create automatic backup" << std::endl;
    std::cout << "  restore <file>    Restore from backup" << std::endl;
    std::cout << "  change-password   Change master password" << std::endl;
    std::cout << "  version           Display version information" << std::endl;
    std::cout << "  help              Display this help message" << std::endl;
    std::cout << std::endl;

    std::cout << ColorOutput::colorize("Global Options:", Color::BrightYellow) << std::endl;
    std::cout << "  -v, --verbose     Enable verbose output" << std::endl;
    std::cout << "  -f, --force       Force operation without confirmation" << std::endl;
    std::cout << "  --no-color        Disable colored output" << std::endl;
    std::cout << "  --db <path>       Specify database path" << std::endl;
    std::cout << std::endl;

    std::cout << ColorOutput::colorize("Password Generation Options:", Color::BrightYellow) << std::endl;
    std::cout << "  -l, --length <n>      Password length (default: 16)" << std::endl;
    std::cout << "  --no-uppercase       Disable uppercase letters" << std::endl;
    std::cout << "  --no-lowercase       Disable lowercase letters" << std::endl;
    std::cout << "  --no-digits          Disable digits" << std::endl;
    std::cout << "  --no-special         Disable special characters" << std::endl;
    std::cout << "  --ambiguous          Allow ambiguous characters (0, O, 1, l, I)" << std::endl;
    std::cout << "  --pronounceable      Generate pronounceable password" << std::endl;
    std::cout << "  --passphrase         Generate passphrase (4 words)" << std::endl;
    std::cout << "  --words <n>          Number of words for passphrase (default: 4)" << std::endl;

    print_separator();
}

void CliUtils::display_command_help(Command command) {
    switch (command) {
        case Command::INIT:
            print_header("Init Command");
            std::cout << "Initialize a new password database." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr init [--db <path>]" << std::endl;
            break;

        case Command::ADD:
            print_header("Add Command");
            std::cout << "Add a new password entry to the database." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr add [--service <name>] [--username <user>] [--password <pwd>]" << std::endl;
            std::cout << "                [--url <url>] [--notes <notes>]" << std::endl;
            break;

        case Command::GET:
            print_header("Get Command");
            std::cout << "Retrieve password for a service." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr get <service> [--show] [--copy]" << std::endl;
            std::cout << "  --show    Display password (instead of copying to clipboard)" << std::endl;
            std::cout << "  --copy    Copy password to clipboard (default)" << std::endl;
            break;

        case Command::LIST:
            print_header("List Command");
            std::cout << "List all password entries." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr list" << std::endl;
            break;

        case Command::SEARCH:
            print_header("Search Command");
            std::cout << "Search for password entries matching a pattern." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr search <pattern>" << std::endl;
            break;

        case Command::UPDATE:
            print_header("Update Command");
            std::cout << "Update an existing password entry." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr update <service> [--username <user>] [--password <pwd>]" << std::endl;
            std::cout << "                     [--url <url>] [--notes <notes>]" << std::endl;
            break;

        case Command::DELETE:
            print_header("Delete Command");
            std::cout << "Delete a password entry." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr delete <service>" << std::endl;
            break;

        case Command::GENERATE:
            print_header("Generate Command");
            std::cout << "Generate a random password." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr generate [options]" << std::endl;
            break;

        case Command::EXPORT:
            print_header("Export Command");
            std::cout << "Export encrypted backup of the database." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr export <output_file>" << std::endl;
            break;

        case Command::IMPORT:
            print_header("Import Command");
            std::cout << "Import encrypted backup to the database." << std::endl;
            std::cout << std::endl;
            std::cout << "Usage: pwdmgr import <input_file>" << std::endl;
            break;

        default:
            display_help();
            break;
    }

    print_separator();
}

void CliUtils::clear_screen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

Result<void> CliUtils::copy_to_clipboard(const std::string& text) {
#ifdef _WIN32
    if (!OpenClipboard(nullptr)) {
        return Result<void>::error("Failed to open clipboard");
    }

    HGLOBAL hglb = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hglb) {
        CloseClipboard();
        return Result<void>::error("Failed to allocate memory for clipboard");
    }

    char* lptstr = static_cast<char*>(GlobalLock(hglb));
    memcpy(lptstr, text.c_str(), text.size() + 1);
    GlobalUnlock(hglb);

    if (!SetClipboardData(CF_TEXT, hglb)) {
        GlobalFree(hglb);
        CloseClipboard();
        return Result<void>::error("Failed to set clipboard data");
    }

    CloseClipboard();
#elif defined(__APPLE__)
    FILE* pipe = popen("pbcopy", "w");
    if (!pipe) {
        return Result<void>::error("Failed to open pbcopy");
    }

    fwrite(text.c_str(), 1, text.size(), pipe);
    pclose(pipe);
#else
    // Linux - try xclip or xsel
    FILE* pipe = popen("xclip -selection clipboard", "w");
    if (!pipe) {
        pipe = popen("xsel --clipboard --input", "w");
        if (!pipe) {
            return Result<void>::error("Neither xclip nor xsel is installed");
        }
    }

    fwrite(text.c_str(), 1, text.size(), pipe);
    pclose(pipe);
#endif

    return Result<void>::ok();
}

int CliUtils::get_terminal_width() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    return csbi.srWindow.Right - csbi.srWindow.Left + 1;
#else
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    return w.ws_col;
#endif
}

void CliUtils::print_separator(char c, int width) {
    if (width == 0) {
        width = get_terminal_width();
        if (width <= 0) width = 80;
    }

    std::string separator(width, c);
    ColorOutput::print(Color::White, separator);
}

void CliUtils::print_header(const std::string& title) {
    int width = get_terminal_width();
    if (width <= 0) width = 80;

    // Calculate padding
    int padding = (width - title.length() - 2) / 2;
    if (padding < 1) padding = 1;

    std::string line = std::string(padding, ' ') + title + std::string(padding, ' ');

    // Adjust if odd length
    if (line.length() < static_cast<size_t>(width)) {
        line += " ";
    }

    print_separator();
    ColorOutput::print(Color::BrightWhite, line);
    print_separator();
}

void CliUtils::print_table_row(const std::vector<std::string>& columns,
                                const std::vector<int>& column_widths) {
    for (size_t i = 0; i < columns.size(); ++i) {
        std::string col = columns[i];
        int width = (i < column_widths.size()) ? column_widths[i] : 20;

        if (col.length() > static_cast<size_t>(width)) {
            col = col.substr(0, width - 3) + "...";
        }

        std::cout << std::left << std::setw(width) << col;
    }
    std::cout << std::endl;
}

// PasswordInput implementation

#ifdef _WIN32
Result<std::string> PasswordInput::read_password(const std::string& prompt) {
    return read_password_windows(prompt);
}

Result<std::string> PasswordInput::read_password_windows(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string password;
    int ch;

    while ((ch = _getch()) != '\r') {
        if (ch == 3) { // Ctrl+C
            return Result<std::string>::error("Input cancelled");
        }
        if (ch == 8) { // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
                std::cout.flush();
            }
        } else {
            password += static_cast<char>(ch);
            std::cout << '*';
            std::cout.flush();
        }
    }

    std::cout << std::endl;

    return Result<std::string>::ok(password);
}
#else
Result<std::string> PasswordInput::read_password(const std::string& prompt) {
    return read_password_unix(prompt);
}

Result<std::string> PasswordInput::read_password_unix(const std::string& prompt) {
    struct termios old_termios, new_termios;

    // Get current terminal settings
    if (tcgetattr(STDIN_FILENO, &old_termios) != 0) {
        return Result<std::string>::error("Failed to get terminal attributes");
    }

    // Disable echo
    new_termios = old_termios;
    new_termios.c_lflag &= ~(ECHO | ECHOE | ECHOK | ECHONL | ICANON);

    // Apply new settings
    if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_termios) != 0) {
        return Result<std::string>::error("Failed to set terminal attributes");
    }

    std::cout << prompt;
    std::cout.flush();

    std::string password;
    char ch;

    while (std::cin.get(ch) && ch != '\n') {
        if (ch == 3) { // Ctrl+C
            // Restore terminal settings
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);
            return Result<std::string>::error("Input cancelled");
        }
        if (ch == 127 || ch == 8) { // Backspace
            if (!password.empty()) {
                password.pop_back();
                std::cout << "\b \b";
                std::cout.flush();
            }
        } else {
            password += ch;
            std::cout << '*';
            std::cout.flush();
        }
    }

    std::cout << std::endl;

    // Restore terminal settings
    tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_termios);

    return Result<std::string>::ok(password);
}
#endif

// CommandLineParser implementation

CommandLineParser::CommandLineParser(int argc, char* argv[])
    : argc_(argc), argv_(argv) {}

Result<CliOptions> CommandLineParser::parse() {
    CliOptions options;

    // Skip program name
    int i = 1;

    // Parse global options first
    while (i < argc_ && argv_[i][0] == '-') {
        if (strcmp(argv_[i], "-v") == 0 || strcmp(argv_[i], "--verbose") == 0) {
            options.verbose = true;
        } else if (strcmp(argv_[i], "-f") == 0 || strcmp(argv_[i], "--force") == 0) {
            options.force = true;
        } else if (strcmp(argv_[i], "--no-color") == 0) {
            ColorOutput::set_enabled(false);
        } else if (strcmp(argv_[i], "--db") == 0) {
            if (++i >= argc_) {
                return Result<CliOptions>::error("Missing value for --db option");
            }
            // Store for later use
            remaining_args_.push_back("--db");
            remaining_args_.push_back(argv_[i]);
        } else {
            // Unknown option, assume it's part of command
            break;
        }
        i++;
    }

    // Parse command
    if (i >= argc_) {
        options.command = Command::HELP;
        return Result<CliOptions>::ok(options);
    }

    std::string cmd = argv_[i];
    i++;

    // Map command string to enum
    if (cmd == "init") {
        options.command = Command::INIT;
    } else if (cmd == "add") {
        options.command = Command::ADD;
    } else if (cmd == "get") {
        options.command = Command::GET;
        if (i < argc_) {
            options.service = argv_[i++];
        }
    } else if (cmd == "list") {
        options.command = Command::LIST;
    } else if (cmd == "search") {
        options.command = Command::SEARCH;
        if (i < argc_) {
            options.pattern = argv_[i++];
        }
    } else if (cmd == "update") {
        options.command = Command::UPDATE;
        if (i < argc_) {
            options.service = argv_[i++];
        }
    } else if (cmd == "delete") {
        options.command = Command::DELETE;
        if (i < argc_) {
            options.service = argv_[i++];
        }
    } else if (cmd == "generate") {
        options.command = Command::GENERATE;
    } else if (cmd == "export") {
        options.command = Command::EXPORT;
        if (i < argc_) {
            options.output_file = argv_[i++];
        }
    } else if (cmd == "import") {
        options.command = Command::IMPORT;
        if (i < argc_) {
            options.input_file = argv_[i++];
        }
    } else if (cmd == "backup") {
        options.command = Command::BACKUP;
    } else if (cmd == "restore") {
        options.command = Command::RESTORE;
        if (i < argc_) {
            options.input_file = argv_[i++];
        }
    } else if (cmd == "change-password") {
        options.command = Command::CHANGE_MASTER;
    } else if (cmd == "version") {
        options.command = Command::VERSION;
    } else if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        options.command = Command::HELP;
    } else {
        return Result<CliOptions>::error("Unknown command: " + cmd);
    }

    // Parse command-specific options
    auto parse_result = parse_command_options(options.command, options);
    if (!parse_result.success) {
        return Result<CliOptions>::error(parse_result.error_message);
    }

    // Store remaining arguments
    while (i < argc_) {
        remaining_args_.push_back(argv_[i++]);
    }

    return Result<CliOptions>::ok(options);
}

void CommandLineParser::parse_global_options(CliOptions& options) {
    // Already handled in parse()
}

Result<void> CommandLineParser::parse_command_options(Command command, CliOptions& options) {
    // For simplicity, command options are handled in the main application logic
    // This parser just extracts the basic structure
    (void)command;
    (void)options;
    return Result<void>::ok();
}

void CommandLineParser::show_usage() {
    std::cout << "Usage: pwdmgr <command> [options]" << std::endl;
    std::cout << "Run 'pwdmgr help' for more information." << std::endl;
}

bool CommandLineParser::parse_flag(const std::string& arg, const std::string& flag) {
    return arg == "-" + flag || arg == "--" + flag;
}

bool CommandLineParser::parse_option(const std::string& arg, const std::string& option, std::string& value) {
    if (arg == "-" + option || arg == "--" + option) {
        return true; // Value is in next arg
    }

    // Check for --option=value format
    size_t pos = arg.find("=");
    if (pos != std::string::npos) {
        std::string opt = arg.substr(0, pos);
        if (opt == "-" + option || opt == "--" + option) {
            value = arg.substr(pos + 1);
            return true;
        }
    }

    return false;
}

} // namespace pwdmgr