#ifndef PASSWORD_MANAGER_CLI_UTILS_H
#define PASSWORD_MANAGER_CLI_UTILS_H

#include <string>
#include <vector>
#include <functional>
#include "types.h"

namespace pwdmgr {

// CLI utilities for password input and output
class CliUtils {
public:
    // Get password from user with masking
    static Result<std::string> get_password(const std::string& prompt = "Enter password: ");

    // Get password with confirmation
    static Result<std::string> get_password_with_confirmation(
        const std::string& prompt = "Enter password: ",
        const std::string& confirm_prompt = "Confirm password: ");

    // Get masked input
    static Result<std::string> get_masked_input(const std::string& prompt);

    // Get input from user
    static Result<std::string> get_input(const std::string& prompt, bool optional = false);

    // Get input with default value
    static Result<std::string> get_input_with_default(
        const std::string& prompt,
        const std::string& default_value);

    // Confirm action
    static bool confirm_action(const std::string& message, bool default_yes = true);

    // Display error message
    static void error(const std::string& message);

    // Display warning message
    static void warning(const std::string& message);

    // Display info message
    static void info(const std::string& message);

    // Display success message
    static void success(const std::string& message);

    // Display password entry
    static void display_entry(const PasswordEntry& entry, bool show_password = false);

    // Display password entry list
    static void display_entries(const std::vector<PasswordEntry>& entries);

    // Display backup information
    static void display_backup(const BackupMetadata& backup);

    // Display backup list
    static void display_backups(const std::vector<BackupMetadata>& backups);

    // Display password strength
    static void display_password_strength(const std::string& password);

    // Display version
    static void display_version();

    // Display help
    static void display_help();

    // Display help for specific command
    static void display_command_help(Command command);

    // Clear screen
    static void clear_screen();

    // Copy to clipboard
    static Result<void> copy_to_clipboard(const std::string& text);

    // Get terminal width
    static int get_terminal_width();

    // Print separator line
    static void print_separator(char c = '-', int width = 0);

    // Print header
    static void print_header(const std::string& title);

    // Print table row
    static void print_table_row(const std::vector<std::string>& columns,
                                const std::vector<int>& column_widths);

private:
    // Enable/disable terminal echo
    static void set_terminal_echo(bool enabled);

    // Get terminal attributes
    static bool get_terminal_attributes(int* fd, void* termios);

    // Set terminal attributes
    static bool set_terminal_attributes(int* fd, void* termios);
};

// Command line argument parser
class CommandLineParser {
public:
    CommandLineParser(int argc, char* argv[]);

    // Parse command line arguments
    Result<CliOptions> parse();

    // Get remaining arguments (after parsing)
    const std::vector<std::string>& get_remaining_args() const { return remaining_args_; }

private:
    int argc_;
    char** argv_;
    std::vector<std::string> remaining_args_;

    // Parse global options
    void parse_global_options(CliOptions& options);

    // Parse command-specific options
    Result<void> parse_command_options(Command command, CliOptions& options);

    // Show usage
    void show_usage();

    // Parse flag (e.g., --verbose, -v)
    bool parse_flag(const std::string& arg, const std::string& flag);

    // Parse option with value (e.g., --service myservice)
    bool parse_option(const std::string& arg, const std::string& option, std::string& value);
};

// Password input with masking (for platforms without getpass())
class PasswordInput {
public:
    // Read password with masking
    static Result<std::string> read_password(const std::string& prompt);

private:
    // Platform-specific implementation
#ifdef _WIN32
    static Result<std::string> read_password_windows(const std::string& prompt);
#else
    static Result<std::string> read_password_unix(const std::string& prompt);
#endif
};

// Color output support
class ColorOutput {
public:
    enum class Color {
        Reset,
        Red,
        Green,
        Yellow,
        Blue,
        Magenta,
        Cyan,
        White,
        BrightRed,
        BrightGreen,
        BrightYellow,
        BrightBlue,
        BrightMagenta,
        BrightCyan,
        BrightWhite
    };

    // Enable/disable colors
    static void set_enabled(bool enabled) { enabled_ = enabled; }

    // Check if colors are enabled
    static bool is_enabled() { return enabled_; }

    // Colorize text
    static std::string colorize(const std::string& text, Color color);

    // Print colored text
    static void print(Color color, const std::string& text);

    // Print error (red)
    static void print_error(const std::string& text);

    // Print success (green)
    static void print_success(const std::string& text);

    // Print warning (yellow)
    static void print_warning(const std::string& text);

    // Print info (blue)
    static void print_info(const std::string& text);

private:
    static bool enabled_;
    static std::string get_color_code(Color color);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_CLI_UTILS_H