/**
 * @file cli_utils.h
 * @brief Command-line interface utilities for user interaction.
 *
 * This header provides utilities for building interactive command-line
 * interfaces, including:
 * - Password input with masking
 * - Colored output
 * - User prompts and confirmations
 * - Command-line argument parsing
 * - Table and entry display
 *
 * Platform Support:
 * - POSIX systems (Linux, macOS): Uses termios for password masking
 * - Windows: Uses _getch() for password masking
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_CLI_UTILS_H
#define PASSWORD_MANAGER_CLI_UTILS_H

#include <string>
#include <vector>
#include <functional>
#include "types.h"

namespace pwdmgr {

// =============================================================================
// CliUtils Class
// =============================================================================

/**
 * @class CliUtils
 * @brief Static utilities for CLI input and output.
 *
 * This class provides a collection of static methods for building
 * interactive command-line interfaces with secure password input,
 * colored output, and formatted display.
 *
 * Key Features:
 * - Secure password input with character masking
 * - Cross-platform colored output
 * - Formatted table display
 * - Clipboard integration (copy passwords)
 * - User confirmation prompts
 *
 * @code
 * // Get password securely
 * auto pwd = CliUtils::get_password("Enter password: ");
 * if (pwd.success) {
 *     std::cout << "Password received: " << pwd.value.length() << " chars\n";
 * }
 *
 * // Display colored messages
 * CliUtils::success("Operation completed!");
 * CliUtils::error("Something went wrong!");
 * CliUtils::warning("This action cannot be undone");
 *
 * // Display a password entry
 * PasswordEntry entry;
 * entry.service_name = "github";
 * entry.username = "user@example.com";
 * CliUtils::display_entry(entry, true); // show password
 * @endcode
 */
class CliUtils {
public:
    // -------------------------------------------------------------------------
    // Password Input
    // -------------------------------------------------------------------------

    /**
     * @brief Gets a password from user input with masking.
     *
     * Displays a prompt and reads a password with each character
     * masked (displayed as *). This is secure for terminal input
     * and prevents shoulder surfing.
     *
     * @param prompt The prompt to display (default: "Enter password: ")
     * @return Result containing the password on success
     *
     * @note Uses platform-specific implementations:
     *       - POSIX: termios
     *       - Windows: _getch()
     */
    static Result<std::string> get_password(const std::string& prompt = "Enter password: ");

    /**
     * @brief Gets a password with confirmation.
     *
     * Prompts for password twice and verifies they match.
     * Useful for setting new passwords.
     *
     * @param prompt First password prompt
     * @param confirm_prompt Second password prompt (confirmation)
     * @return Result containing the password on success
     *
     * @note Returns error if passwords don't match.
     */
    static Result<std::string> get_password_with_confirmation(
        const std::string& prompt = "Enter password: ",
        const std::string& confirm_prompt = "Confirm password: ");

    /**
     * @brief Gets masked input (alias for get_password).
     *
     * Provided for semantic clarity when masking non-password input.
     *
     * @param prompt The prompt to display
     * @return Result containing the input on success
     */
    static Result<std::string> get_masked_input(const std::string& prompt);

    // -------------------------------------------------------------------------
    // General Input
    // -------------------------------------------------------------------------

    /**
     * @brief Gets text input from the user.
     *
     * Displays a prompt and reads a line of text.
     *
     * @param prompt The prompt to display
     * @param optional If true, allows empty input
     * @return Result containing the input on success
     */
    static Result<std::string> get_input(const std::string& prompt, bool optional = false);

    /**
     * @brief Gets input with a default value.
     *
     * Displays a prompt with the default value shown in brackets.
     * If user presses Enter without typing, returns the default.
     *
     * @param prompt The prompt to display
     * @param default_value The default value if input is empty
     * @return Result containing the input (or default) on success
     */
    static Result<std::string> get_input_with_default(
        const std::string& prompt,
        const std::string& default_value);

    /**
     * @brief Asks for user confirmation.
     *
     * Displays a yes/no prompt with the specified message.
     *
     * @param message The confirmation message
     * @param default_yes If true, pressing Enter confirms; if false, user must type y/yes
     * @return true if user confirms, false otherwise
     */
    static bool confirm_action(const std::string& message, bool default_yes = true);

    // -------------------------------------------------------------------------
    // Output Messages
    // -------------------------------------------------------------------------

    /**
     * @brief Displays an error message in red.
     *
     * @param message The error message to display
     */
    static void error(const std::string& message);

    /**
     * @brief Displays a warning message in yellow.
     *
     * @param message The warning message to display
     */
    static void warning(const std::string& message);

    /**
     * @brief Displays an info message in blue/cyan.
     *
     * @param message The info message to display
     */
    static void info(const std::string& message);

    /**
     * @brief Displays a success message in green.
     *
     * @param message The success message to display
     */
    static void success(const std::string& message);

    // -------------------------------------------------------------------------
    // Entry Display
    // -------------------------------------------------------------------------

    /**
     * @brief Displays a single password entry.
     *
     * Formats and prints a password entry with optional password visibility.
     *
     * @param entry The entry to display
     * @param show_password If true, shows the password; if false, shows ********
     */
    static void display_entry(const PasswordEntry& entry, bool show_password = false);

    /**
     * @brief Displays a list of password entries.
     *
     * Formats entries in a table with service name, username, and URL columns.
     *
     * @param entries Vector of entries to display
     */
    static void display_entries(const std::vector<PasswordEntry>& entries);

    // -------------------------------------------------------------------------
    // Backup Display
    // -------------------------------------------------------------------------

    /**
     * @brief Displays backup metadata.
     *
     * Shows backup ID, timestamp, version, and file path.
     *
     * @param backup The backup metadata to display
     */
    static void display_backup(const BackupMetadata& backup);

    /**
     * @brief Displays a list of backups.
     *
     * Formats backups in a list with timestamps and versions.
     *
     * @param backups Vector of backups to display
     */
    static void display_backups(const std::vector<BackupMetadata>& backups);

    // -------------------------------------------------------------------------
    // Password Strength Display
    // -------------------------------------------------------------------------

    /**
     * @brief Displays password strength analysis.
     *
     * Shows a color-coded strength bar and numerical score.
     *
     * @param password The password to analyze
     */
    static void display_password_strength(const std::string& password);

    // -------------------------------------------------------------------------
    // Help and Version Display
    // -------------------------------------------------------------------------

    /**
     * @brief Displays version information.
     *
     * Shows application version, database version, and encryption details.
     */
    static void display_version();

    /**
     * @brief Displays general help message.
     *
     * Lists all available commands and options.
     */
    static void display_help();

    /**
     * @brief Displays help for a specific command.
     *
     * Shows detailed usage information for the specified command.
     *
     * @param command The command to show help for
     */
    static void display_command_help(Command command);

    // -------------------------------------------------------------------------
    // Terminal Utilities
    // -------------------------------------------------------------------------

    /**
     * @brief Clears the terminal screen.
     *
     * Uses platform-specific commands:
     * - Windows: system("cls")
     * - POSIX: system("clear")
     */
    static void clear_screen();

    /**
     * @brief Copies text to the system clipboard.
     *
     * Uses platform-specific clipboard tools:
     * - Windows: Win32 Clipboard API
     * - macOS: pbcopy
     * - Linux: xclip or xsel
     *
     * @param text The text to copy
     * @return Result indicating success or containing an error message
     */
    static Result<void> copy_to_clipboard(const std::string& text);

    /**
     * @brief Gets the terminal width.
     *
     * Returns the number of columns in the terminal for formatting.
     *
     * @return Terminal width in columns, or 80 if unable to determine
     */
    static int get_terminal_width();

    /**
     * @brief Prints a separator line.
     *
     * Prints a line of repeated characters across the terminal width.
     *
     * @param c Character to repeat (default: '-')
     * @param width Width of the line (default: 0 = terminal width)
     */
    static void print_separator(char c = '-', int width = 0);

    /**
     * @brief Prints a formatted header.
     *
     * Displays a centered title with separator lines above and below.
     *
     * @param title The title to display
     */
    static void print_header(const std::string& title);

    /**
     * @brief Prints a formatted table row.
     *
     * Aligns columns according to specified widths.
     *
     * @param columns Column values to display
     * @param column_widths Width for each column
     */
    static void print_table_row(const std::vector<std::string>& columns,
                                const std::vector<int>& column_widths);

private:
    /**
     * @brief Enables or disables terminal echo.
     *
     * Used internally for password masking on POSIX systems.
     *
     * @param enabled true to enable echo, false to disable
     */
    static void set_terminal_echo(bool enabled);

    /**
     * @brief Gets terminal attributes.
     *
     * Platform-specific implementation for POSIX systems.
     *
     * @param fd File descriptor (output)
     * @param termios Terminal settings structure (output)
     * @return true on success
     */
    static bool get_terminal_attributes(int* fd, void* termios);

    /**
     * @brief Sets terminal attributes.
     *
     * Platform-specific implementation for POSIX systems.
     *
     * @param fd File descriptor
     * @param termios Terminal settings structure
     * @return true on success
     */
    static bool set_terminal_attributes(int* fd, void* termios);
};

// =============================================================================
// CommandLineParser Class
// =============================================================================

/**
 * @class CommandLineParser
 * @brief Parses command-line arguments into structured options.
 *
 * This class handles argument parsing for the password manager CLI,
 * converting argc/argv into a CliOptions structure with command and
 * parameter extraction.
 *
 * Supported Argument Formats:
 * - Short flags: -v, -f
 * - Long flags: --verbose, --force
 * - Options with values: --service myservice, --service=myservice
 * - Positional arguments: get github, add
 *
 * @code
 * int main(int argc, char* argv[]) {
 *     CommandLineParser parser(argc, argv);
 *     auto result = parser.parse();
 *     if (result.success) {
 *         CliOptions opts = result.value;
 *         // process opts.command...
 *     }
 * }
 * @endcode
 */
class CommandLineParser {
public:
    /**
     * @brief Constructs a parser with command-line arguments.
     *
     * @param argc Argument count from main()
     * @param argv Argument values from main()
     */
    CommandLineParser(int argc, char* argv[]);

    /**
     * @brief Parses the command-line arguments.
     *
     * Extracts the command and all options into a CliOptions structure.
     *
     * @return Result containing parsed options on success
     */
    Result<CliOptions> parse();

    /**
     * @brief Gets remaining arguments after parsing.
     *
     * Returns arguments that weren't consumed by the parser.
     *
     * @return Reference to vector of remaining argument strings
     */
    const std::vector<std::string>& get_remaining_args() const { return remaining_args_; }

private:
    int argc_;                              ///< Argument count
    char** argv_;                           ///< Argument values
    std::vector<std::string> remaining_args_; ///< Unprocessed arguments

    /**
     * @brief Parses global options (verbose, force, etc.).
     *
     * @param options Options structure to populate
     */
    void parse_global_options(CliOptions& options);

    /**
     * @brief Parses command-specific options.
     *
     * @param command The command being parsed
     * @param options Options structure to populate
     * @return Result indicating success or containing an error message
     */
    Result<void> parse_command_options(Command command, CliOptions& options);

    /**
     * @brief Displays usage information.
     */
    void show_usage();

    /**
     * @brief Checks if argument matches a flag.
     *
     * @param arg The argument to check
     * @param flag The flag name (without - or --)
     * @return true if argument matches the flag
     */
    bool parse_flag(const std::string& arg, const std::string& flag);

    /**
     * @brief Parses an option with a value.
     *
     * Handles both --option value and --option=value formats.
     *
     * @param arg The argument to check
     * @param option The option name (without - or --)
     * @param value Output parameter for the option value
     * @return true if argument matches and has a value
     */
    bool parse_option(const std::string& arg, const std::string& option, std::string& value);
};

// =============================================================================
// PasswordInput Class
// =============================================================================

/**
 * @class PasswordInput
 * @brief Platform-specific password input implementation.
 *
 * This class provides cross-platform password input functionality with
 * character masking. It handles the differences between POSIX and
 * Windows terminal I/O.
 *
 * Platform Implementations:
 * - POSIX: Uses termios to disable echo
 * - Windows: Uses _getch() for character-by-character input
 *
 * Security Features:
 * - Characters masked with * to prevent shoulder surfing
 * - Backspace handling for editing
 * - No password stored in terminal history
 */
class PasswordInput {
public:
    /**
     * @brief Reads a password with masking.
     *
     * Platform-independent entry point that delegates to the
     * appropriate platform-specific implementation.
     *
     * @param prompt The prompt to display
     * @return Result containing the password on success
     */
    static Result<std::string> read_password(const std::string& prompt);

private:
#ifdef _WIN32
    /**
     * @brief Windows-specific password input implementation.
     *
     * Uses _getch() for character-by-character input without echo.
     *
     * @param prompt The prompt to display
     * @return Result containing the password on success
     */
    static Result<std::string> read_password_windows(const std::string& prompt);
#else
    /**
     * @brief POSIX-specific password input implementation.
     *
     * Uses termios to temporarily disable echo.
     *
     * @param prompt The prompt to display
     * @return Result containing the password on success
     */
    static Result<std::string> read_password_unix(const std::string& prompt);
#endif
};

// =============================================================================
// ColorOutput Class
// =============================================================================

/**
 * @class ColorOutput
 * @brief ANSI color output utilities.
 *
 * This class provides methods for colored terminal output using ANSI
 * escape codes. Colors can be enabled/disabled globally (useful for
 * non-terminal output or Windows legacy terminals).
 *
 * Supported Colors:
 * - Standard: Red, Green, Yellow, Blue, Magenta, Cyan, White
 * - Bright variants: BrightRed, BrightGreen, etc.
 *
 * @note Colors are automatically disabled on Windows legacy consoles
 *       that don't support ANSI codes.
 *
 * @code
 * // Enable colors
 * ColorOutput::set_enabled(true);
 *
 * // Print colored text
 * ColorOutput::print(Color::Green, "Success!");
 * ColorOutput::print_error("Something failed");
 *
 * // Get colored string
 * std::string msg = ColorOutput::colorize("Warning!", Color::Yellow);
 * @endcode
 */
class ColorOutput {
public:
    /**
     * @enum Color
     * @brief Available text colors.
     */
    enum class Color {
        Reset,           ///< Reset to default color
        Red,             ///< Standard red
        Green,           ///< Standard green
        Yellow,          ///< Standard yellow
        Blue,            ///< Standard blue
        Magenta,         ///< Standard magenta
        Cyan,            ///< Standard cyan
        White,           ///< Standard white
        BrightRed,       ///< Bright/bold red
        BrightGreen,     ///< Bright/bold green
        BrightYellow,    ///< Bright/bold yellow
        BrightBlue,      ///< Bright/bold blue
        BrightMagenta,   ///< Bright/bold magenta
        BrightCyan,      ///< Bright/bold cyan
        BrightWhite      ///< Bright/bold white
    };

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /**
     * @brief Enables or disables colored output.
     *
     * When disabled, all colorize() and print() calls return
     * uncolored text.
     *
     * @param enabled true to enable colors, false to disable
     */
    static void set_enabled(bool enabled) { enabled_ = enabled; }

    /**
     * @brief Checks if colors are enabled.
     *
     * @return true if colors are enabled
     */
    static bool is_enabled() { return enabled_; }

    // -------------------------------------------------------------------------
    // Color Functions
    // -------------------------------------------------------------------------

    /**
     * @brief Wraps text in ANSI color codes.
     *
     * @param text The text to colorize
     * @param color The color to apply
     * @return Text wrapped with ANSI escape codes
     */
    static std::string colorize(const std::string& text, Color color);

    /**
     * @brief Prints colored text to stdout.
     *
     * @param color The color to use
     * @param text The text to print
     */
    static void print(Color color, const std::string& text);

    /**
     * @brief Prints an error message in red.
     *
     * Prefixes the message with "Error: " and displays in red.
     *
     * @param text The error message
     */
    static void print_error(const std::string& text);

    /**
     * @brief Prints a success message in green.
     *
     * Prefixes the message with "✓ " and displays in green.
     *
     * @param text The success message
     */
    static void print_success(const std::string& text);

    /**
     * @brief Prints a warning message in yellow.
     *
     * Prefixes the message with "⚠ " and displays in yellow.
     *
     * @param text The warning message
     */
    static void print_warning(const std::string& text);

    /**
     * @brief Prints an info message in blue/cyan.
     *
     * Prefixes the message with "ℹ " and displays in cyan.
     *
     * @param text The info message
     */
    static void print_info(const std::string& text);

private:
    static bool enabled_;  ///< Whether colors are enabled

    /**
     * @brief Gets the ANSI escape code for a color.
     *
     * @param color The color to get code for
     * @return ANSI escape sequence string
     */
    static std::string get_color_code(Color color);
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_CLI_UTILS_H