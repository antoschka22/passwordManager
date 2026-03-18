# Password Manager CLI

A secure, command-line password manager built with C++20, featuring AES-256-GCM encryption and PBKDF2 key derivation.

## Features

### Security
- **AES-256-GCM** encryption for all password data
- **PBKDF2-HMAC-SHA256** key derivation with 100,000+ iterations
- Secure memory allocation with automatic zeroing
- Constant-time comparisons to prevent timing attacks
- Encrypted SQLite database storage

### Core Functionality
- Master password management with key derivation
- Add, modify, and delete password entries
- Search and filter entries by service name
- View passwords with auto-zeroing of memory buffers
- Secure deletion with memory overwriting

### Password Generation
- Customizable password generator
- Pronounceable password option
- Passphrase generation (4-word combinations)
- Configurable character sets and complexity

### Backup & Recovery
- Export/import encrypted backups
- Automatic backup with versioning
- Recovery key generation
- Backup integrity verification

## Installation

### Prerequisites

- CMake 3.20+
- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 2019+)
- OpenSSL 1.1.1+
- SQLite3
- Google Test (for building tests)

### Building

```bash
# Clone the repository
git clone https://github.com/antoschka22/passwordManager.git
cd passwordManager

# Create build directory
mkdir build
cd build

# Configure and build
cmake ..
make

# Install (optional)
sudo make install
```

### Dependencies

**macOS:**
```bash
brew install openssl sqlite3 googletest
```

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get install libssl-dev libsqlite3-dev libgtest-dev cmake build-essential
```

## Usage

### Initialize Database

```bash
pwdmgr init
```

This will create a new encrypted password database at `~/.pwdmgr/passwords.db`.

### Add a Password Entry

```bash
# Interactive mode
pwdmgr add

# With options
pwdmgr add --service github --username myuser --password mypass
```

### Retrieve a Password

```bash
# Copy to clipboard (default)
pwdmgr get github

# Show password
pwdmgr get github --show
```

### List All Entries

```bash
pwdmgr list
```

### Search Entries

```bash
pwdmgr search github
```

### Update an Entry

```bash
pwdmgr update github
```

### Delete an Entry

```bash
pwdmgr delete github
```

### Generate a Password

```bash
# Default settings
pwdmgr generate

# Custom length
pwdmgr generate --length 24

# Without special characters
pwdmgr generate --no-special

# Pronounceable password
pwdmgr generate --pronounceable

# Passphrase
pwdmgr generate --passphrase
```

### Export/Import Backup

```bash
# Export
pwdmgr export backup.pwdb

# Import
pwdmgr import backup.pwdb
```

### Create Automatic Backup

```bash
pwdmgr backup
```

### Change Master Password

```bash
pwdmgr change-password
```

### Help

```bash
# General help
pwdmgr help

# Command-specific help
pwdmgr help add
```

## Configuration

### Environment Variables

- `PWDMGR_DB`: Path to the password database file
- `PWDMGR_BACKUP_DIR`: Directory for automatic backups

### File Locations

- **Database**: `~/.pwdmgr/passwords.db`
- **Backups**: `~/.pwdmgr/backups/`
- **Config**: `~/.pwdmgr/config.json` (optional)

## Security Best Practices

1. **Choose a Strong Master Password**
   - Minimum 12 characters
   - Mix of uppercase, lowercase, numbers, and symbols
   - Avoid common words and patterns

2. **Regular Backups**
   - Use `pwdmgr backup` regularly
   - Store backups in multiple secure locations
   - Verify backup integrity

3. **Secure Environment**
   - Run on trusted systems only
   - Keep your system updated
   - Use secure password storage for backup encryption keys

## Project Structure

```
passwordManager/
├── include/           # Header files
│   ├── types.h
│   ├── secure_memory.h
│   ├── crypt_utils.h
│   ├── database.h
│   ├── password_generator.h
│   ├── backup_manager.h
│   └── cli_utils.h
├── src/              # Source files
│   ├── main.cpp
│   ├── secure_memory.cpp
│   ├── crypt_utils.cpp
│   ├── database.cpp
│   ├── password_generator.cpp
│   ├── backup_manager.cpp
│   └── cli_utils.cpp
├── tests/            # Unit tests
│   ├── CMakeLists.txt
│   ├── test_secure_memory.cpp
│   ├── test_crypt_utils.cpp
│   ├── test_database.cpp
│   ├── test_password_generator.cpp
│   └── test_cli_utils.cpp
├── resources/        # Additional resources
├── CMakeLists.txt
└── README.md
```

## Building Tests

```bash
cd build
cmake .. -DBUILD_TESTING=ON
make
./pwdmgr_tests
```

## Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## License

This project is licensed under the MIT License.

## Acknowledgments

- OpenSSL for cryptographic operations
- SQLite for database storage
- Google Test for testing framework

## Security Considerations

This password manager is designed with security in mind, but remember:

- No software is perfectly secure
- Keep your master password secure and memorable
- Regularly update the software
- Review the code before trusting it with sensitive data
- Consider using hardware security modules for extra protection

## Version

Current version: 1.0.0

## Author

Created as a first C++ project demonstrating secure password management practices.