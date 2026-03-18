# Build Instructions for Password Manager CLI

## Prerequisites Installation

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install openssl sqlite3 googletest cmake

# Make OpenSSL accessible
export PKG_CONFIG_PATH="/usr/local/opt/openssl/lib/pkgconfig:$PKG_CONFIG_PATH"
```

### Linux (Ubuntu/Debian)

```bash
# Update package list
sudo apt-get update

# Install build tools
sudo apt-get install build-essential cmake git

# Install dependencies
sudo apt-get install libssl-dev libsqlite3-dev libgtest-dev

# If GoogleTest is not available, build from source
cd /tmp
git clone https://github.com/google/googletest.git
cd googletest
mkdir build && cd build
cmake ..
make
sudo make install
```

### Linux (Fedora/RHEL)

```bash
# Install dependencies
sudo dnf install gcc-c++ cmake make openssl-devel sqlite-devel gtest-devel
```

## Building the Project

### Standard Build

```bash
# Navigate to project directory
cd /path/to/passwordManager

# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Build the project
make

# Install (optional, requires sudo)
sudo make install
```

### Build with Tests

```bash
# Configure with testing enabled
cmake .. -DBUILD_TESTING=ON

# Build
make

# Run tests
./pwdmgr_tests

# Or run specific tests
./pwdmgr_tests --gtest_filter=SecureMemory*
```

### Debug Build

```bash
# Configure for debug
cmake .. -DCMAKE_BUILD_TYPE=Debug

# Build
make
```

### Release Build

```bash
# Configure for release
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build
make
```

## Building with Specific Compiler

### Using GCC

```bash
cmake .. -DCMAKE_CXX_COMPILER=g++
make
```

### Using Clang

```bash
cmake .. -DCMAKE_CXX_COMPILER=clang++
make
```

## Common Build Issues

### OpenSSL not found

```bash
# macOS - specify OpenSSL path
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl

# Linux - specify OpenSSL path
cmake .. -DOPENSSL_ROOT_DIR=/usr/local/ssl
```

### SQLite not found

```bash
# Specify SQLite path
cmake .. -DSQLITE3_ROOT_DIR=/usr/local
```

### Google Test not found (tests won't build)

```bash
# Tests are optional, build without them
cmake .. -DBUILD_TESTING=OFF
make
```

## Running the Application

### First Time Setup

```bash
# Initialize the database
./pwdmgr init

# Follow prompts to create master password
```

### Basic Usage

```bash
# Add a password
./pwdmgr add

# Get a password
./pwdmgr get <service>

# List all passwords
./pwdmgr list

# Generate a password
./pwdmgr generate

# Get help
./pwdmgr help
```

## Development

### Code Style

The project follows these conventions:
- C++20 standard
- 4-space indentation
- CamelCase for classes and functions
- snake_case for variables and member functions
- Prefix private members with underscore

### Adding New Features

1. Create header file in `include/`
2. Create implementation in `src/`
3. Update `CMakeLists.txt` with new files
4. Add tests in `tests/`
5. Update README.md if user-facing

### Running with GDB (Debugging)

```bash
# Debug build first
cmake .. -DCMAKE_BUILD_TYPE=Debug
make

# Run with GDB
gdb ./pwdmgr

# GDB commands:
(gdb) break main
(gdb) run
(gdb) next
(gdb) print variable_name
(gdb) continue
(gdb) quit
```

### Using Valgrind (Memory Checking)

```bash
# Install Valgrind
# macOS: brew install valgrind
# Linux: sudo apt-get install valgrind

# Run Valgrind
valgrind --leak-check=full --show-leak-kinds=all ./pwdmgr init
```

## Cross-Compilation

### Cross-compile for Linux from macOS

```bash
# Requires appropriate toolchain
cmake .. -DCMAKE_TOOLCHAIN_FILE=path/to/toolchain.cmake
make
```

### Cross-compile for Windows from Linux

```bash
# Requires MinGW
cmake .. -DCMAKE_CXX_COMPILER=x86_64-w64-mingw32-g++
make
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Build and Test

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest

    steps:
    - uses: actions/checkout@v2

    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install -y build-essential cmake libssl-dev libsqlite3-dev libgtest-dev

    - name: Build
      run: |
        mkdir build
        cd build
        cmake ..
        make

    - name: Test
      run: |
        cd build
        ./pwdmgr_tests
```

## Package Creation

### Creating a tarball

```bash
# Build release version
cmake .. -DCMAKE_BUILD_TYPE=Release
make

# Create package
make package
```

### Creating an RPM (Linux)

```bash
cmake .. -DCPACK_GENERATOR=RPM
make package
```

### Creating a Debian package

```bash
cmake .. -DCPACK_GENERATOR=DEB
make package
```

## Troubleshooting

### "command not found: pwdmgr"

After installation, ensure the installation prefix is in your PATH:

```bash
# Add to ~/.bashrc or ~/.zshrc
export PATH="/usr/local/bin:$PATH"
```

### "Library not found: libssl"

Link OpenSSL properly:

```bash
export LD_LIBRARY_PATH="/usr/local/opt/openssl/lib:$LD_LIBRARY_PATH"
```

### Permission denied when creating database

Ensure your home directory is writable:

```bash
chmod 700 ~/.pwdmgr
```

## Advanced Configuration

### Custom Installation Prefix

```bash
cmake .. -DCMAKE_INSTALL_PREFIX=/opt/pwdmgr
make
sudo make install
```

### Disable Colors in Output

```bash
cmake .. -DDISABLE_COLORS=ON
make
```

### Custom Compiler Flags

```bash
cmake .. -DCMAKE_CXX_FLAGS="-O3 -march=native"
make
```

## Cleaning Build Artifacts

```bash
# From build directory
make clean

# Remove entire build directory
cd ..
rm -rf build
```