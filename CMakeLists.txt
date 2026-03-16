cmake_minimum_required(VERSION 3.20)
project(passwordManager VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags for security
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror -Wshadow -Wold-style-cast -Wcast-align)
    add_compile_options(-fstack-protector-strong -fPIE)
    add_link_options(-fPIE -pie)
endif()

# Find required packages
find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)

# Source files
set(SOURCES
    src/main.cpp
    src/secure_memory.cpp
    src/crypt_utils.cpp
    src/database.cpp
    src/cli_utils.cpp
    src/password_generator.cpp
    src/backup_manager.cpp
)

# Header files
set(HEADERS
    include/secure_memory.h
    include/crypt_utils.h
    include/database.h
    include/cli_utils.h
    include/password_generator.h
    include/backup_manager.h
    include/types.h
)

# Create executable
add_executable(pwdmgr ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(pwdmgr PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Link libraries
target_link_libraries(pwdmgr PRIVATE
    OpenSSL::Crypto
    SQLite3::SQLite3
)

# Platform-specific settings
if(APPLE)
    # macOS specific settings
    target_link_libraries(pwdmgr PRIVATE
        "-framework Security"
        "-framework LocalAuthentication"
    )
    target_compile_definitions(pwdmgr PRIVATE MACOS_AVAILABLE)
elseif(UNIX)
    # Linux specific settings
    target_link_libraries(pwdmgr PRIVATE
        pam
    )
endif()

# Installation
install(TARGETS pwdmgr DESTINATION bin)

# Enable testing
enable_testing()
add_subdirectory(tests)