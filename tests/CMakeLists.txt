# Tests CMakeLists.txt
cmake_minimum_required(VERSION 3.20)

# Enable testing
enable_testing()

# Find Google Test
find_package(GTest QUIET)

if(GTest_FOUND)
    # Test executable
    add_executable(pwdmgr_tests
        test_secure_memory.cpp
        test_crypt_utils.cpp
        test_database.cpp
        test_password_generator.cpp
        test_cli_utils.cpp
    )

    target_include_directories(pwdmgr_tests PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
    )

    target_link_libraries(pwdmgr_tests PRIVATE
        GTest::GTest
        GTest::Main
        OpenSSL::Crypto
        SQLite3::SQLite3
    )

    # Add tests
    add_test(NAME SecureMemoryTests COMMAND pwdmgr_tests --gtest_filter=SecureMemory*)
    add_test(NAME CryptUtilsTests COMMAND pwdmgr_tests --gtest_filter=CryptUtils*)
    add_test(NAME DatabaseTests COMMAND pwdmgr_tests --gtest_filter=Database*)
    add_test(NAME PasswordGeneratorTests COMMAND pwdmgr_tests --gtest_filter=PasswordGenerator*)
    add_test(NAME CliUtilsTests COMMAND pwdmgr_tests --gtest_filter=CliUtils*)

    # Run all tests
    add_test(NAME AllTests COMMAND pwdmgr_tests)
else()
    message(WARNING "Google Test not found. Tests will not be built.")
endif()