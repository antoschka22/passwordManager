/**
 * @file crypt_utils.h
 * @brief Cryptographic utilities for AES-256-GCM encryption and key management.
 *
 * This header provides the core cryptographic functionality for the password manager:
 * - AES-256-GCM encryption/decryption for stored passwords
 * - PBKDF2-HMAC-SHA256 key derivation from master password
 * - Key verification and management utilities
 * - Base64 and hex encoding/decoding
 * - SHA-256 checksum computation
 *
 * Security Features:
 * - 256-bit encryption keys (AES-256)
 * - 128-bit authentication tags (GCM mode)
 * - 128-bit initialization vectors
 * - 100,000 iteration PBKDF2 key derivation
 * - Constant-time key verification
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_CRYPT_UTILS_H
#define PASSWORD_MANAGER_CRYPT_UTILS_H

#include <vector>
#include <string>
#include <memory>
#include <evp.h>
#include "types.h"

namespace pwdmgr {

// =============================================================================
// CryptUtils Class
// =============================================================================

/**
 * @class CryptUtils
 * @brief Core cryptographic utilities for AES-256-GCM encryption.
 *
 * This class provides the primary encryption and decryption functionality
 * for the password manager. It uses AES-256 in GCM (Galois/Counter Mode)
 * which provides both confidentiality and authenticity.
 *
 * GCM Mode Benefits:
 * - Authenticated encryption: detects tampering
 * - Parallelizable encryption/decryption
 * - No padding required
 * - 128-bit authentication tag
 *
 * Usage Flow:
 * 1. Initialize with master password and salt
 * 2. Encrypt/decrypt as needed
 * 3. Clear key when done (or let destructor handle it)
 *
 * @code
 * CryptUtils crypto;
 * auto salt = crypto.generate_salt();
 * crypto.initialize(master_password, salt.value);
 *
 * auto encrypted = crypto.encrypt("secret_password");
 * auto decrypted = crypto.decrypt(encrypted.value);
 *
 * crypto.clear_key(); // Manual cleanup
 * @endcode
 *
 * @note This class stores the derived encryption key in memory. Always call
 *       clear_key() or let the destructor handle cleanup when done.
 */
class CryptUtils {
public:
    /**
     * @brief Default constructor.
     *
     * Creates an uninitialized CryptUtils instance. Call initialize()
     * before using encryption/decryption operations.
     */
    CryptUtils() = default;

    /**
     * @brief Destructor - securely clears the encryption key.
     *
     * Ensures the encryption key is zeroed from memory when the object
     * is destroyed.
     */
    ~CryptUtils();

    // -------------------------------------------------------------------------
    // Initialization
    // -------------------------------------------------------------------------

    /**
     * @brief Initializes the cryptographic utilities with master credentials.
     *
     * Derives an encryption key from the master password using PBKDF2-HMAC-SHA256
     * and stores it for subsequent encryption operations.
     *
     * @param master_password The user's master password
     * @param salt A random salt value (typically 32 bytes)
     * @return Result indicating success or containing an error message
     *
     * @note The salt should be generated using generate_salt() and stored
     *       alongside the encrypted data. The same salt must be used for
     *       subsequent initializations to derive the same key.
     *
     * @warning The master password should be securely cleared after calling
     *          this method.
     */
    Result<void> initialize(const std::string& master_password, const std::vector<uint8_t>& salt);

    /**
     * @brief Generates a cryptographically secure random salt.
     *
     * Creates a random salt value suitable for use with PBKDF2 key derivation.
     * The salt should be stored alongside encrypted data and reused for
     * subsequent key derivations.
     *
     * @return Result containing 32 random bytes on success
     */
    Result<std::vector<uint8_t>> generate_salt() const;

    /**
     * @brief Derives an encryption key from a password.
     *
     * Uses PBKDF2-HMAC-SHA256 to derive a 256-bit key from the password.
     * This key is NOT stored internally; it's returned to the caller.
     *
     * @param password The password to derive from
     * @param salt The salt value
     * @return Result containing the derived key on success
     *
     * @note This method can be called without initialization. The initialize()
     *       method calls this internally and stores the result.
     */
    Result<std::vector<uint8_t>> derive_key(const std::string& password,
                                             const std::vector<uint8_t>& salt) const;

    // -------------------------------------------------------------------------
    // Encryption/Decryption
    // -------------------------------------------------------------------------

    /**
     * @brief Encrypts a string using AES-256-GCM.
     *
     * Encrypts the plaintext string and returns an EncryptedData structure
     * containing the ciphertext, IV, and authentication tag.
     *
     * @param plaintext The string to encrypt
     * @return Result containing EncryptedData on success
     *
     * @pre initialize() must have been called successfully
     *
     * @note A unique IV is generated for each encryption operation. This
     *       means encrypting the same plaintext twice produces different
     *       ciphertexts, which is important for security.
     */
    Result<EncryptedData> encrypt(const std::string& plaintext) const;

    /**
     * @brief Decrypts data using AES-256-GCM.
     *
     * Decrypts the EncryptedData structure and returns the original plaintext.
     * Also verifies the authentication tag to detect tampering.
     *
     * @param encrypted The encrypted data structure
     * @return Result containing the decrypted string on success
     *
     * @pre initialize() must have been called successfully
     *
     * @throws Returns error if authentication tag verification fails,
     *         indicating potential data corruption or tampering.
     */
    Result<std::string> decrypt(const EncryptedData& encrypted) const;

    /**
     * @brief Encrypts raw bytes using AES-256-GCM.
     *
     * Similar to encrypt() but works with raw byte arrays instead of strings.
     * Useful for encrypting binary data.
     *
     * @param plaintext The bytes to encrypt
     * @return Result containing EncryptedData on success
     */
    Result<EncryptedData> encrypt_bytes(const std::vector<uint8_t>& plaintext) const;

    /**
     * @brief Decrypts to raw bytes using AES-256-GCM.
     *
     * Similar to decrypt() but returns raw bytes instead of a string.
     *
     * @param encrypted The encrypted data structure
     * @return Result containing the decrypted bytes on success
     */
    Result<std::vector<uint8_t>> decrypt_bytes(const EncryptedData& encrypted) const;

    // -------------------------------------------------------------------------
    // State Management
    // -------------------------------------------------------------------------

    /**
     * @brief Checks if the utilities are initialized.
     *
     * @return true if initialize() has been called successfully
     */
    bool is_initialized() const { return initialized_; }

    /**
     * @brief Gets the current encryption key.
     *
     * @return Const reference to the key bytes
     *
     * @warning The returned key is sensitive. Do not log or display it.
     */
    const std::vector<uint8_t>& get_key() const { return key_; }

    /**
     * @brief Securely clears the encryption key from memory.
     *
     * Zeros all key bytes and marks the utilities as uninitialized.
     * This should be called when the key is no longer needed, or when
     * preparing to re-initialize with a different password.
     *
     * @note This is automatically called by the destructor.
     */
    void clear_key();

private:
    /**
     * @brief Custom deleter for EVP_CIPHER_CTX pointers.
     *
     * Ensures OpenSSL cipher contexts are properly freed using
     * EVP_CIPHER_CTX_free when the unique_ptr goes out of scope.
     */
    struct EVP_CIPHER_CTX_Deleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    };

    /** @brief Type alias for unique_ptr with custom deleter. */
    using EVP_CIPHER_CTX_Ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

    bool initialized_ = false;              ///< Whether utilities are ready for use
    std::vector<uint8_t> key_;               ///< The derived encryption key
    std::vector<uint8_t> salt_;              ///< The salt used for key derivation

    /**
     * @brief Securely zeros a memory region.
     *
     * Internal helper that uses volatile pointers to prevent
     * compiler optimizations from removing the zeroing.
     *
     * @param ptr Pointer to memory
     * @param size Size in bytes
     */
    void secure_zero(void* ptr, size_t size) const;
};

// =============================================================================
// KeyManager Class
// =============================================================================

/**
 * @class KeyManager
 * @brief Utilities for master password management and verification.
 *
 * This class provides static methods for:
 * - Generating master password data (salt, verification hash)
 * - Verifying master passwords
 * - Creating and checking verification hashes
 *
 * The master password flow:
 * 1. User creates master password -> generate_master_data()
 * 2. Store salt and verification hash in database
 * 3. User logs in -> verify_master_password()
 * 4. If valid, derive key for encryption operations
 */
class KeyManager {
public:
    /**
     * @brief Generates data for a new master password.
     *
     * Creates a random salt and derives a verification hash from the password.
     * Both should be stored in the database for later verification.
     *
     * @param master_password The user's master password
     * @return Result containing MasterPasswordData on success
     *
     * @warning The master password should be securely cleared after calling.
     *          Do not store the password itself, only the returned data.
     */
    static Result<MasterPasswordData> generate_master_data(const std::string& master_password);

    /**
     * @brief Verifies a master password against stored data.
     *
     * Derives a key from the provided password and compares it against
     * the stored verification hash using constant-time comparison.
     *
     * @param master_password The password to verify
     * @param stored_data The data stored from generate_master_data()
     * @return Result containing true if password matches, false otherwise
     *
     * @note Uses constant-time comparison to prevent timing attacks.
     */
    static Result<bool> verify_master_password(const std::string& master_password,
                                                const MasterPasswordData& stored_data);

    /**
     * @brief Generates a verification hash from a key.
     *
     * Creates a SHA-256 hash of the key for verification purposes.
     * This hash can be stored and used to verify the key later without
     * exposing the key itself.
     *
     * @param key The encryption key to hash
     * @return Result containing the 32-byte hash on success
     */
    static Result<std::vector<uint8_t>> generate_verification_hash(const std::vector<uint8_t>& key);

    /**
     * @brief Verifies a key against a stored hash.
     *
     * Computes the hash of the provided key and compares it against the
     * stored hash using constant-time comparison.
     *
     * @param key The key to verify
     * @param hash The stored verification hash
     * @return true if the key matches
     */
    static bool verify_key(const std::vector<uint8_t>& key, const std::vector<uint8_t>& hash);

private:
    /**
     * @brief Derives a key using PBKDF2-HMAC-SHA256.
     *
     * Internal helper that performs the actual PBKDF2 key derivation.
     *
     * @param password The password to derive from
     * @param salt The salt value
     * @param iterations Number of iterations (use PBKDF2_ITERATIONS)
     * @return Result containing the derived key on success
     */
    static Result<std::vector<uint8_t>> pbkdf2_derive(const std::string& password,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations);
};

// =============================================================================
// Encoding Namespace
// =============================================================================

/**
 * @namespace Encoding
 * @brief Utility functions for encoding and decoding binary data.
 *
 * Provides functions for converting between binary data and text formats
 * that are safe for storage and transmission.
 */
namespace Encoding {
    /**
     * @brief Encodes binary data as base64.
     *
     * Converts arbitrary binary data to a base64-encoded string.
     * Base64 is useful for storing binary data in text-based formats.
     *
     * @param data The binary data to encode
     * @return Base64-encoded string (no line breaks)
     */
    std::string base64_encode(const std::vector<uint8_t>& data);

    /**
     * @brief Decodes base64-encoded data.
     *
     * Converts a base64 string back to binary data.
     *
     * @param encoded The base64-encoded string
     * @return Result containing the decoded bytes on success
     */
    Result<std::vector<uint8_t>> base64_decode(const std::string& encoded);

    /**
     * @brief Encodes binary data as hexadecimal.
     *
     * Converts binary data to a lowercase hexadecimal string.
     * Useful for displaying hashes and salts in a readable format.
     *
     * @param data The binary data to encode
     * @return Hexadecimal string (lowercase, no prefix)
     */
    std::string hex_encode(const std::vector<uint8_t>& data);

    /**
     * @brief Decodes hexadecimal-encoded data.
     *
     * Converts a hexadecimal string back to binary data.
     *
     * @param encoded The hexadecimal string (case-insensitive)
     * @return Result containing the decoded bytes on success
     */
    Result<std::vector<uint8_t>> hex_decode(const std::string& encoded);
}

// =============================================================================
// Checksum Namespace
// =============================================================================

/**
 * @namespace Checksum
 * @brief Utility functions for computing and verifying checksums.
 *
 * Provides SHA-256 based checksum functionality for data integrity
 * verification, particularly for backup files.
 */
namespace Checksum {
    /**
     * @brief Computes SHA-256 checksum of data.
     *
     * Calculates a SHA-256 hash of the input data and returns it
     * as a hexadecimal string.
     *
     * @param data The binary data to hash
     * @return Result containing the 64-character hex string on success
     */
    Result<std::string> compute_sha256(const std::vector<uint8_t>& data);

    /**
     * @brief Verifies data against an expected checksum.
     *
     * Computes the SHA-256 checksum of the data and compares it against
     * the expected value using constant-time comparison.
     *
     * @param data The binary data to verify
     * @param expected The expected checksum (hex string)
     * @return true if checksums match, false otherwise
     *
     * @note Uses constant-time comparison to prevent timing attacks.
     */
    bool verify_sha256(const std::vector<uint8_t>& data, const std::string& expected);
}

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_CRYPT_UTILS_H