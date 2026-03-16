#ifndef PASSWORD_MANAGER_CRYPT_UTILS_H
#define PASSWORD_MANAGER_CRYPT_UTILS_H

#include <vector>
#include <string>
#include <memory>
#include <evp.h>
#include "types.h"

namespace pwdmgr {

// Cryptographic utilities for AES-256-GCM encryption/decryption
class CryptUtils {
public:
    CryptUtils() = default;
    ~CryptUtils();

    // Initialize with master password and salt
    Result<void> initialize(const std::string& master_password, const std::vector<uint8_t>& salt);

    // Generate a new salt
    Result<std::vector<uint8_t>> generate_salt() const;

    // Derive encryption key from master password
    Result<std::vector<uint8_t>> derive_key(const std::string& password,
                                             const std::vector<uint8_t>& salt) const;

    // Encrypt data using AES-256-GCM
    Result<EncryptedData> encrypt(const std::string& plaintext) const;

    // Decrypt data using AES-256-GCM
    Result<std::string> decrypt(const EncryptedData& encrypted) const;

    // Encrypt raw bytes
    Result<EncryptedData> encrypt_bytes(const std::vector<uint8_t>& plaintext) const;

    // Decrypt to raw bytes
    Result<std::vector<uint8_t>> decrypt_bytes(const EncryptedData& encrypted) const;

    // Check if initialized
    bool is_initialized() const { return initialized_; }

    // Get the current encryption key
    const std::vector<uint8_t>& get_key() const { return key_; }

    // Securely clear the key from memory
    void clear_key();

private:
    struct EVP_CIPHER_CTX_Deleter {
        void operator()(EVP_CIPHER_CTX* ctx) const {
            if (ctx) {
                EVP_CIPHER_CTX_free(ctx);
            }
        }
    };

    using EVP_CIPHER_CTX_Ptr = std::unique_ptr<EVP_CIPHER_CTX, EVP_CIPHER_CTX_Deleter>;

    bool initialized_ = false;
    std::vector<uint8_t> key_;
    std::vector<uint8_t> salt_;

    // Zero sensitive data on destruction
    void secure_zero(void* ptr, size_t size) const;
};

// Helper class for key management
class KeyManager {
public:
    // Generate a new master key
    static Result<MasterPasswordData> generate_master_data(const std::string& master_password);

    // Verify master password
    static Result<bool> verify_master_password(const std::string& master_password,
                                                const MasterPasswordData& stored_data);

    // Generate verification hash
    static Result<std::vector<uint8_t>> generate_verification_hash(const std::vector<uint8_t>& key);

    // Verify key against hash
    static bool verify_key(const std::vector<uint8_t>& key, const std::vector<uint8_t>& hash);

private:
    // Use PBKDF2 for key derivation
    static Result<std::vector<uint8_t>> pbkdf2_derive(const std::string& password,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations);
};

// Utility functions for data encoding/decoding
namespace Encoding {
    // Base64 encode
    std::string base64_encode(const std::vector<uint8_t>& data);

    // Base64 decode
    Result<std::vector<uint8_t>> base64_decode(const std::string& encoded);

    // Hex encode
    std::string hex_encode(const std::vector<uint8_t>& data);

    // Hex decode
    Result<std::vector<uint8_t>> hex_decode(const std::string& encoded);
}

// Checksum utilities for backup verification
namespace Checksum {
    // Compute SHA-256 checksum
    Result<std::string> compute_sha256(const std::vector<uint8_t>& data);

    // Verify checksum
    bool verify_sha256(const std::vector<uint8_t>& data, const std::string& expected);
}

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_CRYPT_UTILS_H