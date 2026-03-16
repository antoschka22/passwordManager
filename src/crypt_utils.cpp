#include "crypt_utils.h"
#include "secure_memory.h"
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cstring>
#include <stdexcept>
#include <iomanip>
#include <sstream>

namespace pwdmgr {

CryptUtils::~CryptUtils() {
    clear_key();
}

Result<void> CryptUtils::initialize(const std::string& master_password, const std::vector<uint8_t>& salt) {
    auto key_result = derive_key(master_password, salt);
    if (!key_result.success) {
        return Result<void>::error(key_result.error_message);
    }

    key_ = key_result.value;
    salt_ = salt;
    initialized_ = true;

    return Result<void>::ok();
}

Result<std::vector<uint8_t>> CryptUtils::generate_salt() const {
    return SecureMemory::random_bytes(PBKDF2_SALT_SIZE);
}

Result<std::vector<uint8_t>> CryptUtils::derive_key(const std::string& password,
                                                     const std::vector<uint8_t>& salt) const {
    std::vector<uint8_t> key(MASTER_KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          PBKDF2_ITERATIONS,
                          EVP_sha256(),
                          MASTER_KEY_SIZE, key.data()) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to derive key from password");
    }

    return Result<std::vector<uint8_t>>::ok(std::move(key));
}

Result<EncryptedData> CryptUtils::encrypt(const std::string& plaintext) const {
    if (!initialized_) {
        return Result<EncryptedData>::error("CryptUtils not initialized");
    }

    std::vector<uint8_t> plaintext_bytes(plaintext.begin(), plaintext.end());
    return encrypt_bytes(plaintext_bytes);
}

Result<EncryptedData> CryptUtils::encrypt_bytes(const std::vector<uint8_t>& plaintext) const {
    if (!initialized_) {
        return Result<EncryptedData>::error("CryptUtils not initialized");
    }

    // Generate random IV
    auto iv_result = SecureMemory::random_bytes(AES_IV_SIZE);
    if (!iv_result.success) {
        return Result<EncryptedData>::error(iv_result.error_message);
    }

    const std::vector<uint8_t>& iv = iv_result.value;

    // Prepare cipher context
    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result<EncryptedData>::error("Failed to create cipher context");
    }

    // Initialize encryption
    if (EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                          key_.data(), iv.data()) != 1) {
        return Result<EncryptedData>::error("Failed to initialize encryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           AES_IV_SIZE, nullptr) != 1) {
        return Result<EncryptedData>::error("Failed to set IV length");
    }

    // Prepare output buffer
    std::vector<uint8_t> ciphertext(plaintext.size() + AES_TAG_SIZE);
    int len = 0;

    // Encrypt plaintext
    if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &len,
                         plaintext.data(), static_cast<int>(plaintext.size())) != 1) {
        return Result<EncryptedData>::error("Failed to encrypt data");
    }

    int ciphertext_len = len;

    // Finalize encryption
    if (EVP_EncryptFinal_ex(ctx.get(), ciphertext.data() + len, &len) != 1) {
        return Result<EncryptedData>::error("Failed to finalize encryption");
    }

    ciphertext_len += len;

    // Get authentication tag
    std::vector<uint8_t> tag(AES_TAG_SIZE);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG,
                           AES_TAG_SIZE, tag.data()) != 1) {
        return Result<EncryptedData>::error("Failed to get authentication tag");
    }

    // Resize ciphertext to actual size
    ciphertext.resize(ciphertext_len);

    EncryptedData result;
    result.ciphertext = std::move(ciphertext);
    result.iv = iv;
    result.tag = std::move(tag);

    return Result<EncryptedData>::ok(std::move(result));
}

Result<std::string> CryptUtils::decrypt(const EncryptedData& encrypted) const {
    if (!initialized_) {
        return Result<std::string>::error("CryptUtils not initialized");
    }

    auto bytes_result = decrypt_bytes(encrypted);
    if (!bytes_result.success) {
        return Result<std::string>::error(bytes_result.error_message);
    }

    const auto& bytes = bytes_result.value;
    return Result<std::string>::ok(std::string(bytes.begin(), bytes.end()));
}

Result<std::vector<uint8_t>> CryptUtils::decrypt_bytes(const EncryptedData& encrypted) const {
    if (!initialized_) {
        return Result<std::vector<uint8_t>>::error("CryptUtils not initialized");
    }

    if (encrypted.iv.size() != AES_IV_SIZE) {
        return Result<std::vector<uint8_t>>::error("Invalid IV size");
    }

    if (encrypted.tag.size() != AES_TAG_SIZE) {
        return Result<std::vector<uint8_t>>::error("Invalid tag size");
    }

    // Prepare cipher context
    EVP_CIPHER_CTX_Ptr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        return Result<std::vector<uint8_t>>::error("Failed to create cipher context");
    }

    // Initialize decryption
    if (EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                          key_.data(), encrypted.iv.data()) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to initialize decryption");
    }

    // Set IV length
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN,
                           AES_IV_SIZE, nullptr) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to set IV length");
    }

    // Prepare output buffer
    std::vector<uint8_t> plaintext(encrypted.ciphertext.size());
    int len = 0;

    // Decrypt ciphertext
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &len,
                         encrypted.ciphertext.data(),
                         static_cast<int>(encrypted.ciphertext.size())) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to decrypt data");
    }

    int plaintext_len = len;

    // Set expected tag value
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG,
                           AES_TAG_SIZE, const_cast<uint8_t*>(encrypted.tag.data())) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to set authentication tag");
    }

    // Finalize decryption and verify tag
    int ret = EVP_DecryptFinal_ex(ctx.get(), plaintext.data() + len, &len);
    if (ret <= 0) {
        return Result<std::vector<uint8_t>>::error("Decryption failed - authentication tag mismatch");
    }

    plaintext_len += len;
    plaintext.resize(plaintext_len);

    return Result<std::vector<uint8_t>>::ok(std::move(plaintext));
}

void CryptUtils::clear_key() {
    if (!key_.empty()) {
        secure_zero(key_.data(), key_.size());
        key_.clear();
    }
    initialized_ = false;
}

void CryptUtils::secure_zero(void* ptr, size_t size) const {
    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

// KeyManager implementation

Result<MasterPasswordData> KeyManager::generate_master_data(const std::string& master_password) {
    MasterPasswordData data;

    // Generate random salt
    auto salt_result = SecureMemory::random_bytes(PBKDF2_SALT_SIZE);
    if (!salt_result.success) {
        return Result<MasterPasswordData>::error(salt_result.error_message);
    }
    data.salt = salt_result.value;

    // Derive key
    auto key_result = pbkdf2_derive(master_password, data.salt, PBKDF2_ITERATIONS);
    if (!key_result.success) {
        return Result<MasterPasswordData>::error(key_result.error_message);
    }

    // Generate verification hash
    auto hash_result = generate_verification_hash(key_result.value);
    if (!hash_result.success) {
        return Result<MasterPasswordData>::error(hash_result.error_message);
    }
    data.verification_hash = hash_result.value;

    // Securely clear the derived key
    SecureMemory::secure_zero(key_result.value.data(), key_result.value.size());

    return Result<MasterPasswordData>::ok(std::move(data));
}

Result<bool> KeyManager::verify_master_password(const std::string& master_password,
                                                const MasterPasswordData& stored_data) {
    // Derive key from provided password
    auto key_result = pbkdf2_derive(master_password, stored_data.salt, PBKDF2_ITERATIONS);
    if (!key_result.success) {
        return Result<bool>::error(key_result.error_message);
    }

    // Verify against stored hash
    bool valid = verify_key(key_result.value, stored_data.verification_hash);

    // Clear the derived key
    SecureMemory::secure_zero(key_result.value.data(), key_result.value.size());

    return Result<bool>::ok(valid);
}

Result<std::vector<uint8_t>> KeyManager::generate_verification_hash(const std::vector<uint8_t>& key) {
    // Use SHA-256 of the key for verification
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    if (SHA256(key.data(), key.size(), hash.data()) == nullptr) {
        return Result<std::vector<uint8_t>>::error("Failed to generate verification hash");
    }
    return Result<std::vector<uint8_t>>::ok(std::move(hash));
}

bool KeyManager::verify_key(const std::vector<uint8_t>& key, const std::vector<uint8_t>& hash) {
    // Compute hash of provided key and compare
    auto hash_result = generate_verification_hash(key);
    if (!hash_result.success) {
        return false;
    }

    // Use constant-time comparison
    return SecureMemory::constant_time_compare(
        hash_result.value.data(), hash.data(), hash.size());
}

Result<std::vector<uint8_t>> KeyManager::pbkdf2_derive(const std::string& password,
                                                       const std::vector<uint8_t>& salt,
                                                       int iterations) {
    std::vector<uint8_t> key(MASTER_KEY_SIZE);

    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          iterations,
                          EVP_sha256(),
                          MASTER_KEY_SIZE, key.data()) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to derive key using PBKDF2");
    }

    return Result<std::vector<uint8_t>>::ok(std::move(key));
}

// Encoding namespace implementation

namespace Encoding {

std::string base64_encode(const std::vector<uint8_t>& data) {
    static const char* base64_chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string result;
    int val = 0, valb = -6;

    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            result.push_back(base64_chars[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        result.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (result.size() % 4) {
        result.push_back('=');
    }

    return result;
}

Result<std::vector<uint8_t>> base64_decode(const std::string& encoded) {
    static const int table[256] = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, 62, -1, 63,
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63,
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
    };

    std::vector<uint8_t> result;
    int val = 0, valb = -8;

    for (char c : encoded) {
        unsigned char uc = static_cast<unsigned char>(c);
        if (uc >= sizeof(table) || table[uc] == -1) {
            break;
        }
        val = (val << 6) + table[uc];
        valb += 6;
        if (valb >= 0) {
            result.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return Result<std::vector<uint8_t>>::ok(result);
}

std::string hex_encode(const std::vector<uint8_t>& data) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t byte : data) {
        oss << std::setw(2) << static_cast<int>(byte);
    }
    return oss.str();
}

Result<std::vector<uint8_t>> hex_decode(const std::string& encoded) {
    if (encoded.size() % 2 != 0) {
        return Result<std::vector<uint8_t>>::error("Invalid hex string length");
    }

    std::vector<uint8_t> result;
    result.reserve(encoded.size() / 2);

    for (size_t i = 0; i < encoded.size(); i += 2) {
        std::string byte_str = encoded.substr(i, 2);
        try {
            uint8_t byte = static_cast<uint8_t>(std::stoi(byte_str, nullptr, 16));
            result.push_back(byte);
        } catch (...) {
            return Result<std::vector<uint8_t>>::error("Invalid hex string");
        }
    }

    return Result<std::vector<uint8_t>>::ok(result);
}

} // namespace Encoding

// Checksum namespace implementation

namespace Checksum {

Result<std::string> compute_sha256(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    if (SHA256(data.data(), data.size(), hash.data()) == nullptr) {
        return Result<std::string>::error("Failed to compute SHA-256 checksum");
    }

    return Result<std::string>::ok(Encoding::hex_encode(hash));
}

bool verify_sha256(const std::vector<uint8_t>& data, const std::string& expected) {
    auto checksum_result = compute_sha256(data);
    if (!checksum_result.success) {
        return false;
    }

    return SecureMemory::constant_time_compare(
        checksum_result.value.data(), expected.data(),
        std::min(checksum_result.value.size(), expected.size()));
}

} // namespace Checksum

} // namespace pwdmgr