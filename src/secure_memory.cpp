#include "secure_memory.h"
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace pwdmgr {

void SecureMemory::secure_zero(void* ptr, size_t size) {
    if (!ptr || size == 0) return;

    volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < size; ++i) {
        p[i] = 0;
    }
}

bool SecureMemory::constant_time_compare(const void* a, const void* b, size_t size) {
    if (!a || !b || size == 0) return false;

    const volatile uint8_t* pa = reinterpret_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* pb = reinterpret_cast<const volatile uint8_t*>(b);

    volatile uint8_t result = 0;
    for (size_t i = 0; i < size; ++i) {
        result |= (pa[i] ^ pb[i]);
    }

    return result == 0;
}

Result<std::vector<uint8_t>> SecureMemory::random_bytes(size_t count) {
    if (count == 0) {
        return Result<std::vector<uint8_t>>::ok({});
    }

    std::vector<uint8_t> bytes(count);
    if (RAND_bytes(bytes.data(), static_cast<int>(count)) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to generate random bytes");
    }

    return Result<std::vector<uint8_t>>::ok(std::move(bytes));
}

Result<std::vector<uint8_t>> SecureMemory::hash_password(const std::string& password,
                                                          const std::vector<uint8_t>& salt,
                                                          int iterations) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    if (PKCS5_PBKDF2_HMAC(password.data(), static_cast<int>(password.size()),
                          salt.data(), static_cast<int>(salt.size()),
                          iterations,
                          EVP_sha256(),
                          SHA256_DIGEST_LENGTH, hash.data()) != 1) {
        return Result<std::vector<uint8_t>>::error("Failed to hash password");
    }

    return Result<std::vector<uint8_t>>::ok(std::move(hash));
}

bool SecureMemory::verify_password(const std::vector<uint8_t>& stored_hash,
                                     const std::vector<uint8_t>& provided_hash) {
    if (stored_hash.size() != provided_hash.size()) {
        return false;
    }
    return constant_time_compare(stored_hash.data(), provided_hash.data(), stored_hash.size());
}

} // namespace pwdmgr