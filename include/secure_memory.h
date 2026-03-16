#ifndef PASSWORD_MANAGER_SECURE_MEMORY_H
#define PASSWORD_MANAGER_SECURE_MEMORY_H

#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <type_traits>
#include "types.h"

namespace pwdmgr {

// Secure memory container that zeros memory on destruction
template<typename T>
class SecureBuffer {
public:
    SecureBuffer() = default;

    explicit SecureBuffer(size_t size) : data_(size) {}

    SecureBuffer(size_t size, const T& value) : data_(size, value) {}

    explicit SecureBuffer(const std::vector<T>& other) : data_(other) {}

    SecureBuffer(const T* ptr, size_t size) : data_(ptr, ptr + size) {}

    ~SecureBuffer() {
        secure_zero();
    }

    // Disable copy to prevent accidental copies of sensitive data
    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    // Enable move
    SecureBuffer(SecureBuffer&& other) noexcept {
        data_ = std::move(other.data_);
    }

    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            secure_zero();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    size_t size() const { return data_.size(); }

    bool empty() const { return data_.empty(); }

    T* data() { return data_.data(); }

    const T* data() const { return data_.data(); }

    T& operator[](size_t index) { return data_[index]; }

    const T& operator[](size_t index) const { return data_[index]; }

    const T* begin() const { return data_.data(); }

    const T* end() const { return data_.data() + data_.size(); }

    T* begin() { return data_.data(); }

    T* end() { return data_.data() + data_.size(); }

    void resize(size_t new_size) {
        secure_zero();
        data_.resize(new_size);
    }

    void push_back(const T& value) {
        data_.push_back(value);
    }

    // Secure comparison (constant-time)
    bool constant_time_compare(const SecureBuffer<T>& other) const {
        if (data_.size() != other.data_.size()) {
            return false;
        }

        volatile uint8_t result = 0;
        for (size_t i = 0; i < data_.size(); ++i) {
            result |= (data_[i] ^ other.data_[i]);
        }

        return result == 0;
    }

    // Convert to vector (use with caution - copies sensitive data)
    std::vector<T> to_vector() const {
        return data_;
    }

private:
    void secure_zero() {
        volatile T* ptr = data_.data();
        for (size_t i = 0; i < data_.size(); ++i) {
            ptr[i] = 0;
        }
        data_.clear();
    }

    std::vector<T> data_;
};

// Secure string wrapper
class SecureString {
public:
    SecureString() = default;

    explicit SecureString(const std::string& str) {
        data_.resize(str.size());
        std::memcpy(data_.data(), str.data(), str.size());
    }

    explicit SecureString(size_t size) : data_(size) {}

    ~SecureString() = default;

    SecureString(const SecureString&) = delete;
    SecureString& operator=(const SecureString&) = delete;

    SecureString(SecureString&& other) noexcept = default;
    SecureString& operator=(SecureString&& other) noexcept = default;

    size_t size() const { return data_.size(); }

    size_t length() const { return data_.size(); }

    bool empty() const { return data_.empty(); }

    const char* c_str() const { return reinterpret_cast<const char*>(data_.data()); }

    char* data() { return reinterpret_cast<char*>(data_.data()); }

    const char* data() const { return reinterpret_cast<const char*>(data_.data()); }

    void resize(size_t new_size) {
        data_.resize(new_size);
    }

    void append(const std::string& str) {
        auto old_size = data_.size();
        data_.resize(old_size + str.size());
        std::memcpy(data_.data() + old_size, str.data(), str.size());
    }

    // Convert to regular string (use with caution - copies sensitive data)
    std::string to_string() const {
        return std::string(c_str(), size());
    }

    // Constant-time comparison
    bool constant_time_compare(const SecureString& other) const {
        return data_.constant_time_compare(other.data_);
    }

private:
    SecureBuffer<uint8_t> data_;
};

// Secure memory utilities
class SecureMemory {
public:
    // Zero memory securely
    static void secure_zero(void* ptr, size_t size);

    // Constant-time memory comparison
    static bool constant_time_compare(const void* a, const void* b, size_t size);

    // Generate random bytes
    static Result<std::vector<uint8_t>> random_bytes(size_t count);

    // Hash password using PBKDF2
    static Result<std::vector<uint8_t>> hash_password(const std::string& password,
                                                      const std::vector<uint8_t>& salt,
                                                      int iterations);

    // Verify password (constant-time)
    static bool verify_password(const std::vector<uint8_t>& stored_hash,
                                 const std::vector<uint8_t>& provided_hash);
};

// RAII wrapper for sensitive data
template<typename T>
class SecureValue {
public:
    explicit SecureValue(const T& value) : value_(value) {}

    ~SecureValue() {
        secure_zero(reinterpret_cast<void*>(&value_), sizeof(T));
    }

    SecureValue(const SecureValue&) = delete;
    SecureValue& operator=(const SecureValue&) = delete;

    SecureValue(SecureValue&& other) noexcept {
        std::memcpy(&value_, &other.value_, sizeof(T));
        secure_zero(reinterpret_cast<void*>(&other.value_), sizeof(T));
    }

    SecureValue& operator=(SecureValue&& other) noexcept {
        if (this != &other) {
            secure_zero(reinterpret_cast<void*>(&value_), sizeof(T));
            std::memcpy(&value_, &other.value_, sizeof(T));
            secure_zero(reinterpret_cast<void*>(&other.value_), sizeof(T));
        }
        return *this;
    }

    const T& get() const { return value_; }

    T& get() { return value_; }

private:
    void secure_zero(void* ptr, size_t size) {
        volatile uint8_t* p = reinterpret_cast<volatile uint8_t*>(ptr);
        for (size_t i = 0; i < size; ++i) {
            p[i] = 0;
        }
    }

    T value_;
};

} // namespace pwdmgr

#endif // PASSWORD_MANAGER_SECURE_MEMORY_H