/**
 * @file secure_memory.h
 * @brief Secure memory management utilities for sensitive data handling.
 *
 * This header provides secure memory containers and utilities designed to
 * protect sensitive data (like passwords and encryption keys) from being
 * exposed in memory dumps, swapped to disk, or left in accessible memory
 * after use.
 *
 * Key features:
 * - SecureBuffer: A vector-like container that zeroizes memory on destruction
 * - SecureString: A string wrapper that securely clears its contents
 * - SecureMemory: Static utilities for secure memory operations
 * - SecureValue: RAII wrapper for individual sensitive values
 *
 * @warning These containers are NOT thread-safe. External synchronization is
 *          required when accessing the same instance from multiple threads.
 *
 * @author Password Manager Team
 * @version 1.0
 */

#ifndef PASSWORD_MANAGER_SECURE_MEMORY_H
#define PASSWORD_MANAGER_SECURE_MEMORY_H

#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <type_traits>
#include "types.h"

namespace pwdmgr {

// =============================================================================
// SecureBuffer Template
// =============================================================================

/**
 * @class SecureBuffer
 * @brief A secure container that automatically zeros memory on destruction.
 *
 * This template class provides a vector-like interface for storing sensitive
 * data with automatic memory zeroing. When the buffer is destroyed or resized,
 * all memory is securely overwritten with zeros before deallocation.
 *
 * Key security features:
 * - Automatic zeroing on destruction
 * - Copy operations are disabled to prevent accidental data leaks
 * - Move operations transfer ownership without copying
 * - Constant-time comparison to prevent timing attacks
 *
 * @tparam T The element type (typically uint8_t for byte buffers)
 *
 * @code
 * // Create a secure buffer for a password
 * SecureBuffer<uint8_t> password(32);
 * // ... fill with password data ...
 * // Buffer is automatically zeroed when it goes out of scope
 * @endcode
 *
 * @note For string data, prefer SecureString which provides a more convenient
 *       interface for text operations.
 */
template<typename T>
class SecureBuffer {
public:
    // -------------------------------------------------------------------------
    // Constructors and Destructor
    // -------------------------------------------------------------------------

    /** @brief Default constructor creates an empty buffer. */
    SecureBuffer() = default;

    /**
     * @brief Constructs a buffer of the specified size.
     *
     * Elements are value-initialized (zeroed for fundamental types).
     *
     * @param size Number of elements to allocate
     */
    explicit SecureBuffer(size_t size) : data_(size) {}

    /**
     * @brief Constructs a buffer filled with a specific value.
     *
     * @param size Number of elements to allocate
     * @param value Value to fill the buffer with
     */
    SecureBuffer(size_t size, const T& value) : data_(size, value) {}

    /**
     * @brief Constructs a buffer from an existing vector.
     *
     * @warning This copies the data. For large buffers, prefer the
     *          pointer-based constructor to avoid copying.
     *
     * @param other Vector to copy from
     */
    explicit SecureBuffer(const std::vector<T>& other) : data_(other) {}

    /**
     * @brief Constructs a buffer from a raw pointer.
     *
     * Copies data from the given pointer. The pointer must remain valid
     * for the duration of this constructor call.
     *
     * @param ptr Pointer to the data to copy
     * @param size Number of elements to copy
     */
    SecureBuffer(const T* ptr, size_t size) : data_(ptr, ptr + size) {}

    /**
     * @brief Destructor - securely zeros all memory.
     *
     * Overwrites all elements with zeros before releasing memory.
     * This prevents sensitive data from remaining in memory after
     * the buffer is destroyed.
     */
    ~SecureBuffer() {
        secure_zero();
    }

    // -------------------------------------------------------------------------
    // Copy and Move Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Copy constructor is deleted.
     *
     * Copying is disabled to prevent accidental duplication of sensitive data.
     * Use move semantics instead if transfer of ownership is needed.
     */
    SecureBuffer(const SecureBuffer&) = delete;

    /**
     * @brief Copy assignment is deleted.
     *
     * Copying is disabled to prevent accidental duplication of sensitive data.
     */
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    /**
     * @brief Move constructor - transfers ownership without copying.
     *
     * The source buffer is left in an empty state after the move.
     *
     * @param other Buffer to move from
     */
    SecureBuffer(SecureBuffer&& other) noexcept {
        data_ = std::move(other.data_);
    }

    /**
     * @brief Move assignment - transfers ownership without copying.
     *
     * Current data is securely zeroed before taking ownership of the new data.
     *
     * @param other Buffer to move from
     * @return Reference to this buffer
     */
    SecureBuffer& operator=(SecureBuffer&& other) noexcept {
        if (this != &other) {
            secure_zero();
            data_ = std::move(other.data_);
        }
        return *this;
    }

    // -------------------------------------------------------------------------
    // Element Access
    // -------------------------------------------------------------------------

    /** @brief Returns the number of elements in the buffer. */
    size_t size() const { return data_.size(); }

    /** @brief Returns true if the buffer is empty. */
    bool empty() const { return data_.empty(); }

    /** @brief Returns a pointer to the underlying data. */
    T* data() { return data_.data(); }

    /** @brief Returns a const pointer to the underlying data. */
    const T* data() const { return data_.data(); }

    /** @brief Accesses element at index (no bounds checking). */
    T& operator[](size_t index) { return data_[index]; }

    /** @brief Accesses element at index (no bounds checking, const). */
    const T& operator[](size_t index) const { return data_[index]; }

    /** @brief Returns iterator to the beginning. */
    const T* begin() const { return data_.data(); }

    /** @brief Returns iterator to the end. */
    const T* end() const { return data_.data() + data_.size(); }

    /** @brief Returns mutable iterator to the beginning. */
    T* begin() { return data_.data(); }

    /** @brief Returns mutable iterator to the end. */
    T* end() { return data_.data() + data_.size(); }

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /**
     * @brief Resizes the buffer.
     *
     * Current data is securely zeroed before resizing. New elements
     * are value-initialized (zeroed for fundamental types).
     *
     * @param new_size New size of the buffer
     */
    void resize(size_t new_size) {
        secure_zero();
        data_.resize(new_size);
    }

    /**
     * @brief Appends an element to the end.
     *
     * @param value Value to append
     */
    void push_back(const T& value) {
        data_.push_back(value);
    }

    // -------------------------------------------------------------------------
    // Security Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Performs a constant-time comparison.
     *
     * Compares this buffer with another in constant time, taking the same
     * amount of time regardless of where differences occur. This prevents
     * timing attacks that could reveal information about the contents.
     *
     * @param other Buffer to compare with
     * @return true if buffers are identical, false otherwise
     *
     * @note Returns false immediately if sizes differ, which is not
     *       constant-time. In security-critical contexts, ensure buffers
     *       are always the same size.
     */
    bool constant_time_compare(const SecureBuffer<T>& other) const {
        if (data_.size() != other.data_.size()) {
            return false;
        }

        // Use volatile to prevent compiler optimizations that might
        // introduce timing differences
        volatile uint8_t result = 0;
        for (size_t i = 0; i < data_.size(); ++i) {
            result |= (data_[i] ^ other.data_[i]);
        }

        return result == 0;
    }

    /**
     * @brief Converts to a standard vector.
     *
     * @warning This copies sensitive data to a new location. The caller
     *          is responsible for securing the returned vector.
     *
     * @return A copy of the buffer's contents
     */
    std::vector<T> to_vector() const {
        return data_;
    }

private:
    /**
     * @brief Securely zeros all data in the buffer.
     *
     * Uses volatile pointers to prevent compiler optimizations that might
     * skip the zeroing operation.
     */
    void secure_zero() {
        volatile T* ptr = data_.data();
        for (size_t i = 0; i < data_.size(); ++i) {
            ptr[i] = 0;
        }
        data_.clear();
    }

    std::vector<T> data_;
};

// =============================================================================
// SecureString Class
// =============================================================================

/**
 * @class SecureString
 * @brief A secure string wrapper that zeroizes memory on destruction.
 *
 * This class provides a string-like interface for handling sensitive text
 * data (like passwords). The underlying data is stored in a SecureBuffer
 * and is securely cleared when the string is destroyed.
 *
 * Key features:
 * - Automatic memory zeroing on destruction
 * - Copy operations disabled to prevent accidental data leaks
 * - Constant-time comparison for secure password verification
 *
 * @code
 * SecureString password("my_secret_password");
 * // ... use password ...
 * // Password is automatically zeroed when it goes out of scope
 * @endcode
 */
class SecureString {
public:
    // -------------------------------------------------------------------------
    // Constructors and Destructor
    // -------------------------------------------------------------------------

    /** @brief Default constructor creates an empty string. */
    SecureString() = default;

    /**
     * @brief Constructs from a standard string.
     *
     * Copies the string data into secure memory. The original string's
     * memory is not modified.
     *
     * @param str String to copy from
     */
    explicit SecureString(const std::string& str) {
        data_.resize(str.size());
        std::memcpy(data_.data(), str.data(), str.size());
    }

    /**
     * @brief Constructs a string of the specified size.
     *
     * Creates an uninitialized buffer of the given size.
     *
     * @param size Size in bytes
     */
    explicit SecureString(size_t size) : data_(size) {}

    /** @brief Destructor - memory is zeroed by SecureBuffer. */
    ~SecureString() = default;

    // -------------------------------------------------------------------------
    // Copy and Move Operations
    // -------------------------------------------------------------------------

    /** @brief Copy constructor is deleted. */
    SecureString(const SecureString&) = delete;

    /** @brief Copy assignment is deleted. */
    SecureString& operator=(const SecureString&) = delete;

    /** @brief Move constructor. */
    SecureString(SecureString&& other) noexcept = default;

    /** @brief Move assignment. */
    SecureString& operator=(SecureString&& other) noexcept = default;

    // -------------------------------------------------------------------------
    // String Operations
    // -------------------------------------------------------------------------

    /** @brief Returns the number of characters. */
    size_t size() const { return data_.size(); }

    /** @brief Returns the number of characters (alias for size()). */
    size_t length() const { return data_.size(); }

    /** @brief Returns true if the string is empty. */
    bool empty() const { return data_.empty(); }

    /** @brief Returns a null-terminated C string. */
    const char* c_str() const { return reinterpret_cast<const char*>(data_.data()); }

    /** @brief Returns a pointer to the underlying character array. */
    char* data() { return reinterpret_cast<char*>(data_.data()); }

    /** @brief Returns a const pointer to the underlying character array. */
    const char* data() const { return reinterpret_cast<const char*>(data_.data()); }

    /**
     * @brief Resizes the string.
     *
     * Current contents are securely zeroed before resizing.
     *
     * @param new_size New size in bytes
     */
    void resize(size_t new_size) {
        data_.resize(new_size);
    }

    /**
     * @brief Appends a string to the end.
     *
     * @param str String to append
     */
    void append(const std::string& str) {
        auto old_size = data_.size();
        data_.resize(old_size + str.size());
        std::memcpy(data_.data() + old_size, str.data(), str.size());
    }

    // -------------------------------------------------------------------------
    // Security Operations
    // -------------------------------------------------------------------------

    /**
     * @brief Converts to a standard string.
     *
     * @warning This copies sensitive data. The caller must ensure the
     *          returned string is properly secured.
     *
     * @return A copy of the string contents
     */
    std::string to_string() const {
        return std::string(c_str(), size());
    }

    /**
     * @brief Performs constant-time comparison.
     *
     * @param other String to compare with
     * @return true if strings are identical
     */
    bool constant_time_compare(const SecureString& other) const {
        return data_.constant_time_compare(other.data_);
    }

private:
    SecureBuffer<uint8_t> data_;
};

// =============================================================================
// SecureMemory Utility Class
// =============================================================================

/**
 * @class SecureMemory
 * @brief Static utilities for secure memory operations.
 *
 * This class provides low-level security utilities that don't naturally
 * fit into container classes, including:
 * - Secure memory zeroing
 * - Constant-time comparison
 * - Cryptographically secure random number generation
 * - Password hashing with PBKDF2
 */
class SecureMemory {
public:
    /**
     * @brief Securely zeros a memory region.
     *
     * Overwrites the specified memory region with zeros in a way that
     * cannot be optimized away by the compiler. This is essential for
     * clearing sensitive data like passwords and encryption keys.
     *
     * @param ptr Pointer to the memory region
     * @param size Size of the region in bytes
     *
     * @note If ptr is nullptr or size is 0, this function returns immediately.
     */
    static void secure_zero(void* ptr, size_t size);

    /**
     * @brief Performs constant-time memory comparison.
     *
     * Compares two memory regions in constant time, taking the same amount
     * of time regardless of where differences occur. This prevents timing
     * attacks that could reveal information about compared data.
     *
     * @param a Pointer to first memory region
     * @param b Pointer to second memory region
     * @param size Number of bytes to compare
     * @return true if regions are identical, false otherwise
     *
     * @note Returns false if either pointer is null or size is 0.
     */
    static bool constant_time_compare(const void* a, const void* b, size_t size);

    /**
     * @brief Generates cryptographically secure random bytes.
     *
     * Uses OpenSSL's RAND_bytes to generate cryptographically secure
     * random data. This is suitable for generating salts, IVs, and
     * other security-critical values.
     *
     * @param count Number of random bytes to generate
     * @return Result containing the random bytes on success, or an error message
     *
     * @note On failure, returns an empty vector with an error message.
     *       This typically indicates a failure in the system's entropy source.
     */
    static Result<std::vector<uint8_t>> random_bytes(size_t count);

    /**
     * @brief Hashes a password using PBKDF2-HMAC-SHA256.
     *
     * Derives a cryptographic key from a password using PBKDF2 (Password-Based
     * Key Derivation Function 2) with HMAC-SHA256. This is used for secure
     * password storage and key derivation.
     *
     * @param password The password to hash
     * @param salt A random salt value (should be 32 bytes)
     * @param iterations Number of PBKDF2 iterations (use PBKDF2_ITERATIONS)
     * @return Result containing the derived key on success, or an error message
     *
     * @warning The returned key should be treated as sensitive data and
     *          securely erased when no longer needed.
     */
    static Result<std::vector<uint8_t>> hash_password(const std::string& password,
                                                      const std::vector<uint8_t>& salt,
                                                      int iterations);

    /**
     * @brief Verifies a password hash in constant time.
     *
     * Compares two password hashes in constant time to prevent timing attacks.
     * This should be used instead of direct comparison for password verification.
     *
     * @param stored_hash The hash stored in the database
     * @param provided_hash The hash computed from the provided password
     * @return true if hashes are identical
     */
    static bool verify_password(const std::vector<uint8_t>& stored_hash,
                                 const std::vector<uint8_t>& provided_hash);
};

// =============================================================================
// SecureValue Template
// =============================================================================

/**
 * @class SecureValue
 * @brief RAII wrapper for securing individual sensitive values.
 *
 * This template class provides automatic secure cleanup for any type of
 * sensitive value. When the value goes out of scope, its memory is securely
 * zeroed.
 *
 * This is useful for securing simple types like integers or structs that
 * contain sensitive data. For large buffers or strings, prefer SecureBuffer
 * or SecureString instead.
 *
 * @tparam T The type of value to secure
 *
 * @code
 * {
 *     SecureValue<int> secret_key(42);
 *     // Use secret_key.get() to access the value
 * } // Value is automatically zeroed here
 * @endcode
 */
template<typename T>
class SecureValue {
public:
    /**
     * @brief Constructs a SecureValue with the given value.
     *
     * @param value The value to secure
     */
    explicit SecureValue(const T& value) : value_(value) {}

    /**
     * @brief Destructor - securely zeros the value's memory.
     *
     * Overwrites the entire sizeof(T) bytes with zeros.
     */
    ~SecureValue() {
        secure_zero(reinterpret_cast<void*>(&value_), sizeof(T));
    }

    /** @brief Copy constructor is deleted. */
    SecureValue(const SecureValue&) = delete;

    /** @brief Copy assignment is deleted. */
    SecureValue& operator=(const SecureValue&) = delete;

    /**
     * @brief Move constructor.
     *
     * The source value is zeroed after the move.
     *
     * @param other Value to move from
     */
    SecureValue(SecureValue&& other) noexcept {
        std::memcpy(&value_, &other.value_, sizeof(T));
        secure_zero(reinterpret_cast<void*>(&other.value_), sizeof(T));
    }

    /**
     * @brief Move assignment.
     *
     * Current value is zeroed before taking the new value.
     *
     * @param other Value to move from
     * @return Reference to this object
     */
    SecureValue& operator=(SecureValue&& other) noexcept {
        if (this != &other) {
            secure_zero(reinterpret_cast<void*>(&value_), sizeof(T));
            std::memcpy(&value_, &other.value_, sizeof(T));
            secure_zero(reinterpret_cast<void*>(&other.value_), sizeof(T));
        }
        return *this;
    }

    /** @brief Returns a const reference to the value. */
    const T& get() const { return value_; }

    /** @brief Returns a mutable reference to the value. */
    T& get() { return value_; }

private:
    /**
     * @brief Securely zeros memory.
     *
     * Internal helper function that performs the same secure zeroing
     * as SecureMemory::secure_zero.
     *
     * @param ptr Pointer to memory to zero
     * @param size Number of bytes to zero
     */
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