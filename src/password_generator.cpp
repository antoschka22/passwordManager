#include "password_generator.h"
#include "secure_memory.h"
#include <random>
#include <algorithm>
#include <cctype>

namespace pwdmgr {

Result<std::string> PasswordGenerator::generate(const PasswordGeneratorOptions& options) {
    if (options.length < 8) {
        return Result<std::string>::error("Password length must be at least 8 characters");
    }

    if (options.pronounceable) {
        return generate_pronounceable(options.length, options.avoid_ambiguous);
    }

    std::string pool = build_pool(options);
    if (pool.empty()) {
        return Result<std::string>::error("No character types selected");
    }

    // Use cryptographically secure random number generator
    auto random_result = SecureMemory::random_bytes(options.length);
    if (!random_result.success) {
        return Result<std::string>::error("Failed to generate random bytes");
    }

    const std::vector<uint8_t>& random_bytes = random_result.value;
    std::string password;
    password.reserve(options.length);

    for (size_t i = 0; i < options.length; ++i) {
        size_t index = random_bytes[i] % pool.size();
        password.push_back(pool[index]);
    }

    // Securely zero the random bytes
    SecureMemory::secure_zero((void*)random_bytes.data(), random_bytes.size());

    return Result<std::string>::ok(password);
}

Result<std::string> PasswordGenerator::generate_default() {
    PasswordGeneratorOptions options;
    return generate(options);
}

Result<bool> PasswordGenerator::validate_strength(const std::string& password) {
    auto score = get_strength_score(password);
    if (!score.success) {
        return Result<bool>::error(score.error_message);
    }

    return Result<bool>::ok(score.value >= 60);
}

Result<int> PasswordGenerator::get_strength_score(const std::string& password) {
    if (password.empty()) {
        return Result<int>::ok(0);
    }

    int score = 0;

    // Length contribution (up to 40 points)
    size_t length = password.length();
    if (length >= 8) score += 10;
    if (length >= 12) score += 10;
    if (length >= 16) score += 10;
    if (length >= 20) score += 10;

    // Character variety contribution (up to 30 points)
    bool has_lower = false, has_upper = false, has_digit = false, has_special = false;
    for (char c : password) {
        if (std::islower(c)) has_lower = true;
        else if (std::isupper(c)) has_upper = true;
        else if (std::isdigit(c)) has_digit = true;
        else has_special = true;
    }

    if (has_lower) score += 10;
    if (has_upper) score += 10;
    if (has_digit) score += 5;
    if (has_special) score += 5;

    // Complexity contribution (up to 20 points)
    int unique_chars = std::unique(password.begin(), password.end()) - password.begin();
    double unique_ratio = static_cast<double>(unique_chars) / length;

    if (unique_ratio > 0.5) score += 10;
    if (unique_ratio > 0.7) score += 5;
    if (unique_ratio > 0.9) score += 5;

    // Penalty for common patterns (up to -20 points)
    std::string lower_pwd = password;
    std::transform(lower_pwd.begin(), lower_pwd.end(), lower_pwd.begin(), ::tolower);

    // Common passwords
    static const std::vector<std::string> common_passwords = {
        "password", "123456", "qwerty", "abc123", "letmein",
        "monkey", "dragon", "111111", "baseball", "iloveyou",
        "trustno1", "sunshine", "master", "hello", "freedom"
    };

    for (const auto& common : common_passwords) {
        if (lower_pwd.find(common) != std::string::npos) {
            score -= 10;
            break;
        }
    }

    // Sequential patterns
    bool has_sequential = false;
    for (size_t i = 2; i < length; ++i) {
        if (password[i] == password[i-1] + 1 && password[i-1] == password[i-2] + 1) {
            has_sequential = true;
            break;
        }
        if (password[i] == password[i-1] - 1 && password[i-1] == password[i-2] - 1) {
            has_sequential = true;
            break;
        }
    }
    if (has_sequential) score -= 10;

    // Repeated characters
    int repeated_count = 0;
    for (size_t i = 1; i < length; ++i) {
        if (password[i] == password[i-1]) repeated_count++;
    }
    if (repeated_count > length / 2) score -= 10;

    // Ensure score is between 0 and 100
    score = std::max(0, std::min(100, score));

    return Result<int>::ok(score);
}

std::string PasswordGenerator::get_strength_description(int score) {
    if (score < 20) return "Very Weak";
    if (score < 40) return "Weak";
    if (score < 60) return "Fair";
    if (score < 80) return "Strong";
    return "Very Strong";
}

bool PasswordGenerator::is_compromised(const std::string& password) {
    // In production, this should use a real API like Have I Been Pwned
    // For now, we'll return false as a placeholder
    // TODO: Implement actual breach checking
    (void)password;
    return false;
}

std::string PasswordGenerator::build_pool(const PasswordGeneratorOptions& options) {
    std::string pool;

    if (options.use_lowercase) {
        pool += LOWERCASE;
        if (!options.avoid_ambiguous) {
            pool += "l";
        } else {
            // Remove 'l' from lowercase
            pool.erase(std::remove(pool.begin(), pool.end(), 'l'), pool.end());
        }
    }

    if (options.use_uppercase) {
        pool += UPPERCASE;
        if (!options.avoid_ambiguous) {
            pool += "IO";
        } else {
            pool.erase(std::remove(pool.begin(), pool.end(), 'I'), pool.end());
            pool.erase(std::remove(pool.begin(), pool.end(), 'O'), pool.end());
        }
    }

    if (options.use_digits) {
        pool += DIGITS;
        if (options.avoid_ambiguous) {
            pool.erase(std::remove(pool.begin(), pool.end(), '0'), pool.end());
            pool.erase(std::remove(pool.begin(), pool.end(), '1'), pool.end());
        }
    }

    if (options.use_special) {
        pool += SPECIAL;
    }

    return pool;
}

Result<std::string> PasswordGenerator::generate_pronounceable(size_t length, bool avoid_ambiguous) {
    if (length < 6) {
        return Result<std::string>::error("Pronounceable password must be at least 6 characters");
    }

    // Calculate number of syllables needed (each syllable is 2 chars)
    size_t num_syllables = (length + 1) / 2;

    // Get random syllables
    std::string password;
    password.reserve(length);

    for (size_t i = 0; i < num_syllables && password.length() < length; ++i) {
        auto random_result = SecureMemory::random_bytes(1);
        if (!random_result.success) {
            return Result<std::string>::error("Failed to generate random bytes");
        }

        size_t index = random_result.value[0] % NUM_SYLLABLES;
        std::string syllable = SYLLABLES[index];

        // Alternating case for better strength
        if (i % 2 == 0) {
            std::transform(syllable.begin(), syllable.end(), syllable.begin(), ::toupper);
        }

        // Avoid ambiguous characters if requested
        if (avoid_ambiguous) {
            syllable.erase(std::remove(syllable.begin(), syllable.end(), 'I'), syllable.end());
            syllable.erase(std::remove(syllable.begin(), syllable.end(), 'O'), syllable.end());
            syllable.erase(std::remove(syllable.begin(), syllable.end(), 'l'), syllable.end());
        }

        if (password.length() + syllable.length() <= length) {
            password += syllable;
        }
    }

    // Add some digits or special characters for extra strength
    if (password.length() < length) {
        auto random_result = SecureMemory::random_bytes(1);
        if (random_result.success) {
            char digit = '0' + (random_result.value[0] % 10);
            password += digit;
        }
    }

    if (password.length() < length) {
        auto random_result = SecureMemory::random_bytes(1);
        if (random_result.success) {
            static const char specials[] = "!@#$%^&*";
            char special = specials[random_result.value[0] % (sizeof(specials) - 1)];
            password += special;
        }
    }

    return Result<std::string>::ok(password);
}

// PassphraseGenerator implementation

std::vector<std::string> PassphraseGenerator::default_wordlist;
bool PassphraseGenerator::wordlist_initialized = false;

Result<std::string> PassphraseGenerator::generate(size_t word_count, const std::string& separator) {
    if (!wordlist_initialized) {
        default_wordlist = get_default_wordlist();
        wordlist_initialized = true;
    }

    if (default_wordlist.empty()) {
        return Result<std::string>::error("Word list not available");
    }

    return generate_with_wordlist(default_wordlist, word_count, separator);
}

Result<std::string> PassphraseGenerator::generate_with_wordlist(const std::vector<std::string>& words,
                                                                size_t word_count,
                                                                const std::string& separator) {
    if (words.empty()) {
        return Result<std::string>::error("Word list is empty");
    }

    if (word_count == 0) {
        return Result<std::string>::error("Word count must be at least 1");
    }

    // Generate random indices
    auto random_result = SecureMemory::random_bytes(word_count);
    if (!random_result.success) {
        return Result<std::string>::error("Failed to generate random bytes");
    }

    const std::vector<uint8_t>& random_bytes = random_result.value;
    std::vector<size_t> indices;
    indices.reserve(word_count);

    for (size_t i = 0; i < word_count; ++i) {
        size_t index = static_cast<size_t>(random_bytes[i]) % words.size();
        indices.push_back(index);
    }

    // Build passphrase
    std::string passphrase;
    for (size_t i = 0; i < word_count; ++i) {
        if (i > 0) {
            passphrase += separator;
        }
        passphrase += words[indices[i]];
    }

    // Securely zero the random bytes
    SecureMemory::secure_zero((void*)random_bytes.data(), random_bytes.size());

    return Result<std::string>::ok(passphrase);
}

std::vector<std::string> PassphraseGenerator::get_default_wordlist() {
    // A subset of the EFF Dice Roll wordlist for demonstration
    return {
        "acid", "acorn", "acre", "acts", "afar", "affix", "aged", "agent",
        "agile", "aging", "agony", "ahead", "aide", "aids", "aim", "ajar",
        "alarm", "alias", "alibi", "alien", "alike", "alive", "aloe", "aloft",
        "aloha", "alone", "alpha", "altar", "alter", "amaze", "amber", "amend",
        "amide", "amino", "amiss", "amity", "among", "ample", "amply", "amuse",
        "angel", "anger", "angle", "angry", "animal", "ankle", "annoy", "ants",
        "anvil", "apple", "apply", "arena", "argue", "arise", "arm", "army",
        "aroma", "arose", "array", "arrive", "arrow", "arson", "art", "artist",
        "ascend", "ash", "ashes", "ask", "asset", "assist", "assume", "astute",
        "asylum", "atom", "atone", "attic", "attire", "audio", "audit", "august",
        "aunt", "author", "auto", "autumn", "avail", "avenge", "avenue", "avert",
        "avoid", "awake", "award", "aware", "awful", "awoke", "axe", "axis",
        "bacon", "badge", "badly", "bagel", "baggy", "bait", "bake", "baker",
        "bases", "basic", "basil", "basin", "basis", "basket", "battle", "beach",
        "bead", "beak", "beam", "bean", "bear", "beard", "beast", "began",
        "begin", "begun", "being", "belly", "below", "bench", "berry", "bicycle",
        "bid", "big", "bike", "bill", "bind", "biology", "birth", "biscuit",
        "bit", "bite", "black", "blade", "blame", "bland", "blank", "blast",
        "blaze", "bleak", "blend", "bless", "blind", "blink", "bliss", "block",
        "blonde", "blood", "bloom", "blown", "blue", "bluff", "blunt", "blurb",
        "blush", "board", "boast", "bonus", "boost", "boot", "border", "bore",
        "boring", "borrow", "boss", "both", "bottle", "bottom", "bought", "bounce",
        "bound", "box", "boy", "brain", "brand", "brave", "brawl", "bread",
        "break", "breed", "brick", "bride", "brief", "bring", "brisk", "broad",
        "broil", "broke", "bronze", "brook", "broom", "brown", "bruise", "brush",
        "bubble", "bucket", "budget", "buffet", "buggy", "build", "built", "bulb",
        "bulk", "bulky", "bull", "bully", "bump", "bumpy", "bunch", "bunny",
        "burn", "burst", "bury", "bush", "business", "busy", "butter", "button",
        "buyer", "cabin", "cable", "cactus", "cage", "cake", "call", "calm",
        "came", "camel", "camp", "can", "canal", "candy", "cane", "cannon",
        "canoe", "canopy", "canvas", "canyon", "cap", "cape", "capital", "captain",
        "car", "carbon", "card", "care", "career", "cargo", "carpet", "carrot",
        "carry", "cart", "case", "cash", "cast", "cat", "catch", "cater",
        "cause", "cave", "cease", "cell", "cement", "cent", "center", "century",
        "cereal", "chain", "chair", "chalk", "champ", "change", "chaos", "chap",
        "charge", "chart", "chase", "chat", "cheap", "check", "cheek", "cheer",
        "chef", "cherry", "chess", "chest", "chew", "chief", "child", "chime",
        "chimp", "chin", "chip", "chirp", "choir", "choke", "chop", "chord",
        "chrome", "chunk", "churn", "cider", "cigar", "cinema", "cipher", "circle",
        "cite", "city", "civil", "claim", "clap", "clash", "clasp", "class",
        "claw", "clay", "clean", "clear", "clerk", "click", "cliff", "climb",
        "cling", "cloak", "clock", "clone", "cloth", "cloud", "clown", "club",
        "clue", "clump", "coach", "coast", "coat", "code", "coil", "coin",
        "coke", "cold", "collar", "collect", "color", "colt", "comb", "comic",
        "comma", "come", "comet", "comfort", "comic", "commit", "common", "compel"
    };
}

} // namespace pwdmgr