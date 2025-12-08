package auth

import (
    "crypto/rand"
    "crypto/subtle"
    "encoding/base64"
    "fmt"
    "strings"
    
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/bcrypt"
)

type PasswordConfig struct {
    Time    uint32
    Memory  uint32
    Threads uint8
    KeyLen  uint32
    SaltLen uint32
}

var DefaultPasswordConfig = &PasswordConfig{
    Time:    3,
    Memory:  64 * 1024,
    Threads: 4,
    KeyLen:  32,
    SaltLen: 16,
}

// HashPassword creates a secure password hash using Argon2
func HashPassword(password string) (string, error) {
    // Generate random salt
    salt := make([]byte, DefaultPasswordConfig.SaltLen)
    if _, err := rand.Read(salt); err != nil {
        return "", fmt.Errorf("failed to generate salt: %w", err)
    }
    
    // Generate hash using Argon2
    hash := argon2.IDKey(
        []byte(password),
        salt,
        DefaultPasswordConfig.Time,
        DefaultPasswordConfig.Memory,
        DefaultPasswordConfig.Threads,
        DefaultPasswordConfig.KeyLen,
    )
    
    // Encode salt and hash
    b64Salt := base64.RawStdEncoding.EncodeToString(salt)
    b64Hash := base64.RawStdEncoding.EncodeToString(hash)
    
    // Format: $argon2id$v=19$m=65536,t=3,p=4$salt$hash
    encoded := fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
        DefaultPasswordConfig.Memory,
        DefaultPasswordConfig.Time,
        DefaultPasswordConfig.Threads,
        b64Salt,
        b64Hash,
    )
    
    return encoded, nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, encoded string) (bool, error) {
    // Parse encoded hash
    parts := strings.Split(encoded, "$")
    if len(parts) != 6 {
        return false, fmt.Errorf("invalid hash format")
    }
    
    if parts[1] != "argon2id" {
        return false, fmt.Errorf("unsupported hash algorithm")
    }
    
    // Parse parameters
    var version int
    var memory, time uint32
    var threads uint8
    _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
    if err != nil {
        return false, fmt.Errorf("failed to parse parameters: %w", err)
    }
    
    // Decode salt and hash
    salt, err := base64.RawStdEncoding.DecodeString(parts[4])
    if err != nil {
        return false, fmt.Errorf("failed to decode salt: %w", err)
    }
    
    expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
    if err != nil {
        return false, fmt.Errorf("failed to decode hash: %w", err)
    }
    
    // Verify password
    actualHash := argon2.IDKey(
        []byte(password),
        salt,
        time,
        memory,
        threads,
        uint32(len(expectedHash)),
    )
    
    // Use constant time comparison
    if subtle.ConstantTimeCompare(actualHash, expectedHash) == 1 {
        return true, nil
    }
    
    return false, nil
}

// HashPasswordBcrypt creates a bcrypt hash (for compatibility)
func HashPasswordBcrypt(password string) (string, error) {
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", fmt.Errorf("failed to hash password: %w", err)
    }
    return string(hash), nil
}

// VerifyPasswordBcrypt verifies a bcrypt hash
func VerifyPasswordBcrypt(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// GenerateRandomToken generates a cryptographically secure random token
func GenerateRandomToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate token: %w", err)
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// ValidatePasswordStrength checks password strength
func ValidatePasswordStrength(password string) (bool, []string) {
    var errors []string
    
    if len(password) < 12 {
        errors = append(errors, "Password must be at least 12 characters long")
    }
    
    var hasUpper, hasLower, hasNumber, hasSpecial bool
    for _, c := range password {
        switch {
        case 'A' <= c && c <= 'Z':
            hasUpper = true
        case 'a' <= c && c <= 'z':
            hasLower = true
        case '0' <= c && c <= '9':
            hasNumber = true
        case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?/`~", c):
            hasSpecial = true
        }
    }
    
    if !hasUpper {
        errors = append(errors, "Password must contain at least one uppercase letter")
    }
    if !hasLower {
        errors = append(errors, "Password must contain at least one lowercase letter")
    }
    if !hasNumber {
        errors = append(errors, "Password must contain at least one number")
    }
    if !hasSpecial {
        errors = append(errors, "Password must contain at least one special character")
    }
    
    // Check for common passwords
    commonPasswords := []string{
        "password", "123456", "qwerty", "admin", "welcome",
        "password123", "123456789", "12345678", "12345",
        "1234567", "123123", "111111", "sunshine", "iloveyou",
        "monkey", "dragon", "football", "baseball", "mustang",
    }
    
    lowerPass := strings.ToLower(password)
    for _, common := range commonPasswords {
        if lowerPass == common || strings.Contains(lowerPass, common) {
            errors = append(errors, "Password is too common or contains common words")
            break
        }
    }
    
    // Check for sequential characters
    if hasSequentialChars(password) {
        errors = append(errors, "Password contains sequential characters")
    }
    
    // Check for repeated characters
    if hasRepeatedChars(password, 3) {
        errors = append(errors, "Password contains too many repeated characters")
    }
    
    return len(errors) == 0, errors
}

func hasSequentialChars(s string) bool {
    for i := 0; i < len(s)-2; i++ {
        if (s[i]+1 == s[i+1] && s[i]+2 == s[i+2]) ||
            (s[i]-1 == s[i+1] && s[i]-2 == s[i+2]) {
            return true
        }
    }
    return false
}

func hasRepeatedChars(s string, threshold int) bool {
    count := 1
    for i := 1; i < len(s); i++ {
        if s[i] == s[i-1] {
            count++
            if count >= threshold {
                return true
            }
        } else {
            count = 1
        }
    }
    return false
}