package auth

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
    "strings"
    
    "golang.org/x/crypto/argon2"
    "golang.org/x/crypto/bcrypt"
)

// HashPassword creates a secure password hash
func HashPassword(password string) (string, error) {
    // Use bcrypt for simplicity
    hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
    if err != nil {
        return "", fmt.Errorf("failed to hash password: %w", err)
    }
    return string(hash), nil
}

// VerifyPassword verifies a password against a hash
func VerifyPassword(password, hash string) bool {
    err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
    return err == nil
}

// GenerateRandomToken generates a secure random token
func GenerateRandomToken(length int) (string, error) {
    bytes := make([]byte, length)
    if _, err := rand.Read(bytes); err != nil {
        return "", fmt.Errorf("failed to generate token: %w", err)
    }
    return base64.URLEncoding.EncodeToString(bytes), nil
}

// ValidatePasswordStrength checks if password is strong enough
func ValidatePasswordStrength(password string) (bool, []string) {
    var errors []string
    
    if len(password) < 12 {
        errors = append(errors, "Password must be at least 12 characters")
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
        case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", c):
            hasSpecial = true
        }
    }
    
    if !hasUpper {
        errors = append(errors, "Password must contain uppercase letters")
    }
    if !hasLower {
        errors = append(errors, "Password must contain lowercase letters")
    }
    if !hasNumber {
        errors = append(errors, "Password must contain numbers")
    }
    if !hasSpecial {
        errors = append(errors, "Password must contain special characters")
    }
    
    return len(errors) == 0, errors
}