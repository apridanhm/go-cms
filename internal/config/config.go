package config

import (
    "os"
    "strconv"
    "time"
)

type Config struct {
    Server struct {
        Host    string
        Port    string
        Env     string
        SSL     bool
        SSLCert string
        SSLKey  string
    }
    Database struct {
        Host     string
        Port     string
        User     string
        Password string
        Name     string
        Timeout  time.Duration
    }
    Security struct {
        JWTSecret              string
        SessionSecret          string
        CSRFKey                string
        RateLimitRequests      int
        RateLimitWindow        time.Duration
        EnableHSTS             bool
        EnableCSP              bool
        EnableXSSProtection    bool
        EnableClickjackingProt bool
        MaxLoginAttempts       int
        SessionTimeout         time.Duration
    }
    Cache struct {
        RedisURL string
        Memory   bool
        TTL      time.Duration
    }
    Upload struct {
        MaxSize      int64
        UploadPath   string
    }
}

func Load() (*Config, error) {
    cfg := &Config{}
    
    // Server
    cfg.Server.Host = getEnv("HOST", "0.0.0.0")
    cfg.Server.Port = getEnv("PORT", "8080")
    cfg.Server.Env = getEnv("ENV", "development")
    cfg.Server.SSL = getEnvAsBool("SSL", false)
    cfg.Server.SSLCert = getEnv("SSL_CERT", "")
    cfg.Server.SSLKey = getEnv("SSL_KEY", "")
    
    // Database
    cfg.Database.Host = getEnv("DB_HOST", "localhost")
    cfg.Database.Port = getEnv("DB_PORT", "3306")
    cfg.Database.User = getEnv("DB_USER", "root")
    cfg.Database.Password = os.Getenv("DB_PASSWORD")
    cfg.Database.Name = getEnv("DB_NAME", "go_cms")
    cfg.Database.Timeout = 30 * time.Second
    
    // Security
    cfg.Security.JWTSecret = getEnv("JWT_SECRET", "change-this-in-production-12345")
    cfg.Security.SessionSecret = getEnv("SESSION_SECRET", "change-this-in-production-67890")
    cfg.Security.CSRFKey = getEnv("CSRF_KEY", "change-this-in-production-abcde")
    cfg.Security.RateLimitRequests, _ = strconv.Atoi(getEnv("RATE_LIMIT", "100"))
    cfg.Security.RateLimitWindow = 1 * time.Minute
    cfg.Security.EnableHSTS = getEnvAsBool("ENABLE_HSTS", true)
    cfg.Security.EnableCSP = getEnvAsBool("ENABLE_CSP", true)
    cfg.Security.EnableXSSProtection = getEnvAsBool("ENABLE_XSS_PROTECTION", true)
    cfg.Security.EnableClickjackingProt = getEnvAsBool("ENABLE_CLICKJACKING_PROT", true)
    cfg.Security.MaxLoginAttempts, _ = strconv.Atoi(getEnv("MAX_LOGIN_ATTEMPTS", "5"))
    cfg.Security.SessionTimeout = 30 * time.Minute
    
    // Cache
    cfg.Cache.RedisURL = getEnv("REDIS_URL", "")
    cfg.Cache.Memory = getEnvAsBool("CACHE_MEMORY", true)
    cfg.Cache.TTL = 5 * time.Minute
    
    // Upload
    cfg.Upload.MaxSize = 10 * 1024 * 1024 // 10MB
    cfg.Upload.UploadPath = getEnv("UPLOAD_PATH", "./uploads")
    
    return cfg, nil
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}

func getEnvAsBool(key string, defaultValue bool) bool {
    if value := os.Getenv(key); value != "" {
        boolValue, err := strconv.ParseBool(value)
        if err == nil {
            return boolValue
        }
    }
    return defaultValue
}