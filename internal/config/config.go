package config

import (
    "io"
    "log"
    "os"
    "path/filepath"
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
        EnableSQLInjectionProt bool
        MaxLoginAttempts       int
        LockoutDuration        time.Duration
        SessionTimeout         time.Duration
        Require2FA             bool
    }
    Cache struct {
        RedisURL string
        Memory   bool
        TTL      time.Duration
    }
    Upload struct {
        MaxSize        int64
        AllowedTypes   []string
        UploadPath     string
        EnableVirusScan bool
        ScanEndpoint   string
    }
    Logging struct {
        Level      string
        File       string
        MaxSize    int
        MaxBackups int
        MaxAge     int
    }
}

func Load() (*Config, error) {
    cfg := &Config{}
    
    // Server
    cfg.Server.Host = getEnv("HOST", "0.0.0.0")
    cfg.Server.Port = getEnv("PORT", "8080")
    cfg.Server.Env = getEnv("ENV", "production")
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
    cfg.Security.JWTSecret = os.Getenv("JWT_SECRET")
    cfg.Security.SessionSecret = os.Getenv("SESSION_SECRET")
    cfg.Security.CSRFKey = os.Getenv("CSRF_KEY")
    cfg.Security.RateLimitRequests, _ = strconv.Atoi(getEnv("RATE_LIMIT", "100"))
    cfg.Security.RateLimitWindow = 1 * time.Minute
    cfg.Security.EnableHSTS = getEnvAsBool("ENABLE_HSTS", true)
    cfg.Security.EnableCSP = getEnvAsBool("ENABLE_CSP", true)
    cfg.Security.EnableXSSProtection = getEnvAsBool("ENABLE_XSS_PROTECTION", true)
    cfg.Security.EnableClickjackingProt = getEnvAsBool("ENABLE_CLICKJACKING_PROT", true)
    cfg.Security.EnableSQLInjectionProt = getEnvAsBool("ENABLE_SQL_INJECTION_PROT", true)
    cfg.Security.MaxLoginAttempts, _ = strconv.Atoi(getEnv("MAX_LOGIN_ATTEMPTS", "5"))
    cfg.Security.LockoutDuration = 15 * time.Minute
    cfg.Security.SessionTimeout = 30 * time.Minute
    cfg.Security.Require2FA = getEnvAsBool("REQUIRE_2FA", false)
    
    // Cache
    cfg.Cache.RedisURL = getEnv("REDIS_URL", "")
    cfg.Cache.Memory = getEnvAsBool("CACHE_MEMORY", true)
    cfg.Cache.TTL = 5 * time.Minute
    
    // Upload
    cfg.Upload.MaxSize = 10 * 1024 * 1024 // 10MB
    cfg.Upload.AllowedTypes = []string{
        "image/jpeg", "image/png", "image/gif", "image/webp",
        "application/pdf", "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    }
    cfg.Upload.UploadPath = getEnv("UPLOAD_PATH", "./uploads")
    cfg.Upload.EnableVirusScan = getEnvAsBool("ENABLE_VIRUS_SCAN", true)
    cfg.Upload.ScanEndpoint = getEnv("VIRUS_SCAN_ENDPOINT", "")
    
    // Logging
    cfg.Logging.Level = getEnv("LOG_LEVEL", "info")
    cfg.Logging.File = getEnv("LOG_FILE", "")
    cfg.Logging.MaxSize, _ = strconv.Atoi(getEnv("LOG_MAX_SIZE", "100"))
    cfg.Logging.MaxBackups, _ = strconv.Atoi(getEnv("LOG_MAX_BACKUPS", "10"))
    cfg.Logging.MaxAge, _ = strconv.Atoi(getEnv("LOG_MAX_AGE", "30"))
    
    // Ensure upload directory exists
    os.MkdirAll(cfg.Upload.UploadPath, 0755)
    
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

type Logger struct {
    *log.Logger
    file *os.File
}

func NewLogger() *Logger {
    cfg, _ := Load()
    
    var output io.Writer = os.Stdout
    
    if cfg.Logging.File != "" {
        // Create log directory if it doesn't exist
        logDir := filepath.Dir(cfg.Logging.File)
        os.MkdirAll(logDir, 0755)
        
        file, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
        if err == nil {
            output = io.MultiWriter(os.Stdout, file)
        }
    }
    
    logger := log.New(output, "", log.Ldate|log.Ltime|log.Lshortfile)
    return &Logger{Logger: logger}
}

func (l *Logger) Close() {
    if l.file != nil {
        l.file.Close()
    }
}