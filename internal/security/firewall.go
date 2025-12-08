package security

import (
    "net/http"
    "strings"
    "time"
    
    "github.com/patrickmn/go-cache"
)

type Firewall struct {
    blockedIPs *cache.Cache
}

func NewFirewall() *Firewall {
    return &Firewall{
        blockedIPs: cache.New(24*time.Hour, 1*time.Hour),
    }
}

func (fw *Firewall) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIP(r)
        
        // Check if IP is blocked
        if _, found := fw.blockedIPs.Get(clientIP); found {
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        // Check for suspicious patterns
        if fw.isSuspiciousRequest(r) {
            fw.blockedIPs.Set(clientIP, true, 1*time.Hour)
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (fw *Firewall) isSuspiciousRequest(r *http.Request) bool {
    path := strings.ToLower(r.URL.Path)
    ua := strings.ToLower(r.UserAgent())
    
    // Block common attack paths
    blockedPaths := []string{
        "/wp-admin", "/wp-login", "/wp-includes",
        "/administrator", "/phpmyadmin", "/mysql",
        "/cgi-bin/", "/.git/", "/.env", "/config.php",
        "/backup", "/sql", "/database",
    }
    
    for _, blocked := range blockedPaths {
        if strings.Contains(path, blocked) {
            return true
        }
    }
    
    // Block suspicious user agents
    badBots := []string{
        "sqlmap", "nikto", "nmap", "metasploit",
        "dirbuster", "gobuster", "hydra", "wpscan",
        "acunetix", "nessus", "netsparker",
    }
    
    for _, bot := range badBots {
        if strings.Contains(ua, bot) {
            return true
        }
    }
    
    // Check for SQL injection patterns in URL
    sqlPatterns := []string{
        "'", "\"", ";", "--", "/*", "*/", "@@",
        "union", "select", "insert", "update", "delete",
        "drop", "create", "alter", "exec",
    }
    
    query := strings.ToLower(r.URL.RawQuery)
    for _, pattern := range sqlPatterns {
        if strings.Contains(query, pattern) {
            return true
        }
    }
    
    return false
}

func getClientIP(r *http.Request) string {
    // Check forwarded headers
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        parts := strings.Split(ip, ",")
        if len(parts) > 0 {
            return strings.TrimSpace(parts[0])
        }
    }
    
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    
    // Fallback to remote address
    addr := r.RemoteAddr
    if idx := strings.LastIndex(addr, ":"); idx != -1 {
        addr = addr[:idx]
    }
    
    return addr
}