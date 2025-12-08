package middleware

import (
    "log"
    "net/http"
    "regexp"
    "strings"
    "sync"
    "time"
    
    "github.com/patrickmn/go-cache"
)

type WAF struct {
    cache      *cache.Cache
    blockedIPs map[string]time.Time
    mu         sync.RWMutex
}

func NewWAF() *WAF {
    return &WAF{
        cache:      cache.New(5*time.Minute, 10*time.Minute),
        blockedIPs: make(map[string]time.Time),
    }
}

func (waf *WAF) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getRealIP(r)
        
        // Check if IP is blocked
        waf.mu.RLock()
        blockTime, blocked := waf.blockedIPs[clientIP]
        waf.mu.RUnlock()
        
        if blocked && time.Since(blockTime) < 24*time.Hour {
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        // Check for attacks
        if waf.isAttack(r) {
            waf.mu.Lock()
            waf.blockedIPs[clientIP] = time.Now()
            waf.mu.Unlock()
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (waf *WAF) isAttack(r *http.Request) bool {
    url := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
    ua := strings.ToLower(r.UserAgent())
    clientIP := getRealIP(r)
    
    attackPatterns := []struct{
        pattern string
        name    string
    }{
        {"union.*select", "SQL Injection"},
        {"select.*from", "SQL Injection"},
        {"insert.*into", "SQL Injection"},
        {"<script", "XSS Attack"},
        {"javascript:", "XSS Attack"},
        {"onload=", "XSS Attack"},
        {"onerror=", "XSS Attack"},
        {"\\.\\./", "Path Traversal"},
        {"/etc/passwd", "LFI Attack"},
        {"/proc/self", "LFI Attack"},
        {"wp-admin", "WordPress Scan"},
        {"wp-login", "WordPress Scan"},
        {"wp-includes", "WordPress Scan"},
        {"\\.git/", "Git Disclosure"},
        {"\\.env", "Env Disclosure"},
        {"phpmyadmin", "phpMyAdmin Scan"},
        {"administrator", "Admin Panel Scan"},
        {"cgi-bin", "CGI Scan"},
        {"backup", "Backup File Scan"},
    }
    
    for _, attack := range attackPatterns {
        matched, _ := regexp.MatchString(attack.pattern, url)
        if matched {
            log.Printf("WAF BLOCKED: %s from %s | Path: %s | Type: %s", 
                r.Method, clientIP, r.URL.Path, attack.name)
            return true
        }
    }
    
    // Check for SQL injection in POST data
    if r.Method == "POST" {
        r.ParseForm()
        for _, values := range r.PostForm {
            for _, value := range values {
                lowerValue := strings.ToLower(value)
                sqlKeywords := []string{"'", "\"", ";", "--", "/*", "*/", "union", "select"}
                for _, keyword := range sqlKeywords {
                    if strings.Contains(lowerValue, keyword) {
                        log.Printf("WAF BLOCKED: SQL Injection attempt from %s", clientIP)
                        return true
                    }
                }
            }
        }
    }
    
    badBots := []string{
        "sqlmap", "nikto", "nmap", "metasploit",
        "dirbuster", "gobuster", "ffuf", "wfuzz",
        "hydra", "wpscan", "acunetix", "nessus",
        "netsparker", "appscan", "burpsuite",
    }
    
    for _, bot := range badBots {
        if strings.Contains(ua, bot) {
            log.Printf("WAF BLOCKED: Bad Bot from %s | UA: %s", 
                clientIP, ua)
            return true
        }
    }
    
    // Block empty or suspicious user agents
    if ua == "" || strings.Contains(ua, "bot") || strings.Contains(ua, "crawler") {
        log.Printf("WAF Warning: Suspicious UA from %s: %s", clientIP, ua)
    }
    
    return false
}

func getRealIP(r *http.Request) string {
    // Check forwarded headers
    headers := []string{
        "X-Forwarded-For",
        "X-Real-IP",
        "CF-Connecting-IP",
        "True-Client-IP",
    }
    
    for _, header := range headers {
        if ip := r.Header.Get(header); ip != "" {
            // Take first IP if multiple
            parts := strings.Split(ip, ",")
            if len(parts) > 0 {
                return strings.TrimSpace(parts[0])
            }
        }
    }
    
    // Fallback to remote address
    addr := r.RemoteAddr
    if idx := strings.LastIndex(addr, ":"); idx != -1 {
        addr = addr[:idx]
    }
    
    return addr
}