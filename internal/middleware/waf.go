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
            log.Printf("WAF blocked attack from %s", clientIP)
            http.Error(w, "Access denied", http.StatusForbidden)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (waf *WAF) isAttack(r *http.Request) bool {
    // Check URL
    url := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
    
    attackPatterns := []string{
        "union.*select",
        "select.*from",
        "insert.*into",
        "<script",
        "javascript:",
        "onload=",
        "onerror=",
        "../",
        "/etc/passwd",
        "wp-admin",
        "wp-login",
        ".git/",
        ".env",
    }
    
    for _, pattern := range attackPatterns {
        matched, _ := regexp.MatchString(pattern, url)
        if matched {
            return true
        }
    }
    
    // Check user agent
    ua := strings.ToLower(r.UserAgent())
    badBots := []string{"sqlmap", "nikto", "nmap", "dirbuster"}
    for _, bot := range badBots {
        if strings.Contains(ua, bot) {
            return true
        }
    }
    
    return false
}

func getRealIP(r *http.Request) string {
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return strings.Split(ip, ",")[0]
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    return r.RemoteAddr
}
