package middleware

import (
    "bufio"
    "bytes"
    "io"
    "net"
    "net/http"
    "regexp"
    "strings"
    "time"
    
    "github.com/patrickmn/go-cache"
)

type WAF struct {
    cache          *cache.Cache
    blockedIPs     map[string]time.Time
    suspiciousIPs  map[string]int
    rateLimits     map[string][]time.Time
    rules          []WAFRule
    mu             sync.RWMutex
}

type WAFRule struct {
    Name        string
    Pattern     *regexp.Regexp
    Action      string // "block", "log", "challenge"
    Description string
    Score       int
}

func NewWAF() *WAF {
    waf := &WAF{
        cache:         cache.New(5*time.Minute, 10*time.Minute),
        blockedIPs:    make(map[string]time.Time),
        suspiciousIPs: make(map[string]int),
        rateLimits:    make(map[string][]time.Time),
        rules:         loadWAFRules(),
    }
    
    // Cleanup goroutine
    go waf.cleanup()
    
    return waf
}

func (waf *WAF) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getRealIP(r)
        
        // Check if IP is blocked
        if waf.isIPBlocked(clientIP) {
            waf.logBlockedRequest(r, "IP blocked")
            http.Error(w, "Access Denied", http.StatusForbidden)
            return
        }
        
        // Rate limiting
        if !waf.checkRateLimit(clientIP) {
            waf.logBlockedRequest(r, "Rate limit exceeded")
            http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
            return
        }
        
        // Clone request for body inspection
        var bodyBytes []byte
        if r.Body != nil {
            bodyBytes, _ = io.ReadAll(r.Body)
            r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
        }
        
        // Analyze request
        threatScore := waf.analyzeRequest(r, bodyBytes)
        
        // Take action based on threat score
        if threatScore >= 100 {
            waf.blockIP(clientIP, 24*time.Hour)
            waf.logBlockedRequest(r, "High threat score")
            http.Error(w, "Access Denied", http.StatusForbidden)
            return
        } else if threatScore >= 50 {
            waf.addSuspiciousIP(clientIP)
            // Add CAPTCHA challenge
            if !waf.handleChallenge(w, r) {
                return
            }
        }
        
        // Add security headers
        w.Header().Set("X-WAF-Status", "Protected")
        
        next.ServeHTTP(w, r)
    })
}

func (waf *WAF) analyzeRequest(r *http.Request, body []byte) int {
    score := 0
    
    // Check URL
    score += waf.checkURL(r.URL.Path)
    score += waf.checkURL(r.URL.RawQuery)
    
    // Check headers
    for key, values := range r.Header {
        for _, value := range values {
            score += waf.checkHeader(key, value)
        }
    }
    
    // Check body
    if len(body) > 0 {
        score += waf.checkBody(string(body))
    }
    
    // Check HTTP method
    if r.Method != "GET" && r.Method != "POST" && r.Method != "PUT" && 
       r.Method != "DELETE" && r.Method != "HEAD" && r.Method != "OPTIONS" {
        score += 10
    }
    
    // Check user agent
    ua := r.UserAgent()
    if ua == "" || strings.Contains(strings.ToLower(ua), "bot") {
        score += 5
    }
    
    // Check referer
    referer := r.Referer()
    if referer != "" && !strings.HasPrefix(referer, "http") {
        score += 10
    }
    
    return score
}

func (waf *WAF) checkURL(url string) int {
    score := 0
    
    patterns := []struct {
        pattern *regexp.Regexp
        score   int
    }{
        {regexp.MustCompile(`(?i)(union.*select)`), 50},
        {regexp.MustCompile(`(?i)(select.*from)`), 40},
        {regexp.MustCompile(`(?i)(insert.*into)`), 40},
        {regexp.MustCompile(`(?i)(update.*set)`), 40},
        {regexp.MustCompile(`(?i)(delete.*from)`), 40},
        {regexp.MustCompile(`(?i)(drop.*table)`), 50},
        {regexp.MustCompile(`(?i)(script.*alert)`), 30},
        {regexp.MustCompile(`(?i)(<script)`), 25},
        {regexp.MustCompile(`(?i)(javascript:)`), 20},
        {regexp.MustCompile(`(?i)(onload=)`), 15},
        {regexp.MustCompile(`(?i)(onerror=)`), 15},
        {regexp.MustCompile(`(?i)(eval\()`), 30},
        {regexp.MustCompile(`\.\./`), 20}, // Path traversal
        {regexp.MustCompile(`/etc/passwd`), 50},
        {regexp.MustCompile(`/proc/self`), 40},
        {regexp.MustCompile(`phpinfo`), 30},
        {regexp.MustCompile(`\.git/`), 25},
        {regexp.MustCompile(`\.env`), 25},
        {regexp.MustCompile(`wp-admin`), 10},
        {regexp.MustCompile(`wp-login`), 10},
        {regexp.MustCompile(`administrator`), 10},
    }
    
    for _, p := range patterns {
        if p.pattern.MatchString(url) {
            score += p.score
        }
    }
    
    return score
}

func (waf *WAF) checkHeader(key, value string) int {
    score := 0
    
    // Check for suspicious headers
    suspiciousHeaders := map[string][]*regexp.Regexp{
        "User-Agent": {
            regexp.MustCompile(`(?i)(sqlmap|nikto|nmap|metasploit|hydra|wpscan)`),
            regexp.MustCompile(`(?i)(dirbuster|gobuster|ffuf|wfuzz)`),
        },
        "X-Forwarded-For": {
            regexp.MustCompile(`\d+\.\d+\.\d+\.\d+,\s*\d+\.\d+\.\d+\.\d+`), // Multiple IPs
        },
    }
    
    if patterns, ok := suspiciousHeaders[strings.ToLower(key)]; ok {
        for _, pattern := range patterns {
            if pattern.MatchString(value) {
                score += 20
            }
        }
    }
    
    return score
}

func (waf *WAF) checkBody(body string) int {
    score := 0
    
    patterns := []struct {
        pattern *regexp.Regexp
        score   int
    }{
        {regexp.MustCompile(`(?i)<\s*iframe`), 15},
        {regexp.MustCompile(`(?i)<\s*object`), 15},
        {regexp.MustCompile(`(?i)<\s*embed`), 15},
        {regexp.MustCompile(`(?i)document\.cookie`), 20},
        {regexp.MustCompile(`(?i)window\.location`), 15},
        {regexp.MustCompile(`(?i)base64_decode`), 25},
        {regexp.MustCompile(`(?i)shell_exec`), 50},
        {regexp.MustCompile(`(?i)system\s*\(`), 50},
        {regexp.MustCompile(`(?i)passthru\s*\(`), 50},
        {regexp.MustCompile(`(?i)exec\s*\(`), 50},
        {regexp.MustCompile(`(?i)eval\s*\(`), 40},
        {regexp.MustCompile(`(?i)assert\s*\(`), 40},
        {regexp.MustCompile(`(?i)file_put_contents`), 30},
        {regexp.MustCompile(`(?i)fopen\s*\(`), 25},
        {regexp.MustCompile(`(?i)readfile\s*\(`), 25},
        {regexp.MustCompile(`(?i)curl_exec`), 30},
        {regexp.MustCompile(`(?i)fsockopen`), 30},
    }
    
    for _, p := range patterns {
        if p.pattern.MatchString(body) {
            score += p.score
        }
    }
    
    return score
}

func (waf *WAF) checkRateLimit(ip string) bool {
    waf.mu.Lock()
    defer waf.mu.Unlock()
    
    now := time.Now()
    
    // Clean old timestamps
    var validTimestamps []time.Time
    for _, ts := range waf.rateLimits[ip] {
        if now.Sub(ts) < time.Minute {
            validTimestamps = append(validTimestamps, ts)
        }
    }
    
    // Check if limit exceeded (100 requests per minute)
    if len(validTimestamps) >= 100 {
        return false
    }
    
    // Add current request
    validTimestamps = append(validTimestamps, now)
    waf.rateLimits[ip] = validTimestamps
    
    return true
}

func (waf *WAF) isIPBlocked(ip string) bool {
    waf.mu.RLock()
    defer waf.mu.RUnlock()
    
    if blockTime, ok := waf.blockedIPs[ip]; ok {
        if time.Since(blockTime) < 24*time.Hour {
            return true
        }
        // Remove expired block
        delete(waf.blockedIPs, ip)
    }
    
    return false
}

func (waf *WAF) blockIP(ip string, duration time.Duration) {
    waf.mu.Lock()
    defer waf.mu.Unlock()
    
    waf.blockedIPs[ip] = time.Now().Add(duration)
}

func (waf *WAF) addSuspiciousIP(ip string) {
    waf.mu.Lock()
    defer waf.mu.Unlock()
    
    waf.suspiciousIPs[ip]++
    
    // Auto-block after 5 suspicious activities
    if waf.suspiciousIPs[ip] >= 5 {
        waf.blockedIPs[ip] = time.Now().Add(1 * time.Hour)
    }
}

func (waf *WAF) handleChallenge(w http.ResponseWriter, r *http.Request) bool {
    // Implement CAPTCHA challenge
    // For now, just allow with logging
    return true
}

func (waf *WAF) logBlockedRequest(r *http.Request, reason string) {
    // Log to file or external service
    log.Printf("WAF blocked request: %s %s from %s - Reason: %s",
        r.Method, r.URL.Path, getRealIP(r), reason)
}

func (waf *WAF) cleanup() {
    ticker := time.NewTicker(5 * time.Minute)
    defer ticker.Stop()
    
    for {
        select {
        case <-ticker.C:
            waf.mu.Lock()
            now := time.Now()
            
            // Clean expired blocks
            for ip, blockTime := range waf.blockedIPs {
                if now.After(blockTime) {
                    delete(waf.blockedIPs, ip)
                }
            }
            
            // Clean old suspicious counts
            for ip, count := range waf.suspiciousIPs {
                if count > 0 {
                    waf.suspiciousIPs[ip] = count - 1
                }
                if count <= 1 {
                    delete(waf.suspiciousIPs, ip)
                }
            }
            
            waf.mu.Unlock()
        }
    }
}

func getRealIP(r *http.Request) string {
    // Check common proxy headers
    headers := []string{
        "X-Real-IP",
        "X-Forwarded-For",
        "CF-Connecting-IP",
        "True-Client-IP",
    }
    
    for _, header := range headers {
        if ip := r.Header.Get(header); ip != "" {
            // Take first IP if multiple
            if comma := strings.Index(ip, ","); comma != -1 {
                ip = ip[:comma]
            }
            if net.ParseIP(ip) != nil {
                return ip
            }
        }
    }
    
    // Fallback to remote address
    host, _, _ := net.SplitHostPort(r.RemoteAddr)
    return host
}

func loadWAFRules() []WAFRule {
    return []WAFRule{
        {
            Name:        "SQL Injection",
            Pattern:     regexp.MustCompile(`(?i)(union.*select|select.*from|insert.*into|update.*set|delete.*from|drop.*table)`),
            Action:      "block",
            Description: "SQL injection attempt detected",
            Score:       50,
        },
        {
            Name:        "XSS Attack",
            Pattern:     regexp.MustCompile(`(?i)(<script|javascript:|onload=|onerror=|alert\(|prompt\(|confirm\()`),
            Action:      "block",
            Description: "Cross-site scripting attempt detected",
            Score:       40,
        },
        {
            Name:        "Path Traversal",
            Pattern:     regexp.MustCompile(`\.\./|\.\.\\|/etc/passwd|/proc/self`),
            Action:      "block",
            Description: "Path traversal attempt detected",
            Score:       50,
        },
        {
            Name:        "Command Injection",
            Pattern:     regexp.MustCompile(`(?i)(shell_exec|system\(|exec\(|passthru\(|eval\()`),
            Action:      "block",
            Description: "Command injection attempt detected",
            Score:       60,
        },
        {
            Name:        "File Inclusion",
            Pattern:     regexp.MustCompile(`(?i)(include\(|require\(|include_once\(|require_once\(|file_put_contents|fopen\(|readfile\()`),
            Action:      "block",
            Description: "File inclusion attempt detected",
            Score:       40,
        },
    }
}