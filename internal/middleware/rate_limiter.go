package middleware

import (
    "net/http"
    "sync"
    "time"
)

type RateLimiter struct {
    requests map[string][]time.Time
    mu       sync.RWMutex
    limit    int
    window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
    return &RateLimiter{
        requests: make(map[string][]time.Time),
        limit:    limit,
        window:   window,
    }
}

func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIP(r)
        
        if !rl.Allow(clientIP) {
            http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (rl *RateLimiter) Allow(ip string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()
    
    now := time.Now()
    
    // Clean old requests
    var validRequests []time.Time
    for _, t := range rl.requests[ip] {
        if now.Sub(t) <= rl.window {
            validRequests = append(validRequests, t)
        }
    }
    
    // Check if limit exceeded
    if len(validRequests) >= rl.limit {
        return false
    }
    
    // Add current request
    validRequests = append(validRequests, now)
    rl.requests[ip] = validRequests
    
    return true
}

func getClientIP(r *http.Request) string {
    // Check headers
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return ip
    }
    if ip := r.Header.Get("X-Real-IP"); ip != "" {
        return ip
    }
    
    // Fallback
    return r.RemoteAddr
}

func RateLimit(limit int, window time.Duration) func(http.Handler) http.Handler {
    limiter := NewRateLimiter(limit, window)
    return limiter.Middleware
}