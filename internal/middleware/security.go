package middleware

import (
    "net/http"
    "strings"
    
    "go-cms/internal/config"
)

func SecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // HSTS
            if cfg.Security.EnableHSTS && cfg.Server.SSL {
                w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
            }
            
            // XSS Protection
            if cfg.Security.EnableXSSProtection {
                w.Header().Set("X-XSS-Protection", "1; mode=block")
            }
            
            // Clickjacking protection
            if cfg.Security.EnableClickjackingProt {
                w.Header().Set("X-Frame-Options", "DENY")
            }
            
            // Content Type Options
            w.Header().Set("X-Content-Type-Options", "nosniff")
            
            // Referrer Policy
            w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
            
            // Permissions Policy
            w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
            
            // CSP if enabled
            if cfg.Security.EnableCSP {
                csp := []string{
                    "default-src 'self'",
                    "script-src 'self'",
                    "style-src 'self' 'unsafe-inline'",
                    "img-src 'self' data: https:",
                    "font-src 'self'",
                    "connect-src 'self'",
                    "frame-ancestors 'none'",
                    "base-uri 'self'",
                    "form-action 'self'",
                }
                w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
            }
            
            next.ServeHTTP(w, r)
        })
    }
}