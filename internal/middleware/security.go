package middleware

import (
    "net/http"
    "strings"
    "time"
    
    "go-cms/internal/config"
)

func SecurityHeaders(cfg *config.Config) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            // HSTS - Strict Transport Security
            if cfg.Security.EnableHSTS && (r.TLS != nil || cfg.Server.SSL) {
                w.Header().Set("Strict-Transport-Security", 
                    "max-age=31536000; includeSubDomains; preload")
            }
            
            // XSS Protection
            if cfg.Security.EnableXSSProtection {
                w.Header().Set("X-XSS-Protection", "1; mode=block")
            }
            
            // Clickjacking protection
            if cfg.Security.EnableClickjackingProt {
                w.Header().Set("X-Frame-Options", "DENY")
                w.Header().Set("Content-Security-Policy", "frame-ancestors 'none';")
            }
            
            // MIME sniffing protection
            w.Header().Set("X-Content-Type-Options", "nosniff")
            
            // Referrer Policy
            w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
            
            // Permissions Policy
            w.Header().Set("Permissions-Policy", 
                "camera=(), microphone=(), geolocation=(), payment=()")
            
            // Feature Policy (legacy, for compatibility)
            w.Header().Set("Feature-Policy", 
                "camera 'none'; microphone 'none'; geolocation 'none'; payment 'none'")
            
            // Cache Control for sensitive pages
            if strings.Contains(r.URL.Path, "/admin") || 
               strings.Contains(r.URL.Path, "/api") ||
               strings.Contains(r.URL.Path, "/auth") {
                w.Header().Set("Cache-Control", 
                    "no-store, no-cache, must-revalidate, proxy-revalidate")
                w.Header.Set("Pragma", "no-cache")
                w.Header.Set("Expires", "0")
            }
            
            // Content Security Policy
            if cfg.Security.EnableCSP {
                csp := []string{
                    "default-src 'self'",
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval'",
                    "style-src 'self' 'unsafe-inline'",
                    "img-src 'self' data: blob: https:",
                    "font-src 'self' data: https:",
                    "connect-src 'self' https: wss:",
                    "media-src 'self' https:",
                    "object-src 'none'",
                    "frame-ancestors 'none'",
                    "base-uri 'self'",
                    "form-action 'self'",
                    "frame-src 'self'",
                    "worker-src 'self' blob:",
                    "manifest-src 'self'",
                }
                
                // Add nonce for inline scripts if needed
                if nonce := r.Context().Value("csp_nonce"); nonce != nil {
                    csp[1] = "script-src 'self' 'nonce-" + nonce.(string) + "'"
                }
                
                w.Header().Set("Content-Security-Policy", strings.Join(csp, "; "))
            }
            
            // X-Permitted-Cross-Domain-Policies
            w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
            
            // Expect-CT (Certificate Transparency)
            w.Header().Set("Expect-CT", 
                "max-age=86400, enforce, report-uri=\"https://example.com/report\"")
            
            // Set secure cookies for HTTPS
            if r.TLS != nil || cfg.Server.SSL {
                if cookies := w.Header().Get("Set-Cookie"); cookies != "" {
                    secureCookies := strings.ReplaceAll(cookies, ";", "; Secure; HttpOnly; SameSite=Strict")
                    w.Header().Set("Set-Cookie", secureCookies)
                }
            }
            
            next.ServeHTTP(w, r)
        })
    }
}

func CSPNonce(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Generate nonce for inline scripts
        nonce := generateNonce()
        ctx := context.WithValue(r.Context(), "csp_nonce", nonce)
        next.ServeHTTP(w, r.WithContext(ctx))
    })
}

func generateNonce() string {
    // Generate a random 16-byte nonce
    b := make([]byte, 16)
    rand.Read(b)
    return base64.StdEncoding.EncodeToString(b)
}

func SecureCookies(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Intercept Set-Cookie headers
        rw := &secureResponseWriter{ResponseWriter: w}
        next.ServeHTTP(rw, r)
        
        // Secure all cookies
        for i, cookie := range rw.cookies {
            cookie.Secure = true
            cookie.HttpOnly = true
            cookie.SameSite = http.SameSiteStrictMode
            
            // Set Max-Age if not set
            if cookie.MaxAge == 0 && cookie.Expires.IsZero() {
                cookie.MaxAge = int(30 * time.Minute / time.Second)
            }
            
            http.SetCookie(w, cookie)
        }
    })
}

type secureResponseWriter struct {
    http.ResponseWriter
    cookies []*http.Cookie
}

func (w *secureResponseWriter) WriteHeader(code int) {
    w.ResponseWriter.WriteHeader(code)
}

func (w *secureResponseWriter) Header() http.Header {
    return w.ResponseWriter.Header()
}

func (w *secureResponseWriter) Write(b []byte) (int, error) {
    return w.ResponseWriter.Write(b)
}