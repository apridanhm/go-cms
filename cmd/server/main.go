package main

import (
    "context"
    "fmt"
    "io"
    "log"
    "net/http"
    "os"
    "os/signal"
    "runtime"
    "strings"
    "syscall"
    "time"
    
    "go-cms/internal/config"
    "go-cms/internal/database"
    "go-cms/internal/middleware"
    "go-cms/internal/security"
)

// Buat variabel global untuk config
var appConfig *config.Config

func main() {
    // Setup security log file
    securityLog, err := os.OpenFile("security.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
    if err == nil {
        defer securityLog.Close()
        log.SetOutput(io.MultiWriter(os.Stdout, securityLog))
    }
    
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }
    
    // Simpan config ke variabel global
    appConfig = cfg
    
    logger := log.New(os.Stdout, "CMS: ", log.Ldate|log.Ltime|log.Lshortfile)
    
    // Initialize database (optional for now)
    var db *database.DB
    if cfg.Database.Password != "" && cfg.Database.Password != "your_mysql_password" {
        db, err = database.NewMySQLConnection(
            cfg.Database.Host,
            cfg.Database.Port,
            cfg.Database.User,
            cfg.Database.Password,
            cfg.Database.Name,
        )
        if err != nil {
            logger.Printf("Database warning: %v (continuing without DB)", err)
        } else {
            defer db.Close()
            logger.Println("Database connected successfully")
        }
    } else {
        logger.Println("Database password not set, running without database")
    }
    
    // Create main router
    router := http.NewServeMux()
    
    // Static files
    fs := http.FileServer(http.Dir("./web/static"))
    router.Handle("/static/", http.StripPrefix("/static/", fs))
    
    // Admin routes
    setupAdminRoutes(router, db)
    
    // API routes
    setupAPIRoutes(router, db)
    
    // Frontend routes
    setupFrontendRoutes(router, db)
    
    // Apply middleware
    handler := middleware.Chain(
        router,
        middleware.NewWAF().Middleware,
        security.NewFirewall().Middleware,
        middleware.SecurityHeaders(cfg),
        middleware.RateLimit(100, time.Minute),
    )
    
    // Start server
    server := &http.Server{
        Addr:         cfg.Server.Host + ":" + cfg.Server.Port,
        Handler:      handler,
        ReadTimeout:  30 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  120 * time.Second,
    }
    
    // Graceful shutdown
    go func() {
        logger.Printf("Server starting on %s", server.Addr)
        if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            logger.Fatal("Server failed:", err)
        }
    }()
    
    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    logger.Println("Shutting down server...")
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := server.Shutdown(ctx); err != nil {
        logger.Fatal("Server forced to shutdown:", err)
    }
    
    logger.Println("Server exited properly")
}

func setupAdminRoutes(router *http.ServeMux, db *database.DB) {
    adminRouter := http.NewServeMux()
    
    adminRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.Write([]byte(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Admin - Go CMS</title>
            <style>
                body { font-family: Arial; margin: 50px; }
                .admin-panel { border: 1px solid #ddd; padding: 20px; max-width: 800px; }
            </style>
        </head>
        <body>
            <div class="admin-panel">
                <h1>Go CMS Admin Panel</h1>
                <p><strong>Security Status:</strong> All security features enabled</p>
                <ul>
                    <li><a href="/admin/dashboard">Dashboard</a></li>
                    <li><a href="/admin/posts">Posts</a></li>
                    <li><a href="/admin/users">Users</a></li>
                    <li><a href="/admin/settings">Security Settings</a></li>
                </ul>
            </div>
        </body>
        </html>
        `))
    })
    
    adminRouter.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
        w.Write([]byte("Admin Dashboard - Coming Soon"))
    })
    
    router.Handle("/admin/", http.StripPrefix("/admin", adminRouter))
}

func setupAPIRoutes(router *http.ServeMux, db *database.DB) {
    apiRouter := http.NewServeMux()
    
    apiRouter.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Write([]byte(`{"status": "ok", "service": "go-cms", "security": "enabled"}`))
    })
    
    apiRouter.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        // Get actual Go version from runtime
        goVersion := strings.TrimPrefix(runtime.Version(), "go")
        
        // Use appConfig (global variable)
        env := "development"
        if appConfig != nil {
            env = appConfig.Server.Env
        }
        
        fmt.Fprintf(w, `{
            "version": "1.0.0",
            "go_version": "%s",
            "go_runtime": "%s",
            "build_time": "%s",
            "environment": "%s",
            "security": {
                "waf": "enabled",
                "firewall": "enabled",
                "rate_limit": "enabled",
                "csp": "enabled"
            }
        }`, goVersion, runtime.Version(), time.Now().Format(time.RFC3339), env)
    })
    
    apiRouter.HandleFunc("/info", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        // Memory stats
        var m runtime.MemStats
        runtime.ReadMemStats(&m)
        
        env := "development"
        host := "0.0.0.0"
        port := "8080"
        
        if appConfig != nil {
            env = appConfig.Server.Env
            host = appConfig.Server.Host
            port = appConfig.Server.Port
        }
        
        fmt.Fprintf(w, `{
            "server": {
                "host": "%s",
                "port": "%s",
                "environment": "%s"
            },
            "runtime": {
                "go_version": "%s",
                "compiler": "%s",
                "goroutines": %d,
                "cpus": %d
            },
            "memory": {
                "alloc": %d,
                "total_alloc": %d,
                "sys": %d,
                "num_gc": %d
            },
            "security": {
                "status": "active",
                "waf": true,
                "firewall": true
            }
        }`,
            host, port, env,
            strings.TrimPrefix(runtime.Version(), "go"),
            runtime.Compiler,
            runtime.NumGoroutine(),
            runtime.NumCPU(),
            m.Alloc,
            m.TotalAlloc,
            m.Sys,
            m.NumGC,
        )
    })
    
    // Security logs endpoint
    apiRouter.HandleFunc("/logs/security", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        
        // Read log file if exists
        logData := "Security logs available in console"
        if _, err := os.Stat("security.log"); err == nil {
            data, _ := os.ReadFile("security.log")
            logData = string(data)
        }
        
        // Escape newlines for JSON
        escapedLog := strings.ReplaceAll(logData, "\n", "\\n")
        escapedLog = strings.ReplaceAll(escapedLog, "\"", "\\\"")
        
        fmt.Fprintf(w, `{"security_logs": "%s"}`, escapedLog)
    })
    
    router.Handle("/api/", http.StripPrefix("/api", apiRouter))
}

func setupFrontendRoutes(router *http.ServeMux, db *database.DB) {
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "text/html")
        w.Write([]byte(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Go CMS - Secure Content Management</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 0; }
                .header { background: #2c3e50; color: white; padding: 20px; }
                .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
                .feature { background: #f8f9fa; padding: 20px; margin: 20px 0; border-radius: 10px; }
                .security-badge { background: #27ae60; color: white; padding: 5px 10px; border-radius: 5px; }
                .attack-log { background: #ffebee; padding: 10px; margin: 10px 0; border-left: 4px solid #f44336; }
            </style>
        </head>
        <body>
            <div class="header">
                <div class="container">
                    <h1>Go CMS - Enterprise Grade Security</h1>
                    <p>High-performance CMS built with Go and maximum security</p>
                </div>
            </div>
            <div class="container">
                <div class="feature">
                    <h2><span class="security-badge"></span> Security Features</h2>
                    <ul>
                        <li>Web Application Firewall (WAF) - Active</li>
                        <li>SQL Injection Protection</li>
                        <li>XSS & CSRF Protection</li>
                        <li>Rate Limiting & DDoS Protection</li>
                        <li>Real-time Attack Detection</li>
                        <li>Audit Logging</li>
                    </ul>
                </div>
                
                <div class="feature">
                    <h2>Security Dashboard</h2>
                    <div class="attack-log">
                        <strong>Live Attack Monitoring:</strong>
                        <p>WAF is actively blocking malicious requests</p>
                        <p><a href="/api/logs/security" target="_blank">View Security Logs</a></p>
                    </div>
                </div>
                
                <div class="feature">
                    <h2>Performance</h2>
                    <p>Built with Go for maximum performance and concurrency.</p>
                </div>
                
                <p>
                    <a href="/admin">Admin Panel</a> | 
                    <a href="/api/health">API Health</a> | 
                    <a href="/api/version">Version Info</a> |
                    <a href="/api/info">System Info</a>
                </p>
            </div>
        </body>
        </html>
        `))
    })
}