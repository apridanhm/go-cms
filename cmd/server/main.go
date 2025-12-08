package main

import (
    "context"
    "log"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"
    
    "go-cms/internal/admin"
    "go-cms/internal/api"
    "go-cms/internal/auth"
    "go-cms/internal/cache"
    "go-cms/internal/config"
    "go-cms/internal/content"
    "go-cms/internal/database"
    "go-cms/internal/middleware"
    "go-cms/internal/security"
    "go-cms/internal/themes"
)

func main() {
    // Load configuration
    cfg, err := config.Load()
    if err != nil {
        log.Fatal("Failed to load config:", err)
    }
    
    // Initialize logger
    logger := config.NewLogger()
    
    // Initialize database
    db, err := database.NewMySQLConnection(
        cfg.Database.Host,
        cfg.Database.Port,
        cfg.Database.User,
        cfg.Database.Password,
        cfg.Database.Name,
    )
    if err != nil {
        logger.Fatal("Failed to connect to database:", err)
    }
    defer db.Close()
    
    // Run migrations
    if err := db.RunMigrations("./migrations"); err != nil {
        logger.Fatal("Failed to run migrations:", err)
    }
    
    // Initialize cache
    var cacheStore cache.CacheStore
    if cfg.Cache.RedisURL != "" {
        cacheStore = cache.NewRedisCache(cfg.Cache.RedisURL, cfg.Cache.TTL)
    } else {
        cacheStore = cache.NewMemoryCache(cfg.Cache.TTL)
    }
    
    // Initialize security firewall
    firewall := security.NewFirewall()
    
    // Initialize authentication
    authService := auth.NewAuthService(db, cfg.Security.JWTSecret)
    
    // Initialize theme manager
    themeManager := themes.NewManager("./web/themes")
    if err := themeManager.LoadThemes(); err != nil {
        logger.Printf("Warning: Failed to load themes: %v", err)
    }
    
    // Initialize content service
    contentService := content.NewService(db, cacheStore)
    
    // Initialize admin handlers
    adminHandler := admin.NewHandler(contentService, authService, themeManager)
    
    // Initialize API handlers
    apiHandler := api.NewHandler(contentService, authService)
    
    // Create main router
    router := http.NewServeMux()
    
    // Static files
    fs := http.FileServer(http.Dir("./web/static"))
    router.Handle("/static/", http.StripPrefix("/static/", fs))
    
    // Theme files
    themeFs := http.FileServer(http.Dir("./web/themes"))
    router.Handle("/themes/", http.StripPrefix("/themes/", themeFs))
    
    // Admin routes
    adminRouter := adminHandler.RegisterRoutes()
    router.Handle("/admin/", http.StripPrefix("/admin", adminRouter))
    
    // API routes
    apiRouter := apiHandler.RegisterRoutes()
    router.Handle("/api/", http.StripPrefix("/api", apiRouter))
    
    // Frontend routes
    setupFrontendRoutes(router, contentService, themeManager)
    
    // Apply middleware chain
    handler := middleware.Chain(
        router,
        middleware.Logging(logger),
        firewall.Middleware,
        middleware.CORS(cfg),
        middleware.CSRF(cfg.Security.CSRFKey),
        middleware.RateLimit(cfg.Security.RateLimitRequests, cfg.Security.RateLimitWindow),
        middleware.SecurityHeaders(cfg),
        middleware.WAF(),
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
        logger.Printf("Server starting on %s in %s mode", server.Addr, cfg.Server.Env)
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

func setupFrontendRoutes(router *http.ServeMux, contentService *content.Service, themeManager *themes.Manager) {
    // Home page
    router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/" {
            http.NotFound(w, r)
            return
        }
        
        posts, err := contentService.GetPosts(1, 10, "published")
        if err != nil {
            http.Error(w, "Internal Server Error", http.StatusInternalServerError)
            return
        }
        
        themeManager.RenderTemplate(w, "index.html", map[string]interface{}{
            "Posts": posts,
        })
    })
    
    // Single post/page
    router.HandleFunc("/{slug}", func(w http.ResponseWriter, r *http.Request) {
        slug := r.URL.Path[1:]
        content, err := contentService.GetContentBySlug(slug)
        if err != nil {
            http.NotFound(w, r)
            return
        }
        
        themeManager.RenderTemplate(w, "single.html", map[string]interface{}{
            "Content": content,
        })
    })
}