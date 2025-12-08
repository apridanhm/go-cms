package database

import (
    "context"
    "database/sql"
    "fmt"
    "time"
    
    _ "github.com/go-sql-driver/mysql"
)

type DB struct {
    *sql.DB
    queryTimeout time.Duration
}

func NewMySQLConnection(host, port, user, password, dbname string) (*DB, error) {
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci&timeout=30s",
        user, password, host, port, dbname)
    
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Configure connection pool
    db.SetMaxOpenConns(25)
    db.SetMaxIdleConns(10)
    db.SetConnMaxLifetime(5 * time.Minute)
    db.SetConnMaxIdleTime(2 * time.Minute)
    
    // Test connection
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    if err := db.PingContext(ctx); err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    // Create tables if they don't exist
    if err := createTables(db); err != nil {
        fmt.Printf("Warning: Failed to create tables: %v\n", err)
    }
    
    return &DB{
        DB:           db,
        queryTimeout: 15 * time.Second,
    }, nil
}

func createTables(db *sql.DB) error {
    queries := []string{
        // Users table
        `CREATE TABLE IF NOT EXISTS users (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            role ENUM('superadmin','admin','editor','author','subscriber') DEFAULT 'subscriber',
            status ENUM('active','inactive','suspended') DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            INDEX idx_email (email),
            INDEX idx_status (status)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
        
        // Posts table
        `CREATE TABLE IF NOT EXISTS posts (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            title VARCHAR(255) NOT NULL,
            slug VARCHAR(255) UNIQUE NOT NULL,
            content LONGTEXT NOT NULL,
            excerpt TEXT,
            author_id INT UNSIGNED NOT NULL,
            status ENUM('draft','published','trash') DEFAULT 'draft',
            post_type ENUM('post','page') DEFAULT 'post',
            view_count INT UNSIGNED DEFAULT 0,
            published_at TIMESTAMP NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (author_id) REFERENCES users(id),
            INDEX idx_slug (slug),
            INDEX idx_status (status),
            FULLTEXT idx_content (title, content)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci`,
        
        // Security logs
        `CREATE TABLE IF NOT EXISTS security_logs (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            action VARCHAR(100) NOT NULL,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_ip (ip_address),
            INDEX idx_created (created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`,
    }
    
    for _, query := range queries {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        
        _, err := db.ExecContext(ctx, query)
        if err != nil {
            return fmt.Errorf("failed to execute query: %w\nQuery: %s", err, query)
        }
    }
    
    return nil
}

func (db *DB) RunMigrations(migrationPath string) error {
    // Simple migration system
    migrationQueries := []string{
        `CREATE TABLE IF NOT EXISTS migrations (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            name VARCHAR(255) UNIQUE NOT NULL,
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )`,
    }
    
    for _, query := range migrationQueries {
        if _, err := db.Exec(query); err != nil {
            return err
        }
    }
    
    return nil
}

// SecureQuery executes a query with timeout
func (db *DB) SecureQuery(query string, args ...interface{}) (*sql.Rows, error) {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    return db.QueryContext(ctx, query, args...)
}

// SecureExec executes a command with timeout
func (db *DB) SecureExec(query string, args ...interface{}) (sql.Result, error) {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    return db.ExecContext(ctx, query, args...)
}

func (db *DB) Close() error {
    return db.DB.Close()
}