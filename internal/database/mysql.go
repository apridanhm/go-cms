package database

import (
    "context"
    "database/sql"
    "fmt"
    "time"
    
    _ "github.com/go-sql-driver/mysql"
    "github.com/golang-migrate/migrate/v4"
    "github.com/golang-migrate/migrate/v4/database/mysql"
    _ "github.com/golang-migrate/migrate/v4/source/file"
)

type DB struct {
    *sql.DB
    queryTimeout time.Duration
}

func NewMySQLConnection(host, port, user, password, dbname string) (*DB, error) {
    // Connection string with security parameters
    dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&charset=utf8mb4&collation=utf8mb4_unicode_ci&tls=preferred&timeout=30s",
        user, password, host, port, dbname)
    
    db, err := sql.Open("mysql", dsn)
    if err != nil {
        return nil, fmt.Errorf("failed to open database: %w", err)
    }
    
    // Security-focused connection pool settings
    db.SetMaxOpenConns(50)                   // Limit concurrent connections
    db.SetMaxIdleConns(25)                   // Keep some idle connections
    db.SetConnMaxLifetime(5 * time.Minute)   // Refresh connections periodically
    db.SetConnMaxIdleTime(2 * time.Minute)   // Close idle connections
    
    // Test connection with timeout
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    if err := db.PingContext(ctx); err != nil {
        db.Close()
        return nil, fmt.Errorf("failed to ping database: %w", err)
    }
    
    return &DB{
        DB:           db,
        queryTimeout: 15 * time.Second,
    }, nil
}

func (db *DB) RunMigrations(migrationPath string) error {
    driver, err := mysql.WithInstance(db.DB, &mysql.Config{
        MultiStatementEnabled: false, // Security: disable multiple statements
    })
    if err != nil {
        return fmt.Errorf("failed to create migration driver: %w", err)
    }
    
    m, err := migrate.NewWithDatabaseInstance(
        fmt.Sprintf("file://%s", migrationPath),
        "mysql", driver,
    )
    if err != nil {
        return fmt.Errorf("failed to create migration instance: %w", err)
    }
    
    // Run migrations
    if err := m.Up(); err != nil && err != migrate.ErrNoChange {
        return fmt.Errorf("failed to run migrations: %w", err)
    }
    
    return nil
}

// SecureQuery executes a query with parameterized inputs and context timeout
func (db *DB) SecureQuery(query string, args ...interface{}) (*sql.Rows, error) {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    // Validate query doesn't contain dangerous patterns
    if err := validateSQLQuery(query); err != nil {
        return nil, err
    }
    
    return db.QueryContext(ctx, query, args...)
}

// SecureQueryRow executes a query that returns at most one row
func (db *DB) SecureQueryRow(query string, args ...interface{}) *sql.Row {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    if err := validateSQLQuery(query); err != nil {
        // Return a dummy row that will error on scan
        return &sql.Row{}
    }
    
    return db.QueryRowContext(ctx, query, args...)
}

// SecureExec executes a command with parameterized inputs
func (db *DB) SecureExec(query string, args ...interface{}) (sql.Result, error) {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    if err := validateSQLQuery(query); err != nil {
        return nil, err
    }
    
    return db.ExecContext(ctx, query, args...)
}

// Transaction executes a function within a transaction with proper rollback
func (db *DB) Transaction(fn func(*sql.Tx) error) error {
    ctx, cancel := context.WithTimeout(context.Background(), db.queryTimeout)
    defer cancel()
    
    tx, err := db.BeginTx(ctx, &sql.TxOptions{
        Isolation: sql.LevelSerializable, // Highest isolation level
        ReadOnly:  false,
    })
    if err != nil {
        return fmt.Errorf("failed to begin transaction: %w", err)
    }
    
    defer func() {
        if p := recover(); p != nil {
            tx.Rollback()
            panic(p) // Re-panic after rollback
        }
    }()
    
    if err := fn(tx); err != nil {
        if rbErr := tx.Rollback(); rbErr != nil {
            return fmt.Errorf("transaction error: %w, rollback error: %v", err, rbErr)
        }
        return err
    }
    
    if err := tx.Commit(); err != nil {
        return fmt.Errorf("failed to commit transaction: %w", err)
    }
    
    return nil
}

// validateSQLQuery checks for potentially dangerous SQL patterns
func validateSQLQuery(query string) error {
    dangerousPatterns := []string{
        ";", "--", "/*", "*/", "xp_", "sp_",
        "DROP ", "TRUNCATE ", "DELETE FROM", 
        "CREATE ", "ALTER ", "EXEC ", "EXECUTE",
        "UNION ALL", "UNION SELECT",
    }
    
    upperQuery := string(preventSQLInjection([]byte(query)))
    for _, pattern := range dangerousPatterns {
        if containsCaseInsensitive(upperQuery, pattern) {
            return fmt.Errorf("potentially dangerous SQL pattern detected: %s", pattern)
        }
    }
    
    return nil
}

func containsCaseInsensitive(s, substr string) bool {
    if len(substr) > len(s) {
        return false
    }
    
    for i := 0; i <= len(s)-len(substr); i++ {
        if stringsEqualFold(s[i:i+len(substr)], substr) {
            return true
        }
    }
    return false
}

func stringsEqualFold(s1, s2 string) bool {
    if len(s1) != len(s2) {
        return false
    }
    
    for i := 0; i < len(s1); i++ {
        c1 := s1[i]
        c2 := s2[i]
        
        if c1 >= 'A' && c1 <= 'Z' {
            c1 += 'a' - 'A'
        }
        if c2 >= 'A' && c2 <= 'Z' {
            c2 += 'a' - 'A'
        }
        
        if c1 != c2 {
            return false
        }
    }
    
    return true
}

// preventSQLInjection removes null bytes and other dangerous characters
func preventSQLInjection(input []byte) []byte {
    // Remove null bytes
    input = bytes.ReplaceAll(input, []byte{0}, []byte{})
    
    // Remove backticks (can be used for SQL injection)
    input = bytes.ReplaceAll(input, []byte("`"), []byte{})
    
    return input
}

// Close closes the database connection
func (db *DB) Close() error {
    return db.DB.Close()
}

// HealthCheck checks if the database is healthy
func (db *DB) HealthCheck() error {
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    return db.PingContext(ctx)
}