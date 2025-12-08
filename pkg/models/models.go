package models

import (
    "time"
)

type User struct {
    ID                     uint      `json:"id" db:"id"`
    UUID                   string    `json:"uuid" db:"uuid"`
    Username               string    `json:"username" db:"username"`
    Email                  string    `json:"email" db:"email"`
    PasswordHash           string    `json:"-" db:"password_hash"`
    PasswordSalt           string    `json:"-" db:"password_salt"`
    TwoFactorSecret        *string   `json:"-" db:"two_factor_secret"`
    TwoFactorEnabled       bool      `json:"two_factor_enabled" db:"two_factor_enabled"`
    Role                   string    `json:"role" db:"role"`
    Status                 string    `json:"status" db:"status"`
    FailedLoginAttempts    int       `json:"-" db:"failed_login_attempts"`
    LastLoginAt            *time.Time `json:"last_login_at" db:"last_login_at"`
    LastLoginIP            *string   `json:"last_login_ip" db:"last_login_ip"`
    EmailVerified          bool      `json:"email_verified" db:"email_verified"`
    EmailVerificationToken *string   `json:"-" db:"email_verification_token"`
    PasswordResetToken     *string   `json:"-" db:"password_reset_token"`
    PasswordResetExpires   *time.Time `json:"-" db:"password_reset_expires"`
    CreatedAt              time.Time `json:"created_at" db:"created_at"`
    UpdatedAt              time.Time `json:"updated_at" db:"updated_at"`
}

type Post struct {
    ID            uint       `json:"id" db:"id"`
    UUID          string     `json:"uuid" db:"uuid"`
    Title         string     `json:"title" db:"title"`
    Slug          string     `json:"slug" db:"slug"`
    Content       string     `json:"content" db:"content"`
    Excerpt       string     `json:"excerpt" db:"excerpt"`
    AuthorID      uint       `json:"author_id" db:"author_id"`
    Author        *User      `json:"author,omitempty" db:"-"`
    Status        string     `json:"status" db:"status"`
    Password      *string    `json:"password,omitempty" db:"password"`
    CommentStatus string     `json:"comment_status" db:"comment_status"`
    PostType      string     `json:"post_type" db:"post_type"`
    MimeType      *string    `json:"mime_type,omitempty" db:"mime_type"`
    ParentID      *uint      `json:"parent_id,omitempty" db:"parent_id"`
    MenuOrder     int        `json:"menu_order" db:"menu_order"`
    ViewCount     uint       `json:"view_count" db:"view_count"`
    PublishedAt   *time.Time `json:"published_at,omitempty" db:"published_at"`
    CreatedAt     time.Time  `json:"created_at" db:"created_at"`
    UpdatedAt     time.Time  `json:"updated_at" db:"updated_at"`
    
    // Relationships
    Categories []Category `json:"categories,omitempty" db:"-"`
    Tags       []Tag      `json:"tags,omitempty" db:"-"`
    Meta       []Meta     `json:"meta,omitempty" db:"-"`
}

type Category struct {
    ID          uint      `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Slug        string    `json:"slug" db:"slug"`
    Description string    `json:"description" db:"description"`
    ParentID    *uint     `json:"parent_id,omitempty" db:"parent_id"`
    Count       uint      `json:"count" db:"count"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Tag struct {
    ID          uint      `json:"id" db:"id"`
    Name        string    `json:"name" db:"name"`
    Slug        string    `json:"slug" db:"slug"`
    Description string    `json:"description" db:"description"`
    Count       uint      `json:"count" db:"count"`
    CreatedAt   time.Time `json:"created_at" db:"created_at"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

type Meta struct {
    ID        uint      `json:"id" db:"id"`
    PostID    uint      `json:"post_id" db:"post_id"`
    MetaKey   string    `json:"meta_key" db:"meta_key"`
    MetaValue string    `json:"meta_value" db:"meta_value"`
    CreatedAt time.Time `json:"created_at" db:"created_at"`
    UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

type LoginAttempt struct {
    ID         uint      `json:"id" db:"id"`
    UserID     *uint     `json:"user_id,omitempty" db:"user_id"`
    IPAddress  string    `json:"ip_address" db:"ip_address"`
    UserAgent  string    `json:"user_agent" db:"user_agent"`
    Successful bool      `json:"successful" db:"successful"`
    CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

type AuditLog struct {
    ID         uint       `json:"id" db:"id"`
    UserID     *uint      `json:"user_id,omitempty" db:"user_id"`
    Action     string     `json:"action" db:"action"`
    EntityType string     `json:"entity_type" db:"entity_type"`
    EntityID   *uint      `json:"entity_id,omitempty" db:"entity_id"`
    OldValues  string     `json:"old_values,omitempty" db:"old_values"`
    NewValues  string     `json:"new_values,omitempty" db:"new_values"`
    IPAddress  string     `json:"ip_address" db:"ip_address"`
    UserAgent  string     `json:"user_agent" db:"user_agent"`
    CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

type SecuritySetting struct {
    ID          uint      `json:"id" db:"id"`
    SettingKey  string    `json:"setting_key" db:"setting_key"`
    SettingValue string   `json:"setting_value" db:"setting_value"`
    SettingType string    `json:"setting_type" db:"setting_type"`
    IsEncrypted bool      `json:"is_encrypted" db:"is_encrypted"`
    Description string    `json:"description" db:"description"`
    UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}