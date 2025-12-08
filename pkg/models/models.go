package models

import "time"

type User struct {
    ID           uint      `json:"id"`
    Username     string    `json:"username"`
    Email        string    `json:"email"`
    PasswordHash string    `json:"-"`
    Role         string    `json:"role"`
    Status       string    `json:"status"`
    CreatedAt    time.Time `json:"created_at"`
    UpdatedAt    time.Time `json:"updated_at"`
}

type Post struct {
    ID         uint       `json:"id"`
    Title      string     `json:"title"`
    Slug       string     `json:"slug"`
    Content    string     `json:"content"`
    Excerpt    string     `json:"excerpt"`
    AuthorID   uint       `json:"author_id"`
    Author     *User      `json:"author,omitempty"`
    Status     string     `json:"status"`
    PostType   string     `json:"post_type"`
    ViewCount  uint       `json:"view_count"`
    PublishedAt *time.Time `json:"published_at,omitempty"`
    CreatedAt  time.Time  `json:"created_at"`
    UpdatedAt  time.Time  `json:"updated_at"`
}