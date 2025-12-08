# Go CMS - Secure Content Management System

Go CMS adalah sistem manajemen konten berbasis Go dengan fokus keamanan maksimal. Dibangun untuk menjadi alternatif yang lebih aman dari WordPress dengan performa tinggi.

## Fitur Utama

### Keamanan
- **Web Application Firewall (WAF)** terintegrasi
- **SQL Injection Protection** dengan prepared statements
- **XSS Protection** dengan sanitasi input/output
- **CSRF Protection** dengan token-based validation
- **Rate Limiting** untuk mencegah brute force
- **Two-Factor Authentication** (2FA)
- **Content Security Policy (CSP)** headers
- **HTTP Strict Transport Security (HSTS)**
- **Secure password hashing** dengan Argon2
- **Audit logging** lengkap

### Performa
- **High performance** dengan Go
- **Caching** dengan Redis/Memory
- **Connection pooling** untuk database
- **Optimized queries** dengan indexing

### Kompatibilitas
- **WordPress theme compatibility** (parsial)
- **RESTful API** dengan authentication
- **Admin dashboard** responsif
- **Multi-language support** (i18n)

## Instalasi

### Prasyarat
- Go 1.18 atau lebih baru
- MySQL 5.7+ atau MariaDB 10.3+
- Redis (opsional, untuk caching)

### Langkah Instalasi

1. **Clone repository**
   ```bash
   git clone https://github.com/yourusername/go-cms.git
   cd go-cms
