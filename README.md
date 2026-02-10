# 🔐 Go + JS Secure Authentication System

A production-ready authentication system built with **Go (Chi)** and **Vanilla JS**. It features a unified architecture where the Go backend serves both the API and the secure frontend, implementing industry-standard security practices including JWT rotation, JTI revocation, CSRF protection, and HttpOnly cookies.

## 🚀 Key Features

### Security Architecture
- **JWT Architecture**: Short-lived Access Tokens (15m) + Long-lived Refresh Tokens (7d).
- **Transport Security**: All tokens stored in **HttpOnly, Secure Cookies**. No `localStorage` usage.
- **Token Revocation (JTI)**: Server-side tracking of Access Token IDs (JTI). Logout invalidates tokens immediately.
- **Refresh Rotation**: Usage of a refresh token invalidates the old one and issues a new pair, detecting token theft.
- **CSRF Protection**: Double-Submit Cookie pattern with `X-CSRF-Token` headers for all state-changing requests.
- **Secure Storage**: Passwords hashed with **Bcrypt** (Cost 14). Refresh tokens hashed (SHA-256) in the database.
- **Rate Limiting**: In-memory lockout prevents brute access (5 failures = 10m ban).

### Unified Architecture
- **Single Port**: Backend serves static assets (`/asset`) and frontend HTML (`/*`) on port **8080**.
- **No CORS Issues**: Same-origin policy simplifies cookie handling and security.
- **Auto-Migration**: Database tables (`users`, `access_tokens`, `refresh_tokens`) are created automatically on startup.

## 🛠️ Tech Stack
- **Backend**: Go (Golang) 1.25+, `go-chi/chi`, `golang-jwt/jwt/v5`, `x/crypto/bcrypt`.
- **Database**: MySQL 8.0+.
- **Frontend**: Native JavaScript (ES6+), Fetch API, TailwindCSS (CDN).

## ⚡ Quick Start

### 1. Prerequisites
- Go installed.
- MySQL installed and running.
- Create a database named `auth`:
  ```sql
  CREATE DATABASE auth;
  ```

### 2. Configuration
Create a `.env` file in the `backend/` directory:

```env
# Database Config (Ensure ?parseTime=true is included or handled by code)
DB_CONNECTION_STRING=root:your_password@tcp(localhost:3306)/auth

# Secrets (Generate using `openssl rand -base64 32`)
JWT_SECRET_KEY=your_very_long_secure_random_string_for_access
JWT_REFRESH_SECRET_KEY=your_very_long_secure_random_string_for_refresh

# Security Flags
COOKIE_SECURE=false # Set to true in production (requires HTTPS)
```

### 3. Run the Application
Navigate to the backend directory and run the server. It will compile, initialize the database tables, and start listening.

```bash
cd backend
go mod tidy
go run main.go
```

The server will start on **port 8080**.

### 4. Access the App
Open your browser to:
👉 **[http://localhost:8080/index.html](http://localhost:8080/index.html)**

> **Note**: Do not use Live Server or open the HTML files directly. They must be served by the Go backend to share cookies securely.

## 📡 API Endpoints

All `POST` endpoints require `X-CSRF-Token` header (handled automatically by frontend).

| Method | Endpoint | Description | Protected |
| :--- | :--- | :--- | :--- |
| `POST` | `/auth` | Login (Returns HttpOnly Cookies) | No |
| `POST` | `/auth/register` | Create new account | No |
| `POST` | `/auth/refresh` | Rotate tokens using Refresh Cookie | No |
| `POST` | `/auth/logout` | Revoke tokens & clear cookies | Yes |
| `GET` | `/dashboard` | Protected Resource Example | **Yes** |

## 🗄️ Database Schema

The system automatically verifies and creates the following tables:
- **`users`**: Stores user credentials.
- **`refresh_tokens`**: Stores **hashes** of active refresh tokens (never plaintext).
- **`access_tokens`**: Stores active JTIs (Token IDs) for revocation checking.

## 🛡️ Security Details

1.  **Why no LocalStorage?** LocalStorage is vulnerable to XSS. HttpOnly cookies cannot be read by JavaScript, protecting tokens even if the frontend is compromised.
2.  **Why JTI Revocation?** JWTs are stateless by default. We add state checking (`access_tokens` table) to allow immediate "Kill Switch" capability for logout or banning users.
3.  **Why Refresh Rotation?** If a refresh token is stolen, the attacker can use it. But the moment the legitimate user (or the attacker) uses it again, the system detects a reuse attempt and can invalidate the chain.

## 📂 Project Structure

```
├── backend/
│   ├── main.go           # Entry point, Middleware, API Logic, File Server
│   ├── go.mod            # Dependencies
│   └── .env              # Configuration (Not committed)
├── frontend/
│   ├── index.html        # Login Page
│   ├── register.html     # Registration Page
│   ├── user_dashboard.html # Protected Dashboard
│   └── script.js         # Frontend Logic (Auth, Fetch, UI)
└── asset/
    ├── authentication.png
    └── ...
```- `access_tokens(id, jti UNIQUE, username, expires_at, created_at)` — for server-side revocation
See [database/auth.sql](database/auth.sql) for full DDL.

## API
All responses are JSON. Cookies are set/cleared automatically.

### POST /auth (login)
Body:
```json
{ "username": "johnd", "password_hash": "YourPassword123" }
```
On success: sets `access_token` (HttpOnly, ~15m) and `refresh_token` (HttpOnly, ~7d) cookies and returns tokens in the body for non-cookie clients:
```json
{ "access_token": "...", "refresh_token": "...", "token_type": "Bearer", "expires_in": "900" }
```

### POST /auth/register
Body:
```json
{ "name": "Jane Doe", "username": "janed", "password_hash": "YourPassword123" }
```
Password must be >=12 chars with upper, lower, digit, and special character.

### POST /auth/refresh
Uses refresh cookie (or send `refresh_token` in body) to rotate refresh + issue new access. Old refresh and access JTIs are revoked. Requires `X-CSRF-Token` header matching `csrf_token` cookie for browser flows.

### POST /auth/logout
Deletes stored refresh + all access JTIs for the user; clears cookies. Requires `X-CSRF-Token` header matching `csrf_token` cookie for browser flows.

### GET /dashboard
Protected route. Supply `Authorization: Bearer <access>` or rely on the HttpOnly access cookie.

## Security Measures
- Bcrypt password hashing (cost 14)
- Access token JTI store with revocation on logout/login/refresh
- Refresh tokens hashed at rest; rotation on every refresh
- HttpOnly cookies for tokens; avoid `localStorage`
- Strong password policy server-side (>=12 chars, upper/lower/digit/special)
- In-memory login rate limiting/lockout (5 bad attempts → 10 min block, keyed by username+IP)
- CSRF protection: `X-CSRF-Token` must match `csrf_token` cookie for unsafe methods

## Frontend Notes
- `fetch` calls use `credentials: 'include'` to send/receive cookies
- Tokens are not stored in `localStorage`
- `X-CSRF-Token` header is sent when a csrf_token cookie exists
- Authorization header fallback remains for non-browser clients

## Production Checklist
- Serve over HTTPS; set cookie `Secure=true` and consider `SameSite=Strict`
- Move rate limiting to a shared store (e.g., Redis) keyed by IP + username
- Add monitoring/logging and automated tests

## License
MIT
