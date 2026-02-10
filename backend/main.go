package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	_ "github.com/go-sql-driver/mysql"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB
var jwtKey []byte
var refreshKey []byte
var allowedOrigins = map[string]bool{
	"http://127.0.0.1:5500": true,
	"http://localhost:5500": true,
}

var loginAttempts = struct {
	sync.Mutex
	counts       map[string]int
	blockedUntil map[string]time.Time
}{
	counts:       map[string]int{},
	blockedUntil: map[string]time.Time{},
}

const (
	accessTokenTTL  = 15 * time.Minute
	refreshTokenTTL = 7 * 24 * time.Hour
)

var secureCookies bool

func initSchema(db *sql.DB) error {
	queries := []string{
		`CREATE TABLE IF NOT EXISTS users (
            id int NOT NULL AUTO_INCREMENT,
            name varchar(255) DEFAULT NULL,
            username varchar(255) NOT NULL UNIQUE,
            password_hash varchar(300) DEFAULT NULL,
            created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;`,
		`CREATE TABLE IF NOT EXISTS refresh_tokens (
            id int NOT NULL AUTO_INCREMENT,
            username varchar(255) NOT NULL,
            token_hash varchar(64) NOT NULL,
            expires_at timestamp NOT NULL,
            created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            KEY idx_username (username),
            KEY idx_expires_at (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;`,
		`CREATE TABLE IF NOT EXISTS access_tokens (
            id int NOT NULL AUTO_INCREMENT,
            jti varchar(64) NOT NULL,
            username varchar(255) NOT NULL,
            expires_at timestamp NOT NULL,
            created_at timestamp NULL DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY uq_jti (jti),
            KEY idx_username (username),
            KEY idx_expires_at (expires_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;`,
	}
	for _, query := range queries {
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

func generateJTI() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func generateCSRFToken() (string, error) {
	return generateJTI()
}

func isStrongPassword(pw string) bool {
	if len(pw) < 12 {
		return false
	}
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	for _, c := range pw {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?/", c):
			hasSpecial = true
		}
	}
	return hasLower && hasUpper && hasDigit && hasSpecial
}

func rateLimitKey(username string, r *http.Request) string {
	ip := r.RemoteAddr
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ip = strings.Split(forwarded, ",")[0]
	}
	if host, _, err := net.SplitHostPort(ip); err == nil {
		ip = host
	}
	return fmt.Sprintf("%s|%s", username, ip)
}

func isBlocked(key string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	until, ok := loginAttempts.blockedUntil[key]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(loginAttempts.blockedUntil, key)
	loginAttempts.counts[key] = 0
	return false
}

func recordFailure(key string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.counts[key]++
	if loginAttempts.counts[key] >= 5 {
		loginAttempts.blockedUntil[key] = time.Now().Add(10 * time.Minute)
		loginAttempts.counts[key] = 0
	}
}

func resetAttempts(key string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.counts[key] = 0
	delete(loginAttempts.blockedUntil, key)
}

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	accessCookie := &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   secureCookies,
		MaxAge:   int(accessTokenTTL.Seconds()),
	}
	refreshCookie := &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   secureCookies,
		MaxAge:   int(refreshTokenTTL.Seconds()),
	}
	if secureCookies {
		accessCookie.SameSite = http.SameSiteStrictMode
		refreshCookie.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, accessCookie)
	http.SetCookie(w, refreshCookie)
}

func setCSRFCookie(w http.ResponseWriter, token string) {
	csrfCookie := &http.Cookie{
		Name:     "csrf_token",
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   secureCookies,
		MaxAge:   int(refreshTokenTTL.Seconds()),
	}
	if secureCookies {
		csrfCookie.SameSite = http.SameSiteStrictMode
	}
	http.SetCookie(w, csrfCookie)
}

func clearAuthCookies(w http.ResponseWriter) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Path: "/", Expires: expired, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/auth", Expires: expired, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "csrf_token", Value: "", Path: "/", Expires: expired, MaxAge: -1})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); allowedOrigins[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, PATCH")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func csrfMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}

		// Allow unauthenticated creation endpoints without CSRF (login/register)
		if r.URL.Path == "/auth" || r.URL.Path == "/auth/register" {
			next.ServeHTTP(w, r)
			return
		}

		cookie, err := r.Cookie("csrf_token")
		if err != nil || cookie.Value == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}
		headToken := r.Header.Get("X-CSRF-Token")
		if headToken == "" {
			http.Error(w, "CSRF token missing", http.StatusForbidden)
			return
		}
		if subtle.ConstantTimeCompare([]byte(headToken), []byte(cookie.Value)) != 1 {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func generateAccessToken(username string) (string, string, error) {
	jti, err := generateJTI()
	if err != nil {
		return "", "", err
	}
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ID:        jti,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(accessTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "auth-service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(jwtKey)
	if err != nil {
		return "", "", err
	}
	return signed, jti, nil
}

func generateRefreshToken(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(refreshTokenTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Issuer:    "auth-service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshKey)
}

func verifyAccessToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func verifyRefreshToken(tokenString string) (*jwt.RegisteredClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return refreshKey, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		var tokenString string
		if authHeader != "" {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				fmt.Println("AuthMiddleware: Invalid authorization format")
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}
		} else {
			cookie, err := r.Cookie("access_token")
			if err != nil || cookie.Value == "" {
				fmt.Println("AuthMiddleware: Authorization cookie missing or empty")
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}
			tokenString = cookie.Value
		}

		claims, err := verifyAccessToken(tokenString)
		if err != nil {
			fmt.Printf("AuthMiddleware: Token verification failed: %v\n", err)
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		var expiresAt time.Time
		err = db.QueryRow("SELECT expires_at FROM access_tokens WHERE jti = ?", claims.ID).Scan(&expiresAt)
		if err != nil {
			// Token might be revoked or DB error
			http.Error(w, "Invalid or revoked token", http.StatusUnauthorized)
			return
		}
		if time.Now().After(expiresAt) {
			fmt.Printf("AuthMiddleware: Token expired in DB. Now: %v, ExpiresAt: %v\n", time.Now(), expiresAt)
			db.Exec("DELETE FROM access_tokens WHERE jti = ?", claims.ID)
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password_hash"`
}

func login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	var creds Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	key := rateLimitKey(creds.Username, r)
	if isBlocked(key) {
		http.Error(w, "Too many failed attempts. Try again later.", http.StatusTooManyRequests)
		return
	}
	fmt.Printf("Login attempt - Username: %s, Password length: %d\n", creds.Username, len(creds.Password))

	var query string
	if creds.Username == "" {
		http.Error(w, "Username is required", http.StatusBadRequest)
		return
	}
	query = "SELECT password_hash FROM users WHERE username = ?"

	var storedHashedPassword string
	err = db.QueryRow(query, creds.Username).Scan(&storedHashedPassword)
	if err != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		recordFailure(key)
		return
	}
	if !CheckPassword(storedHashedPassword, creds.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		recordFailure(key)
		return
	}

	resetAttempts(key)

	accessToken, accessJTI, err := generateAccessToken(creds.Username)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(creds.Username)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	refreshHash := hashToken(refreshToken)

	_, _ = db.Exec("DELETE FROM refresh_tokens WHERE username = ?", creds.Username)
	_, err = db.Exec("INSERT INTO refresh_tokens (username, token_hash, expires_at) VALUES (?, ?, ?)",
		creds.Username, refreshHash, time.Now().Add(refreshTokenTTL))
	if err != nil {
		fmt.Printf("Error storing refresh token: %v\n", err)
	}

	_, _ = db.Exec("DELETE FROM access_tokens WHERE username = ?", creds.Username)
	_, err = db.Exec("INSERT INTO access_tokens (jti, username, expires_at) VALUES (?, ?, ?)",
		accessJTI, creds.Username, time.Now().Add(accessTokenTTL))
	if err != nil {
		fmt.Printf("Error storing access token JTI: %v\n", err)
		http.Error(w, "Login failed: Database error storing token", http.StatusInternalServerError)
		return
	}

	csrfToken, err := generateCSRFToken()
	if err == nil {
		setCSRFCookie(w, csrfToken)
	}
	setAuthCookies(w, accessToken, refreshToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    fmt.Sprint(int(accessTokenTTL.Seconds())),
	})
}

type RegistrationData struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password_hash"`
}

func registration(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}
	var creds RegistrationData
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		fmt.Printf("Registration decode error: %v\n", err)
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}
	if !isStrongPassword(creds.Password) {
		http.Error(w, "Password must be at least 8 characters and include a letter and a number", http.StatusBadRequest)
		return
	}
	fmt.Printf("Registration attempt - Name: %s, Username: %s, Password length: %d\n", creds.Name, creds.Username, len(creds.Password))

	hashedPassword, err := hashPassword(creds.Password)
	if err != nil {
		fmt.Printf("Hash password error: %v\n", err)
		http.Error(w, "Error hashing password", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO users (name, username, password_hash) VALUES (?, ?, ?)", creds.Name, creds.Username, hashedPassword)
	if err != nil {
		fmt.Printf("Database insert error: %v\n", err)
		http.Error(w, "Error registering user", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"success": "User registered successfully",
	})
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func refreshTokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil || cookie.Value == "" {
		http.Error(w, "Refresh token required", http.StatusUnauthorized)
		return
	}
	refreshTokenString := cookie.Value

	// Verify refresh token
	claims, err := verifyRefreshToken(refreshTokenString)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	refreshHash := hashToken(refreshTokenString)

	// Check if refresh token exists in database
	var storedToken string
	var expiresAt time.Time
	err = db.QueryRow("SELECT token_hash, expires_at FROM refresh_tokens WHERE username = ? AND token_hash = ?",
		claims.Subject, refreshHash).Scan(&storedToken, &expiresAt)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Check if token has expired
	if time.Now().After(expiresAt) {
		// Delete expired token
		db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", refreshHash)
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	// Rotate refresh token: delete old, create new
	_, err = db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", refreshHash)
	if err != nil {
		http.Error(w, "Error rotating refresh token", http.StatusInternalServerError)
		return
	}
	newRefreshToken, err := generateRefreshToken(claims.Subject)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}
	newRefreshHash := hashToken(newRefreshToken)
	_, err = db.Exec("INSERT INTO refresh_tokens (username, token_hash, expires_at) VALUES (?, ?, ?)",
		claims.Subject, newRefreshHash, time.Now().Add(refreshTokenTTL))
	if err != nil {
		http.Error(w, "Error storing refresh token", http.StatusInternalServerError)
		return
	}

	// Revoke prior access tokens and issue new access token
	_, _ = db.Exec("DELETE FROM access_tokens WHERE username = ?", claims.Subject)
	newAccessToken, newJTI, err := generateAccessToken(claims.Subject)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}
	_, err = db.Exec("INSERT INTO access_tokens (jti, username, expires_at) VALUES (?, ?, ?)",
		newJTI, claims.Subject, time.Now().Add(accessTokenTTL))
	if err != nil {
		fmt.Printf("Error storing new access token JTI: %v\n", err)
	}

	csrfToken, err := generateCSRFToken()
	if err == nil {
		setCSRFCookie(w, csrfToken)
	}
	setAuthCookies(w, newAccessToken, newRefreshToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken, // Still returning it, though client won't strictly need it if strictly cookie-based
		"token_type":    "Bearer",
		"expires_in":    fmt.Sprint(int(accessTokenTTL.Seconds())),
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	cookie, err := r.Cookie("refresh_token")
	if err != nil {
		// If no cookie, just clear any that might exist and return success (idempotent-ish)
		clearAuthCookies(w)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"success": "Logged out successfully",
		})
		return
	}
	refreshTokenString := cookie.Value

	claims, err := verifyRefreshToken(refreshTokenString)
	if err != nil {
		clearAuthCookies(w)
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	refreshHash := hashToken(refreshTokenString)

	// Delete refresh token from database
	_, err = db.Exec("DELETE FROM refresh_tokens WHERE token_hash = ?", refreshHash)
	if err != nil {
		fmt.Printf("Error deleting refresh token: %v\n", err)
	}

	// Revoke all access tokens for this user to avoid stolen token reuse
	_, err = db.Exec("DELETE FROM access_tokens WHERE username = ?", claims.Subject)
	if err != nil {
		fmt.Printf("Error deleting access tokens: %v\n", err)
	}

	clearAuthCookies(w)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"success": "Logged out successfully",
	})
}

func main() {
	// Load environment variables
	err := godotenv.Load()
	if err != nil {
		fmt.Println("Warning: .env file not found, using system environment variables")
	}
	secureCookies = strings.ToLower(os.Getenv("COOKIE_SECURE")) == "true"
	if secureCookies {
		fmt.Println("COOKIE_SECURE=true: cookies require HTTPS and SameSite=Strict")
	}

	// Set JWT keys from environment variables
	jwtSecret := os.Getenv("JWT_SECRET_KEY")
	if jwtSecret == "" {
		fmt.Println("Error: JWT_SECRET_KEY environment variable not set")
		return
	}
	jwtKey = []byte(jwtSecret)

	refreshSecret := os.Getenv("JWT_REFRESH_SECRET_KEY")
	if refreshSecret == "" {
		fmt.Println("Error: JWT_REFRESH_SECRET_KEY environment variable not set")
		return
	}
	refreshKey = []byte(refreshSecret)

	// Get database connection string from environment
	dbConnectionString := os.Getenv("DB_CONNECTION_STRING")
	if dbConnectionString == "" {
		dbConnectionString = "root:29112003@tcp(localhost:3306)/auth"
		fmt.Println("Warning: Using default database connection string")
	}

	// Ensure parseTime=true is set so that MySQL DATE/DATETIME columns scan into time.Time correctly
	if !strings.Contains(dbConnectionString, "parseTime=true") {
		separator := "?"
		if strings.Contains(dbConnectionString, "?") {
			separator = "&"
		}
		dbConnectionString += separator + "parseTime=true"
	}

	db, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		fmt.Println("Database connection error: ", err)
		return
	}
	defer db.Close()

	if err := initSchema(db); err != nil {
		fmt.Printf("Error initializing database schema: %v\n", err)
		return
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)

	// Serve static assets (no CSRF for static files)
	workDir, _ := os.Getwd()
	assetDir := http.Dir(filepath.Join(workDir, "../asset"))
	r.Get("/asset/*", func(w http.ResponseWriter, r *http.Request) {
		http.StripPrefix("/asset/", http.FileServer(assetDir)).ServeHTTP(w, r)
	})

	// API routes with CSRF protection
	r.Group(func(r chi.Router) {
		r.Use(csrfMiddleware)
		r.Route("/auth", func(r chi.Router) {
			r.Post("/", login)
			r.Post("/register", registration)
			r.Post("/refresh", refreshTokenHandler)
			r.Post("/logout", logout)
		})
		r.With(AuthMiddleware).Get("/dashboard", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Dashboard"))
		})
	})

	// Serve frontend HTML files (no CSRF for static content)
	frontendDir := http.Dir(filepath.Join(workDir, "../frontend"))
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		// Disable caching for development so browser always gets fresh HTML/JS
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
		http.FileServer(frontendDir).ServeHTTP(w, r)
	})

	fmt.Println("Server start on 8080 port")
	err = http.ListenAndServe(":8080", r)
	if err != nil {
		fmt.Println("Server error: ", err)
	}
}
