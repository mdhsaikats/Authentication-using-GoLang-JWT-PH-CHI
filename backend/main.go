package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

func isStrongPassword(pw string) bool {
	if len(pw) < 8 {
		return false
	}
	hasLetter := false
	hasDigit := false
	for _, c := range pw {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		}
		if c >= '0' && c <= '9' {
			hasDigit = true
		}
	}
	return hasLetter && hasDigit
}

func isBlocked(username string) bool {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	until, ok := loginAttempts.blockedUntil[username]
	if !ok {
		return false
	}
	if time.Now().Before(until) {
		return true
	}
	delete(loginAttempts.blockedUntil, username)
	loginAttempts.counts[username] = 0
	return false
}

func recordFailure(username string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.counts[username]++
	if loginAttempts.counts[username] >= 5 {
		loginAttempts.blockedUntil[username] = time.Now().Add(10 * time.Minute)
		loginAttempts.counts[username] = 0
	}
}

func resetAttempts(username string) {
	loginAttempts.Lock()
	defer loginAttempts.Unlock()
	loginAttempts.counts[username] = 0
	delete(loginAttempts.blockedUntil, username)
}

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "access_token",
		Value:    accessToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(accessTokenTTL.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/auth",
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(refreshTokenTTL.Seconds()),
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	expired := time.Unix(0, 0)
	http.SetCookie(w, &http.Cookie{Name: "access_token", Value: "", Path: "/", Expires: expired, MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: "refresh_token", Value: "", Path: "/auth", Expires: expired, MaxAge: -1})
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5500")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
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
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}
		} else {
			cookie, err := r.Cookie("access_token")
			if err != nil || cookie.Value == "" {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}
			tokenString = cookie.Value
		}

		claims, err := verifyAccessToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		var expiresAt time.Time
		err = db.QueryRow("SELECT expires_at FROM access_tokens WHERE jti = ?", claims.ID).Scan(&expiresAt)
		if err != nil {
			http.Error(w, "Invalid or revoked token", http.StatusUnauthorized)
			return
		}
		if time.Now().After(expiresAt) {
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
	if isBlocked(creds.Username) {
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
		recordFailure(creds.Username)
		return
	}
	if !CheckPassword(storedHashedPassword, creds.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		recordFailure(creds.Username)
		return
	}

	resetAttempts(creds.Username)

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

	var req RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	// Verify refresh token
	claims, err := verifyRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid or expired refresh token", http.StatusUnauthorized)
		return
	}

	refreshHash := hashToken(req.RefreshToken)

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

	setAuthCookies(w, newAccessToken, newRefreshToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  newAccessToken,
		"refresh_token": newRefreshToken,
		"token_type":    "Bearer",
		"expires_in":    fmt.Sprint(int(accessTokenTTL.Seconds())),
	})
}

func logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid Method", http.StatusMethodNotAllowed)
		return
	}

	var req RefreshRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request payload", http.StatusBadRequest)
		return
	}

	claims, err := verifyRefreshToken(req.RefreshToken)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	refreshHash := hashToken(req.RefreshToken)

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

	db, err = sql.Open("mysql", dbConnectionString)
	if err != nil {
		fmt.Println("Database connection error: ", err)
		return
	}
	defer db.Close()

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(corsMiddleware)
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

	fmt.Println("Server start on 8080 port")
	err = http.ListenAndServe(":8080", r)
	if err != nil {
		fmt.Println("Server error: ", err)
	}
}
