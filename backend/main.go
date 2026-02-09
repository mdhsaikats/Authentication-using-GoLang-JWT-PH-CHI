package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
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

func getKeyFromEnv() string {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	log.Println(jwtSecret)
	return jwtSecret
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

func generateAccessToken(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "auth-service",
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

func generateRefreshToken(username string) (string, error) {
	claims := &jwt.RegisteredClaims{
		Subject:   username,
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(7 * 24 * time.Hour)),
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
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Expected format: "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		_, err := verifyAccessToken(tokenString)
		if err != nil {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
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
		return
	}
	if !CheckPassword(storedHashedPassword, creds.Password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	accessToken, err := generateAccessToken(creds.Username)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(creds.Username)
	if err != nil {
		http.Error(w, "Error generating refresh token", http.StatusInternalServerError)
		return
	}

	// Store refresh token in database
	_, err = db.Exec("INSERT INTO refresh_tokens (username, token, expires_at) VALUES (?, ?, ?)",
		creds.Username, refreshToken, time.Now().Add(7*24*time.Hour))
	if err != nil {
		fmt.Printf("Error storing refresh token: %v\n", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    "900", // 15 minutes in seconds
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

	// Check if refresh token exists in database
	var storedToken string
	var expiresAt time.Time
	err = db.QueryRow("SELECT token, expires_at FROM refresh_tokens WHERE username = ? AND token = ?",
		claims.Subject, req.RefreshToken).Scan(&storedToken, &expiresAt)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	// Check if token has expired
	if time.Now().After(expiresAt) {
		// Delete expired token
		db.Exec("DELETE FROM refresh_tokens WHERE token = ?", req.RefreshToken)
		http.Error(w, "Refresh token expired", http.StatusUnauthorized)
		return
	}

	// Generate new access token
	newAccessToken, err := generateAccessToken(claims.Subject)
	if err != nil {
		http.Error(w, "Error generating access token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"access_token": newAccessToken,
		"token_type":   "Bearer",
		"expires_in":   "900",
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

	// Delete refresh token from database
	_, err = db.Exec("DELETE FROM refresh_tokens WHERE token = ?", req.RefreshToken)
	if err != nil {
		fmt.Printf("Error deleting refresh token: %v\n", err)
	}

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
