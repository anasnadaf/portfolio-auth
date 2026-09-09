package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/mail"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var (
	db        *sql.DB
	jwtSecret []byte
	pepper []byte
	// Registration is closed unless explicitly opened. These are personal
	// deployments fronting metered LLM APIs, so an open signup endpoint is a
	// standing invitation to burn someone else's quota. Set
	// ALLOW_REGISTRATION=true to create an account, then turn it back off.
	allowRegistration bool
)

// pepperPassword applies an HMAC-SHA256 with the application pepper to the
// raw password. The result is a fixed-length hex string that is then fed
// into bcrypt. This means the pepper must be present to verify any hash —
// a database leak alone is not enough to brute-force passwords.
func pepperPassword(password string) string {
	h := hmac.New(sha256.New, pepper)
	h.Write([]byte(password))
	return hex.EncodeToString(h.Sum(nil))
}

type credentials struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func issueToken(email string) (string, error) {
	claims := jwt.MapClaims{
		"sub": email,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(24 * time.Hour).Unix(),
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(jwtSecret)
}

func parseCredentials(r *http.Request) (credentials, error) {
	var c credentials
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		return c, errors.New("invalid json body")
	}
	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	if _, err := mail.ParseAddress(c.Email); err != nil {
		return c, errors.New("invalid email")
	}
	if len(c.Password) < 8 {
		return c, errors.New("password must be at least 8 characters")
	}
	return c, nil
}

func register(w http.ResponseWriter, r *http.Request) {
	if !allowRegistration {
		writeError(w, http.StatusForbidden, "registration is closed")
		return
	}
	c, err := parseCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(pepperPassword(c.Password)), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hashing failed")
		return
	}
	_, err = db.Exec(
		"INSERT INTO users (email, password_hash) VALUES ($1, $2)",
		c.Email, string(hash),
	)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate key") {
			writeError(w, http.StatusConflict, "email already registered")
			return
		}
		log.Printf("register insert: %v", err)
		writeError(w, http.StatusInternalServerError, "registration failed")
		return
	}
	token, err := issueToken(c.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"token": token, "email": c.Email})
}

func login(w http.ResponseWriter, r *http.Request) {
	c, err := parseCredentials(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var hash string
	err = db.QueryRow(
		"SELECT password_hash FROM users WHERE email = $1", c.Email,
	).Scan(&hash)
	if err == sql.ErrNoRows ||
		(err == nil && bcrypt.CompareHashAndPassword([]byte(hash), []byte(pepperPassword(c.Password))) != nil) {
		writeError(w, http.StatusUnauthorized, "invalid email or password")
		return
	}
	if err != nil {
		log.Printf("login query: %v", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	token, err := issueToken(c.Email)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "token issue failed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "email": c.Email})
}

func me(w http.ResponseWriter, r *http.Request) {
	header := r.Header.Get("Authorization")
	if !strings.HasPrefix(header, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	token, err := jwt.Parse(
		strings.TrimPrefix(header, "Bearer "),
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return jwtSecret, nil
		},
	)
	if err != nil || !token.Valid {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	sub, err := token.Claims.GetSubject()
	if err != nil {
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": sub})
}

func health(w http.ResponseWriter, r *http.Request) {
	if err := db.Ping(); err != nil {
		writeError(w, http.StatusServiceUnavailable, "db unreachable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		log.Fatal("DATABASE_URL is required")
	}
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Fatal("JWT_SECRET is required")
	}
	jwtSecret = []byte(secret)
	allowRegistration = strings.EqualFold(os.Getenv("ALLOW_REGISTRATION"), "true")

	pepperStr := os.Getenv("PEPPER_SECRET")
	if pepperStr == "" {
		log.Fatal("PEPPER_SECRET is required")
	}
	pepper = []byte(pepperStr)

	var err error
	db, err = sql.Open("postgres", dsn)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	for i := 0; i < 30; i++ {
		if err = db.Ping(); err == nil {
			break
		}
		log.Printf("waiting for db: %v", err)
		time.Sleep(2 * time.Second)
	}
	if err != nil {
		log.Fatalf("db unreachable: %v", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		created_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	if err != nil {
		log.Fatalf("migrate: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /auth/register", register)
	mux.HandleFunc("POST /auth/login", login)
	mux.HandleFunc("GET /auth/me", me)
	mux.HandleFunc("GET /auth/health", health)

	addr := ":8081"
	log.Printf("auth service listening on %s (registration open: %t)", addr, allowRegistration)
	log.Fatal(http.ListenAndServe(addr, withCORS(mux)))
}
