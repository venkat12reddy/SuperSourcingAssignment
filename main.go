package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const (
	DBHost     = "localhost"
	DBPort     = "5432"
	DBUser     = "" //db user
	DBPassword = "" //db password
	DBName     = "" // dab name
	ServerPort = ":8080"
	JWTSecret  = "" // Replace with a secure key in production
)

var db *gorm.DB

type User struct {
	gorm.Model
	Email    string `json:"email" gorm:"unique"`
	Password string `json:"-"`
}

type TokenDetails struct {
	AccessToken  string
	RefreshToken string
	AccessUUID   string
	RefreshUUID  string
	AccessExpiry int64
	RefreshExpiry int64
}

func initDB() {
	var err error
	dsn := "host=" + DBHost + " port=" + DBPort + " user=" + DBUser + " password=" + DBPassword + " dbname=" + DBName + " sslmode=disable"
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Fatal("Failed to perform migrations:", err)
	}

	log.Println("Successfully connected to the database and migrated!")
}
func signUp(w http.ResponseWriter, r *http.Request) {
	var user User
	if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to encrypt password", http.StatusInternalServerError)
		return
	}

	user.Password = string(hashedPassword)
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User created successfully"})
}
func signIn(w http.ResponseWriter, r *http.Request) {
	var credentials User
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("email = ?", credentials.Email).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password)); err != nil {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	tokenDetails, err := createToken(user.ID)
	if err != nil {
		http.Error(w, "Failed to create token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokenDetails)
}
func tokenAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			http.Error(w, "Missing token", http.StatusUnauthorized)
			return
		}

		claims := &jwt.StandardClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return []byte(JWTSecret), nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims.ExpiresAt < time.Now().Unix() {
			http.Error(w, "Token expired", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
func revokeToken(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// In a real-world application, you would invalidate the token by storing its UUID
	// in a blacklist or deleting it from a database.
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Token revoked successfully"})
}
func refreshToken(w http.ResponseWriter, r *http.Request) {
	var tokenDetails TokenDetails
	if err := json.NewDecoder(r.Body).Decode(&tokenDetails); err != nil {
		http.Error(w, "Invalid input", http.StatusBadRequest)
		return
	}

	// Validate refresh token (logic omitted for brevity)
	newTokenDetails, err := createToken(1) // Replace with actual user ID
	if err != nil {
		http.Error(w, "Failed to create new token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(newTokenDetails)
}
func createToken(userID uint) (*TokenDetails, error) {
	td := &TokenDetails{}
	td.AccessExpiry = time.Now().Add(time.Minute * 15).Unix()
	td.RefreshExpiry = time.Now().Add(time.Hour * 24 * 7).Unix()

	var err error
	// Create Access Token
	claims := &jwt.StandardClaims{
		ExpiresAt: td.AccessExpiry,
		Subject:   string(userID),
	}
	accessToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	td.AccessToken, err = accessToken.SignedString([]byte(JWTSecret))
	if err != nil {
		return nil, err
	}

	// Create Refresh Token
	claims.ExpiresAt = td.RefreshExpiry
	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	td.RefreshToken, err = refreshToken.SignedString([]byte(JWTSecret))
	if err != nil {
		return nil, err
	}

	return td, nil
}
func main() {
	// Initialize the database
	initDB()

	// Create a new Gorilla Mux router
	r := mux.NewRouter()

	// Public routes (no token required)
	r.HandleFunc("/signup", signUp).Methods("POST")
	r.HandleFunc("/signin", signIn).Methods("POST")

	// Protected routes (token required)
	protected := r.PathPrefix("/auth").Subrouter()
	protected.Use(tokenAuthMiddleware)
	protected.HandleFunc("/revoke-token", revokeToken).Methods("POST")
	protected.HandleFunc("/refresh-token", refreshToken).Methods("POST")

	// Start the server
	log.Printf("Server is running on port %s", ServerPort)
	log.Fatal(http.ListenAndServe(ServerPort, r))
}
