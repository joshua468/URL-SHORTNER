package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gorilla/mux"
)

// Shortener struct holds the mapping between short and original URLs
type Shortener struct {
	urls      map[string]string // Mapping of short URLs to original URLs
	visits    map[string]int    // Tracking visits to short URLs
	mutex     sync.RWMutex      // Mutex for thread-safe access to maps
	db        *Database         // Database for persisting mappings
	analytics *Analytics        // Analytics tracker
	limiter   *RateLimiter      // Rate limiter to limit the number of requests per second
}

// Database struct represents a simple in-memory database
type Database struct {
	data map[string]string
	sync.RWMutex
}

// NewDatabase creates a new Database instance
func NewDatabase() *Database {
	return &Database{
		data: make(map[string]string),
	}
}

// Analytics struct holds analytics data
type Analytics struct {
	data map[string]int
	sync.Mutex
}

// NewAnalytics creates a new Analytics instance
func NewAnalytics() *Analytics {
	return &Analytics{
		data: make(map[string]int),
	}
}

// RateLimiter struct represents a rate limiter
type RateLimiter struct {
	mu            sync.Mutex
	requests      map[string]int
	lastResetTime time.Time
	maxRequests   int
	duration      time.Duration
}

// NewRateLimiter creates a new RateLimiter instance
func NewRateLimiter(maxRequests int, duration time.Duration) *RateLimiter {
	return &RateLimiter{
		requests:      make(map[string]int),
		lastResetTime: time.Now(),
		maxRequests:   maxRequests,
		duration:      duration,
	}
}

// Allow checks if a request is allowed based on rate limit
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Reset the count if the duration has passed since the last reset
	if time.Since(r.lastResetTime) > r.duration {
		r.requests = make(map[string]int)
		r.lastResetTime = time.Now()
	}

	// Increment request count for the key
	r.requests[key]++

	// Check if the request count exceeds the limit
	if r.requests[key] > r.maxRequests {
		return false
	}

	return true
}

// Shorten generates a short URL for a given original URL
func (s *Shortener) Shorten(originalURL string) string {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	// Check if the URL already exists in the database
	for shortURL, storedURL := range s.db.data {
		if storedURL == originalURL {
			return shortURL
		}
	}

	// Generate a unique short URL
	shortURL := generateShortURL()
	s.urls[shortURL] = originalURL

	// Store the mapping in the database
	s.db.Lock()
	s.db.data[shortURL] = originalURL
	s.db.Unlock()

	return shortURL
}

// Resolve retrieves the original URL for a given short URL
func (s *Shortener) Resolve(shortURL string) (string, bool) {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	originalURL, ok := s.urls[shortURL]
	if ok {
		// Increment visit count and log analytics
		s.analytics.Lock()
		s.analytics.data[shortURL]++
		s.analytics.Unlock()
	}

	return originalURL, ok
}

// GetVisits returns the number of visits for a given short URL
func (s *Shortener) GetVisits(shortURL string) int {
	s.analytics.Lock()
	defer s.analytics.Unlock()

	return s.analytics.data[shortURL]
}

// generateShortURL generates a short URL using a cryptographic hash
func generateShortURL() string {
	h := sha256.New()
	h.Write([]byte(strconv.FormatInt(time.Now().UnixNano(), 10)))
	randomBytes := make([]byte, 8)
	rand.Read(randomBytes)
	h.Write(randomBytes)
	return base64.URLEncoding.EncodeToString(h.Sum(nil))[:8]
}

// authenticateMiddleware is a middleware to enforce authentication
func authenticateMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate authentication (e.g., check for API key)
		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "your-api-key" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	shortener := &Shortener{
		urls:      make(map[string]string),
		visits:    make(map[string]int),
		db:        NewDatabase(),
		analytics: NewAnalytics(),
		limiter:   NewRateLimiter(10, time.Second), // Allowing 10 requests per second
	}
	r := mux.NewRouter()

	// Apply middleware for authentication
	r.Use(authenticateMiddleware)

	// Handler for shortening URLs
	r.HandleFunc("/shorten", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Check rate limit
		if !shortener.limiter.Allow(r.RemoteAddr) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		originalURL := r.FormValue("url")
		if originalURL == "" {
			http.Error(w, "URL parameter is required", http.StatusBadRequest)
			return
		}

		shortURL := shortener.Shorten(originalURL)
		response := struct {
			ShortURL string `json:"short_url"`
		}{ShortURL: shortURL}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("POST")

	// Handler for redirecting short URLs to original URLs
	r.HandleFunc("/{shortURL}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortURL := vars["shortURL"]

		originalURL, ok := shortener.Resolve(shortURL)
		if !ok {
			http.NotFound(w, r)
			return
		}

		// Redirect to the original URL
		http.Redirect(w, r, originalURL, http.StatusFound)
	}).Methods("GET")

	// Handler for getting analytics data
	r.HandleFunc("/analytics/{shortURL}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		shortURL := vars["shortURL"]

		visits := shortener.GetVisits(shortURL)
		response := struct {
			ShortURL string `json:"short_url"`
			Visits   int    `json:"visits"`
		}{ShortURL: shortURL, Visits: visits}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}).Methods("GET")

	// Start HTTP server
	fmt.Println("Server listening on port 8080")
	log.Fatal(http.ListenAndServe(":8080", r))
}
