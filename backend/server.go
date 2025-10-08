package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
	"os"
	"github.com/joho/godotenv"

	// Local
	"secureVault/functions"
)

// RateLimiter represents a token bucket rate limiter
type RateLimiter struct {
    tokens    float64
    capacity  float64
    refillRate float64
    lastRefill time.Time
    mutex     sync.Mutex
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate float64) *RateLimiter {
    return &RateLimiter{
        tokens:     rate,
        capacity:   rate,
        refillRate: rate,
        lastRefill: time.Now(),
    }
}

// Allow checks if a request is allowed
func (rl *RateLimiter) Allow() bool {
    rl.mutex.Lock()
    defer rl.mutex.Unlock()
    
    now := time.Now()
    elapsed := now.Sub(rl.lastRefill).Seconds()
    
    // Refill tokens
    rl.tokens = min(rl.capacity, rl.tokens+(elapsed*rl.refillRate))
    rl.lastRefill = now
    
    if rl.tokens >= 1.0 {
        rl.tokens -= 1.0
        return true
    }
    
    return false
}

// RateLimitConfig holds rate limiting configuration
type RateLimitConfig struct {
    DefaultRate float64            // calls per second
    IPRates     map[string]float64 // per-IP custom rates
    mutex       sync.RWMutex
}

// RateLimitManager manages rate limiters for all IP addresses
type RateLimitManager struct {
    limiters map[string]*RateLimiter
    config   *RateLimitConfig
    mutex    sync.RWMutex
    cleanup  *time.Ticker
}

// NewRateLimitManager creates a new rate limit manager
func NewRateLimitManager(defaultRate float64) *RateLimitManager {
    manager := &RateLimitManager{
        limiters: make(map[string]*RateLimiter),
        config: &RateLimitConfig{
            DefaultRate: defaultRate,
            IPRates:     make(map[string]float64),
        },
    }
    
    // Start cleanup goroutine to remove inactive limiters
    manager.cleanup = time.NewTicker(5 * time.Minute)
    go manager.cleanupRoutine()
    
    return manager
}

// SetIPRate sets a custom rate limit for a specific IP address
func (rm *RateLimitManager) SetIPRate(ipAddress string, rate float64) {
    rm.config.mutex.Lock()
    rm.config.IPRates[ipAddress] = rate
    rm.config.mutex.Unlock()
    
    // Update existing limiter if it exists
    rm.mutex.Lock()
    if limiter, exists := rm.limiters[ipAddress]; exists {
        limiter.mutex.Lock()
        limiter.capacity = rate
        limiter.refillRate = rate
        limiter.tokens = min(limiter.tokens, rate)
        limiter.mutex.Unlock()
    }
    rm.mutex.Unlock()
}

// GetLimiter gets or creates a rate limiter for an IP address
func (rm *RateLimitManager) GetLimiter(ipAddress string) *RateLimiter {
    rm.mutex.Lock()
    defer rm.mutex.Unlock()
    
    if limiter, exists := rm.limiters[ipAddress]; exists {
        return limiter
    }
    
    // Get IP-specific rate or default
    rm.config.mutex.RLock()
    rate, exists := rm.config.IPRates[ipAddress]
    if !exists {
        rate = rm.config.DefaultRate
    }
    rm.config.mutex.RUnlock()
    
    limiter := NewRateLimiter(rate)
    rm.limiters[ipAddress] = limiter
    return limiter
}

// cleanupRoutine removes inactive rate limiters
func (rm *RateLimitManager) cleanupRoutine() {
    for range rm.cleanup.C {
        rm.mutex.Lock()
        cutoff := time.Now().Add(-10 * time.Minute)
        
        for ipAddress, limiter := range rm.limiters {
            limiter.mutex.Lock()
            if limiter.lastRefill.Before(cutoff) {
                delete(rm.limiters, ipAddress)
            }
            limiter.mutex.Unlock()
        }
        rm.mutex.Unlock()
    }
}

// Global rate limit manager
var rateLimitManager = NewRateLimitManager(5.0) // 2 calls per second default

// getClientIP extracts the client IP address with proper proxy handling
func getClientIP(r *http.Request) string {
    // Check CF-Connecting-IP header (Cloudflare)
    if cfIP := r.Header.Get("CF-Connecting-IP"); cfIP != "" {
        return cfIP
    }
    
    // Check X-Forwarded-For header (most common proxy header)
    if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
        ips := strings.Split(xff, ",")
        if len(ips) > 0 {
            // Get the first (original client) IP
            ip := strings.TrimSpace(ips[0])
            if ip != "" {
                return ip
            }
        }
    }
    
    // Check X-Real-IP header (nginx and others)
    if xri := r.Header.Get("X-Real-IP"); xri != "" {
        return xri
    }
    
    // Check X-Client-IP header
    if xci := r.Header.Get("X-Client-IP"); xci != "" {
        return xci
    }
    
    // Check X-Forwarded header
    if xf := r.Header.Get("X-Forwarded"); xf != "" {
        return xf
    }
    
    // Use RemoteAddr as fallback
    ip := r.RemoteAddr
    if strings.Contains(ip, ":") {
        ip = strings.Split(ip, ":")[0]
    }
    return ip
}

// withRateLimit applies rate limiting middleware based on IP address
func withRateLimit(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        clientIP := getClientIP(r)
        limiter := rateLimitManager.GetLimiter(clientIP)
        
        if !limiter.Allow() {
            w.Header().Set("Content-Type", "application/json")
            w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.1f", limiter.capacity))
            w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%.1f", limiter.tokens))
            w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))
            w.Header().Set("Retry-After", "1")
            w.WriteHeader(http.StatusTooManyRequests)
            json.NewEncoder(w).Encode(map[string]interface{}{
                "error":     "Rate limit exceeded",
                "message":   fmt.Sprintf("Maximum %.1f requests per second allowed for your IP", limiter.capacity),
                "clientIP":  clientIP,
                "retryAfter": 1,
            })
            return
        }
        
        // Add rate limit headers to successful responses
        w.Header().Set("X-RateLimit-Limit", fmt.Sprintf("%.1f", limiter.capacity))
        w.Header().Set("X-RateLimit-Remaining", fmt.Sprintf("%.1f", limiter.tokens))
        w.Header().Set("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Second).Unix()))
        
        h.ServeHTTP(w, r)
    })
}

func withCORS(h http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Access-Control-Allow-Origin", "*") // Allow all origins
        w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

        // ### THIS IS THE FIX ###
        // Add "Authorization" to the list of exposed headers
        w.Header().Set("Access-Control-Expose-Headers", "Authorization, X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset, Retry-After")
        
        if r.Method == http.MethodOptions {
            w.WriteHeader(http.StatusOK)
            return
        }
        h.ServeHTTP(w, r)
    })
}

// Admin endpoint to configure rate limits for specific IP addresses
func configureIPRateLimit(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodPost {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    var config struct {
        IPAddress string  `json:"ipAddress"`
        Rate      float64 `json:"rate"`
    }
    
    if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }
    
    if config.IPAddress == "" || config.Rate <= 0 {
        http.Error(w, "Invalid ipAddress or rate", http.StatusBadRequest)
        return
    }
    
    rateLimitManager.SetIPRate(config.IPAddress, config.Rate)
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "message": fmt.Sprintf("Rate limit set to %.1f requests/second for IP %s", config.Rate, config.IPAddress),
    })
}

// Admin endpoint to get current rate limit status
func getRateLimitStatus(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    clientIP := getClientIP(r)
    limiter := rateLimitManager.GetLimiter(clientIP)
    
    limiter.mutex.Lock()
    currentTokens := limiter.tokens
    capacity := limiter.capacity
    refillRate := limiter.refillRate
    limiter.mutex.Unlock()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "clientIP":       clientIP,
        "currentTokens":  fmt.Sprintf("%.2f", currentTokens),
        "capacity":       fmt.Sprintf("%.1f", capacity),
        "refillRate":     fmt.Sprintf("%.1f", refillRate),
        "maxRequests":    fmt.Sprintf("%.1f requests per second", refillRate),
    })
}

// Admin endpoint to list all active rate limiters
func listActiveIPs(w http.ResponseWriter, r *http.Request) {
    if r.Method != http.MethodGet {
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
        return
    }
    
    rateLimitManager.mutex.RLock()
    activeIPs := make([]map[string]interface{}, 0, len(rateLimitManager.limiters))
    
    for ip, limiter := range rateLimitManager.limiters {
        limiter.mutex.Lock()
        activeIPs = append(activeIPs, map[string]interface{}{
            "ipAddress":    ip,
            "tokens":       fmt.Sprintf("%.2f", limiter.tokens),
            "capacity":     fmt.Sprintf("%.1f", limiter.capacity),
            "lastRefill":   limiter.lastRefill.Format(time.RFC3339),
        })
        limiter.mutex.Unlock()
    }
    rateLimitManager.mutex.RUnlock()
    
    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "activeIPs": activeIPs,
        "count":     len(activeIPs),
    })
}

// Helper function for min (Go 1.20 and earlier)
func min(a, b float64) float64 {
    if a < b {
        return a
    }
    return b
}

func main() {
        if err := godotenv.Load(); err != nil {
        fmt.Println("Warning: Could not load .env file: %v", err)
    }

    // Apply both CORS and rate limiting to file server
    // http.Handle("/", withCORS(withRateLimit(http.FileServer(http.Dir("./static")))))
    
    // Apply both middlewares to all API endpoints
    http.Handle("/getFile", withCORS(withRateLimit(http.HandlerFunc(functions.GetFile))))
    http.Handle("/uploadFile", withCORS(withRateLimit(http.HandlerFunc(functions.UploadFile))))
    http.Handle("/deleteFile", withCORS(withRateLimit(http.HandlerFunc(functions.DeleteFile))))
    http.Handle("/getFileList", withCORS(withRateLimit(http.HandlerFunc(functions.GetFileList))))
    http.Handle("/createAccount", withCORS(withRateLimit(http.HandlerFunc(functions.CreateAccount))))
    http.Handle("/deleteAccount", withCORS(withRateLimit(http.HandlerFunc(functions.DeleteAccount))))
    http.Handle("/login", withCORS(withRateLimit(http.HandlerFunc(functions.Login))))
    http.Handle("/changeAccess", withCORS(withRateLimit(http.HandlerFunc(functions.ChangeAccess))))
    http.Handle("/getPublicKey", withCORS(withRateLimit(http.HandlerFunc(functions.GetPublicKey))))
    http.Handle("/getUserInfo", withCORS(withRateLimit(http.HandlerFunc(functions.GetUserInfo))))

    
    // Admin endpoints for managing rate limits
    http.Handle("/admin/configure-ip-rate-limit", withCORS(http.HandlerFunc(configureIPRateLimit)))
    http.Handle("/admin/rate-limit-status", withCORS(http.HandlerFunc(getRateLimitStatus)))
    http.Handle("/admin/active-ips", withCORS(http.HandlerFunc(listActiveIPs)))

    fmt.Println("Server Started on :3000...")
    port := os.Getenv("PORT")
    if port == "" {
        port = "3000"
    }
    http.ListenAndServe(":"+port, nil)

}