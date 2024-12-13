package main

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var (
	requestTimeout = 300 * time.Second // 5 minutes timeout
)

const (
	adminSecretKey  = "admin"  // In production, this should come from environment variables
	serverSecretKey = "server" // In production, this should come from environment variables
)

// Request represents a key request
type Request struct {
	ServerID  string
	Approved  bool
	CreatedAt time.Time
	IP        string // Added IP field to store the requester's IP address
}

var (
	mu              sync.Mutex
	pendingRequests = make(map[string]*Request)
)

// isRequestExpired checks if a request has expired
func isRequestExpired(req *Request) bool {
	return time.Since(req.CreatedAt) > requestTimeout
}

// cleanupExpiredRequests removes expired requests
func cleanupExpiredRequests() {
	mu.Lock()
	defer mu.Unlock()

	for id, req := range pendingRequests {
		if isRequestExpired(req) {
			delete(pendingRequests, id)
		}
	}
}

// requireSecretKey middleware validates the secret key in the Authorization header
func requireAdminSecretKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}

		// Use constant time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte("Bearer "+adminSecretKey)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization key"})
			c.Abort()
			return
		}

		c.Next()
	}
}

// requireSecretKey middleware validates the secret key in the Authorization header
func requireServerSecretKey() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}
		// Use constant time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare([]byte(authHeader), []byte("Bearer "+serverSecretKey)) != 1 {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization key"})
			c.Abort()
			return
		}
		c.Next()
	}
}

func setupRouter() *gin.Engine {
	router := gin.New()

	router.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		// your custom format
		return fmt.Sprintf("%s - [%s] \"%s %s %s %d %s \"%s\" %s\"\n",
			param.ClientIP,
			param.TimeStamp.Format(time.RFC1123),
			param.Method,
			param.Path,
			param.Request.Proto,
			param.StatusCode,
			param.Latency,
			param.Request.UserAgent(),
			param.ErrorMessage,
		)
	}))

	router.Use(gin.Recovery())

	// Start cleanup goroutine
	go func() {
		for {
			time.Sleep(60 * time.Second) // Run cleanup every minute
			cleanupExpiredRequests()
		}
	}()

	// Protected endpoints require secret key
	adminProtected := router.Group("/admin/", requireAdminSecretKey())
	serverProtected := router.Group("/server/", requireServerSecretKey())

	router.GET("/pingz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})

	// Endpoint to receive key requests
	serverProtected.POST("/request-key", func(c *gin.Context) {
		var json struct {
			ServerID string `json:"server_id"`
		}
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Generate a secure random UUID for the request
		reqID := uuid.New().String()

		mu.Lock()
		pendingRequests[reqID] = &Request{
			ServerID:  json.ServerID,
			Approved:  false,
			CreatedAt: time.Now(),
			IP:        c.ClientIP(), // Store the client's IP address
		}
		mu.Unlock()

		// Simulate sending a notification
		c.JSON(http.StatusAccepted, gin.H{
			"message":    "Request received. Awaiting approval. Request will expire in 5 minutes.",
			"request_id": reqID,
		})
	})

	// Endpoint to approve a request (protected)
	adminProtected.GET("/approve/:req_id", func(c *gin.Context) {
		reqID := c.Param("req_id")

		// Validate UUID format
		if _, err := uuid.Parse(reqID); err != nil {
			c.String(http.StatusBadRequest, "Invalid request ID format")
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if req, exists := pendingRequests[reqID]; exists {
			if isRequestExpired(req) {
				delete(pendingRequests, reqID)
				c.String(http.StatusGone, "Request %s has expired.", reqID)
				return
			}
			req.Approved = true
			c.String(http.StatusOK, "Request %s approved.", reqID)
		} else {
			c.String(http.StatusNotFound, "Request not found.")
		}
	})

	// Endpoint to deny a request (protected)
	adminProtected.GET("/deny/:req_id", func(c *gin.Context) {
		reqID := c.Param("req_id")

		// Validate UUID format
		if _, err := uuid.Parse(reqID); err != nil {
			c.String(http.StatusBadRequest, "Invalid request ID format")
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if req, exists := pendingRequests[reqID]; exists {
			if isRequestExpired(req) {
				delete(pendingRequests, reqID)
				c.String(http.StatusGone, "Request %s has expired.", reqID)
				return
			}
			delete(pendingRequests, reqID)
			c.String(http.StatusOK, "Request %s denied and removed.", reqID)
		} else {
			c.String(http.StatusNotFound, "Request not found.")
		}
	})

	// Endpoint to get the decryption key
	serverProtected.POST("/get-key", func(c *gin.Context) {
		var json struct {
			ReqID string `json:"req_id"`
		}
		if err := c.ShouldBindJSON(&json); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		// Validate UUID format
		if _, err := uuid.Parse(json.ReqID); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request ID format"})
			return
		}

		mu.Lock()
		defer mu.Unlock()

		if req, exists := pendingRequests[json.ReqID]; exists {
			if isRequestExpired(req) {
				delete(pendingRequests, json.ReqID)
				c.JSON(http.StatusGone, gin.H{"error": "Request has expired"})
				return
			}
			if req.Approved {
				c.JSON(http.StatusOK, gin.H{"key": "your-decryption-key"})
			} else {
				c.JSON(http.StatusForbidden, gin.H{"error": "Request not approved yet"})
			}
		} else {
			c.JSON(http.StatusNotFound, gin.H{"error": "Request not found"})
		}
	})

	return router
}

func main() {
	router := setupRouter()
	router.Run(":8080") // Start server on port 8080
}
