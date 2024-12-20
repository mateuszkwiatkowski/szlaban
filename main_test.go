package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestPingEndpoint(t *testing.T) {
	router := setupRouter()
	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/pingz", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "pong")
}

func TestRequestKeyEndpoint(t *testing.T) {
	router := setupRouter()
	w := httptest.NewRecorder()

	// Test valid request
	reqBody := map[string]string{"server_id": "test-server"}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/server/request-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusAccepted, w.Code)

	var response map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &response)
	assert.NoError(t, err)

	// Verify response structure
	assert.Contains(t, response, "request_id")

	// Verify UUID validity
	reqID := response["request_id"].(string)
	_, err = uuid.Parse(reqID)
	assert.NoError(t, err, "request_id should be a valid UUID")
}

func TestApprovalEndpoint(t *testing.T) {
	router := setupRouter()

	// Create a test request first
	w := httptest.NewRecorder()
	reqBody := map[string]string{"server_id": "test-server"}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/server/request-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	reqID := response["request_id"].(string)

	tests := []struct {
		name       string
		reqID      string
		authHeader string
		wantCode   int
	}{
		{
			name:       "Valid approval",
			reqID:      reqID,
			authHeader: "Bearer " + adminSecretKey,
			wantCode:   http.StatusOK,
		},
		{
			name:       "Invalid auth",
			reqID:      reqID,
			authHeader: "Bearer invalid-key",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "Missing auth",
			reqID:      reqID,
			authHeader: "",
			wantCode:   http.StatusUnauthorized,
		},
		{
			name:       "Invalid UUID",
			reqID:      "invalid-uuid",
			authHeader: "Bearer " + adminSecretKey,
			wantCode:   http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req, _ := http.NewRequest("GET", "/admin/approve/"+tt.reqID, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

func TestRequestExpiration(t *testing.T) {
	// Override request timeout for testing
	originalTimeout := approvalTimeout
	approvalTimeout = "1s"
	defer func() { approvalTimeout = originalTimeout }()

	router := setupRouter()

	// Create a test request
	w := httptest.NewRecorder()
	reqBody := map[string]string{"server_id": "test-server"}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/server/request-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	reqID := response["request_id"].(string)

	// Wait for request to expire
	time.Sleep(2 * time.Second)

	// Try to approve expired request
	r := httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/admin/approve/"+reqID, nil)
	req.Header.Set("Authorization", "Bearer "+adminSecretKey)
	router.ServeHTTP(r, req)

	assert.Equal(t, http.StatusGone, r.Code)
	assert.Contains(t, r.Body.String(), "expired")
}

func TestGetKeyEndpoint(t *testing.T) {
	router := setupRouter()

	// Create and approve a request
	w := httptest.NewRecorder()
	reqBody := map[string]string{"server_id": "test-server"}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/server/request-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	reqID := response["request_id"].(string)

	// Approve the request
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/admin/approve/"+reqID, nil)
	req.Header.Set("Authorization", "Bearer "+adminSecretKey)
	router.ServeHTTP(w, req)

	tests := []struct {
		name     string
		reqID    string
		wantCode int
	}{
		{
			name:     "Valid approved request",
			reqID:    reqID,
			wantCode: http.StatusOK,
		},
		{
			name:     "Invalid request ID",
			reqID:    "invalid-uuid",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "Non-existent request",
			reqID:    uuid.New().String(),
			wantCode: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			reqBody := map[string]string{"req_id": tt.reqID}
			jsonBody, _ := json.Marshal(reqBody)
			req, _ := http.NewRequest("POST", "/server/get-key", bytes.NewBuffer(jsonBody))
			req.Header.Set("Authorization", "Bearer "+serverSecretKey)
			req.Header.Set("Content-Type", "application/json")
			router.ServeHTTP(w, req)
			assert.Equal(t, tt.wantCode, w.Code)
		})
	}
}

func TestDenyEndpoint(t *testing.T) {
	router := setupRouter()

	// Create a test request
	w := httptest.NewRecorder()
	reqBody := map[string]string{"server_id": "test-server"}
	jsonBody, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/server/request-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	var response map[string]interface{}
	json.Unmarshal(w.Body.Bytes(), &response)
	reqID := response["request_id"].(string)

	// Test deny endpoint
	w = httptest.NewRecorder()
	req, _ = http.NewRequest("GET", "/admin/deny/"+reqID, nil)
	req.Header.Set("Authorization", "Bearer "+adminSecretKey)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "denied")

	// Verify request was removed
	time.Sleep(1 * time.Second)
	r := httptest.NewRecorder()
	reqBody = map[string]string{"req_id": reqID}
	jsonBody, _ = json.Marshal(reqBody)
	req, _ = http.NewRequest("POST", "/server/get-key", bytes.NewBuffer(jsonBody))
	req.Header.Set("Authorization", "Bearer "+serverSecretKey)
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(r, req)

	assert.Equal(t, http.StatusNotFound, r.Code)
}
