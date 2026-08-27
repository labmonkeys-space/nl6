/*
 * © 2025 Sharon Aicler (saichler@gmail.com)
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAuthMiddleware_Disabled verifies that when apiKeyAuth is empty (default),
// all requests are allowed through without authentication.
func TestAuthMiddleware_Disabled(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Ensure authentication is disabled
	apiKeyAuth = ""
	
	router := setupRoutes()
	
	// Test that API endpoints are accessible without authentication
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	
	// Should succeed (200 or other non-401 status)
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("Expected request to succeed without auth when disabled, got 401")
	}
}

// TestAuthMiddleware_MissingKey verifies that when authentication is enabled,
// requests without the X-API-Key header are rejected with 401.
func TestAuthMiddleware_MissingKey(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "test-secret-key"
	
	router := setupRoutes()
	
	// Test that API endpoints reject requests without X-API-Key header
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for missing API key, got %d", rr.Code)
	}
	
	body := rr.Body.String()
	if !strings.Contains(body, "Missing X-API-Key header") {
		t.Errorf("Expected error message about missing header, got: %s", body)
	}
}

// TestAuthMiddleware_InvalidKey verifies that requests with an incorrect
// API key are rejected with 401.
func TestAuthMiddleware_InvalidKey(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "correct-secret-key"
	
	router := setupRoutes()
	
	// Test that API endpoints reject requests with wrong API key
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "wrong-key")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Expected 401 Unauthorized for invalid API key, got %d", rr.Code)
	}
	
	body := rr.Body.String()
	if !strings.Contains(body, "Invalid API key") {
		t.Errorf("Expected error message about invalid key, got: %s", body)
	}
}

// TestAuthMiddleware_ValidKey verifies that requests with the correct
// API key are allowed through.
func TestAuthMiddleware_ValidKey(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "correct-secret-key"
	
	router := setupRoutes()
	
	// Test that API endpoints accept requests with correct API key
	req := httptest.NewRequest(http.MethodGet, "/api/v1/status", nil)
	req.Header.Set("X-API-Key", "correct-secret-key")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	
	// Should succeed (200 or other non-401 status)
	if rr.Code == http.StatusUnauthorized {
		t.Errorf("Expected request to succeed with valid API key, got 401")
	}
}

// TestAuthMiddleware_HealthCheckExempt verifies that the /health endpoint
// remains accessible without authentication even when auth is enabled.
func TestAuthMiddleware_HealthCheckExempt(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "test-secret-key"
	
	router := setupRoutes()
	
	// Test that /health endpoint is accessible without authentication
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	
	if rr.Code != http.StatusOK {
		t.Errorf("Expected /health to be accessible without auth, got %d", rr.Code)
	}
	
	if rr.Body.String() != "OK" {
		t.Errorf("Expected /health to return 'OK', got: %s", rr.Body.String())
	}
}

// TestAuthMiddleware_WebUIExempt verifies that the Web UI endpoints
// remain accessible without authentication even when auth is enabled.
func TestAuthMiddleware_WebUIExempt(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "test-secret-key"
	
	router := setupRoutes()
	
	// Test that / and /ui endpoints don't require authentication
	// (they may return 404 if web files don't exist, but not 401)
	for _, path := range []string{"/", "/ui"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		
		if rr.Code == http.StatusUnauthorized {
			t.Errorf("Expected %s to be accessible without auth, got 401", path)
		}
	}
}

// TestAuthMiddleware_AllAPIEndpointsProtected verifies that all /api/v1
// endpoints are protected by the authentication middleware.
func TestAuthMiddleware_AllAPIEndpointsProtected(t *testing.T) {
	// Save and restore the global apiKeyAuth
	oldKey := apiKeyAuth
	defer func() { apiKeyAuth = oldKey }()
	
	// Enable authentication
	apiKeyAuth = "test-secret-key"
	
	router := setupRoutes()
	
	// Test a sample of different API endpoints to ensure they're all protected
	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/api/v1/devices"},
		{http.MethodGet, "/api/v1/status"},
		{http.MethodGet, "/api/v1/version"},
		{http.MethodGet, "/api/v1/fidelity"},
		{http.MethodGet, "/api/v1/flows/status"},
		{http.MethodGet, "/api/v1/traps/status"},
		{http.MethodGet, "/api/v1/syslog/status"},
		{http.MethodGet, "/api/v1/topology"},
		{http.MethodGet, "/api/v1/scenarios"},
	}
	
	for _, ep := range endpoints {
		req := httptest.NewRequest(ep.method, ep.path, nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("Expected %s %s to require auth (401), got %d", ep.method, ep.path, rr.Code)
		}
	}
}
