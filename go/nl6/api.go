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
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type apiHTTPServer interface {
	Serve(net.Listener) error
	Close() error
}

var apiListenTCP = func(device *DeviceSimulator, addr string) (net.Listener, error) {
	if device.netNamespace != nil {
		return device.netNamespace.ListenTCPInNamespace("tcp", addr)
	}
	lc := net.ListenConfig{Control: setSocketBufferSize}
	return lc.Listen(context.Background(), "tcp", addr)
}

var apiNewHTTPServer = func(handler http.Handler) apiHTTPServer {
	return &http.Server{
		Handler:           handler,
		IdleTimeout:       30 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
	}
}

// APIServer implementation for storage device REST APIs
func (s *APIServer) Start() error {
	if s.running {
		return nil
	}

	// Only start API server if device has API resources
	if len(s.device.resources.API) == 0 {
		return nil // No API endpoints defined, skip
	}

	addr := fmt.Sprintf("%s:%d", s.device.IP.String(), s.device.APIPort)

	// Create HTTP mux for this device's API endpoints
	mux := http.NewServeMux()

	// Group API resources by path to handle multiple methods per endpoint
	pathResources := make(map[string][]*APIResource)
	for i := range s.device.resources.API {
		resource := &s.device.resources.API[i]
		pathResources[resource.Path] = append(pathResources[resource.Path], resource)
	}

	// Register handlers for each unique path (handles all methods)
	for path, resources := range pathResources {
		// Capture resources in closure
		pathResources := resources

		// Register single handler for this path that handles all methods
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			s.handleAPIRequestMultiMethod(w, r, pathResources)
		})
	}

	// Create listener
	listener, err := apiListenTCP(s.device, addr)
	if err != nil {
		return fmt.Errorf("failed to start API server on %s: %v", addr, err)
	}

	// Use shared TLS certificate from SimulatorManager (avoids per-device key generation)
	if s.sharedTLSCert == nil {
		// Close the listener so the socket (and its namespace veth bind, if
		// source-per-device is enabled) isn't orphaned on this error path.
		_ = listener.Close()
		return fmt.Errorf("no shared TLS certificate available for %s", addr)
	}
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*s.sharedTLSCert},
	}
	listener = tls.NewListener(listener, tlsConfig)

	server := apiNewHTTPServer(mux)
	s.listener = listener
	s.server = server
	s.running = true

	// Start HTTPS server in background
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			log.Printf("API server error on %s: %v", addr, err)
		}
	}()

	// log.Printf("API server started on %s", addr)
	return nil
}

func (s *APIServer) Stop() error {
	if !s.running {
		return nil
	}

	// Reset state unconditionally so a Close() error does not leave the
	// APIServer wedged in running=true with stale pointers. A retried
	// Stop() would otherwise double-close the server; a subsequent Start()
	// would short-circuit on running=true and silently "succeed" without
	// restarting. Close/listener errors are still surfaced to the caller.
	var closeErr error
	if s.server != nil {
		closeErr = s.server.Close()
	} else if s.listener != nil {
		closeErr = s.listener.Close()
	}

	s.server = nil
	s.listener = nil
	s.running = false
	return closeErr
}

// handleAPIRequestMultiMethod processes incoming API requests that may have multiple method handlers
func (s *APIServer) handleAPIRequestMultiMethod(w http.ResponseWriter, r *http.Request, resources []*APIResource) {
	// Find the resource that matches the request method and path
	var matchedResource *APIResource

	for _, resource := range resources {
		// Check if method matches (support wildcard for all methods)
		if resource.Method == "*" || r.Method == resource.Method {
			// Handle path parameters (e.g., /api/volumes/{uuid})
			if matchPathPattern(r.URL.Path, resource.Path) {
				matchedResource = resource
				break
			}
		}
	}

	// No matching resource found
	if matchedResource == nil {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Set appropriate content type
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Storage-API-Simulator")

	// Handle authentication (basic check for Authorization header)
	if r.Header.Get("Authorization") == "" {
		// For simulation purposes, we'll be lenient and allow unauthenticated requests
		// In production, this would require proper authentication
	}

	// Return the simulated response
	responseData, err := json.MarshalIndent(matchedResource.Response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set appropriate HTTP status based on method
	switch r.Method {
	case "POST":
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte{}) // No content for DELETE
		return
	case "PUT", "PATCH":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}

	w.Write(responseData)
}

// handleAPIRequest processes incoming API requests and returns simulated responses (legacy single method)
func (s *APIServer) handleAPIRequest(w http.ResponseWriter, r *http.Request, resource *APIResource) {
	// Check if method matches (support wildcard for all methods)
	if resource.Method != "*" && r.Method != resource.Method {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Handle path parameters (e.g., /api/volumes/{uuid})
	requestPath := r.URL.Path
	if !matchPathPattern(requestPath, resource.Path) {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	// Set appropriate content type
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Server", "Storage-API-Simulator")

	// Handle authentication (basic check for Authorization header)
	if r.Header.Get("Authorization") == "" {
		// For simulation purposes, we'll be lenient and allow unauthenticated requests
		// In production, this would require proper authentication
	}

	// Return the simulated response
	responseData, err := json.MarshalIndent(resource.Response, "", "  ")
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Set appropriate HTTP status based on method
	switch r.Method {
	case "POST":
		w.WriteHeader(http.StatusCreated)
	case "DELETE":
		w.WriteHeader(http.StatusNoContent)
		w.Write([]byte{}) // No content for DELETE
		return
	case "PUT", "PATCH":
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}

	w.Write(responseData)
}

// matchPathPattern checks if a request path matches a pattern with parameters
// Supports patterns like /api/volumes/{uuid} matching /api/volumes/123
func matchPathPattern(requestPath, pattern string) bool {
	// Exact match
	if requestPath == pattern {
		return true
	}

	// Split into segments
	requestSegments := strings.Split(strings.Trim(requestPath, "/"), "/")
	patternSegments := strings.Split(strings.Trim(pattern, "/"), "/")

	// Must have same number of segments
	if len(requestSegments) != len(patternSegments) {
		return false
	}

	// Match each segment
	for i := range requestSegments {
		patternSeg := patternSegments[i]
		requestSeg := requestSegments[i]

		// Check if pattern segment is a parameter (e.g., {uuid})
		if strings.HasPrefix(patternSeg, "{") && strings.HasSuffix(patternSeg, "}") {
			// Parameter - matches any value
			continue
		}

		// Must be exact match for non-parameter segments
		if patternSeg != requestSeg {
			return false
		}
	}

	return true
}
