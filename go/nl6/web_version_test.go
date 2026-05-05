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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// TestVersionHandlerGET asserts the shape of GET /api/v1/version: 200,
// JSON body {"version": Version}, Content-Type application/json, and
// Cache-Control max-age=3600.
func TestVersionHandlerGET(t *testing.T) {
	orig := Version
	Version = "v0.5.0-test"
	defer func() { Version = orig }()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/version", nil)
	versionHandler(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}
	if got := rr.Header().Get("Cache-Control"); got != "private, max-age=3600" {
		t.Errorf("Cache-Control = %q, want private, max-age=3600", got)
	}

	var body map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if len(body) != 1 {
		t.Errorf("body has %d keys, want 1: %v", len(body), body)
	}
	if got := body["version"]; got != "v0.5.0-test" {
		t.Errorf("body.version = %q, want v0.5.0-test", got)
	}
}

// TestVersionRouteMethodGuard asserts that non-GET methods to
// /api/v1/version are rejected by the router with 405. Uses the real
// router so the Methods("GET") restriction is exercised.
func TestVersionRouteMethodGuard(t *testing.T) {
	router := mux.NewRouter()
	api := router.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/version", versionHandler).Methods("GET")

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(method, "/api/v1/version", strings.NewReader(""))
			router.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s /api/v1/version: status = %d, want 405", method, rr.Code)
			}
		})
	}
}
