/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	runtimepprof "runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grafana/pyroscope-go"
	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// withProfiling resets the process-global profiling state before a test and
// restores it afterwards, so a test cannot leak a running profiler, an open
// gate or a pending timer into its neighbours.
func withProfiling(t *testing.T) {
	t.Helper()
	prevFlag, _ := profilingStartupFlag.Load().(string)
	reset := func() {
		stopProfiling()
		profiling.mu.Lock()
		profiling.restore = profilingTarget{}
		profiling.lastError = ""
		profiling.mu.Unlock()
	}
	t.Cleanup(func() {
		reset()
		profilingStartupFlag.Store(prevFlag)
	})
	reset()
	profilingStartupFlag.Store("")
}

// fakeIngest records what a fake Pyroscope received, so a test can prove a
// push happened and inspect the headers it carried.
type fakeIngest struct {
	ingests atomic.Int64
	mu      sync.Mutex
	headers []http.Header
}

func (f *fakeIngest) lastHeader() http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.headers) == 0 {
		return nil
	}
	return f.headers[len(f.headers)-1]
}

// fakePyroscopeAnswering is an HTTP server answering every upload with
// status, so the SDK can be started and stopped in-process against a
// collector that accepts (200) or rejects (401) it.
func fakePyroscopeAnswering(t *testing.T, status int) (*httptest.Server, *fakeIngest) {
	t.Helper()
	rec := &fakeIngest{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/ingest") {
			rec.ingests.Add(1)
			rec.mu.Lock()
			rec.headers = append(rec.headers, r.Header.Clone())
			rec.mu.Unlock()
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(srv.Close)
	return srv, rec
}

// fakePyroscope accepts every upload and counts ingests.
func fakePyroscope(t *testing.T) (*httptest.Server, *atomic.Int64) {
	t.Helper()
	srv, rec := fakePyroscopeAnswering(t, http.StatusOK)
	return srv, &rec.ingests
}

// withFastUploads routes the pyroscopeStart seam through the real SDK with a
// 1 s UploadRate, so a test can observe an upload without waiting 15 s.
func withFastUploads(t *testing.T) {
	t.Helper()
	prev := pyroscopeStart
	pyroscopeStart = func(cfg pyroscope.Config) (*pyroscope.Profiler, error) {
		cfg.UploadRate = time.Second
		return pyroscope.Start(cfg)
	}
	t.Cleanup(func() { pyroscopeStart = prev })
}

// withProfilingCredentials sets the flag-only credentials for a test.
func withProfilingCredentials(t *testing.T, user, pass, tenant string) {
	t.Helper()
	pu, pp, pt := profilingBasicAuthUser, profilingBasicAuthPassword, profilingTenantID
	profilingBasicAuthUser, profilingBasicAuthPassword, profilingTenantID = user, pass, tenant
	t.Cleanup(func() { profilingBasicAuthUser, profilingBasicAuthPassword, profilingTenantID = pu, pp, pt })
}

// tapLog tees the standard logger into a buffer for the test's duration (the
// existing captureLog swallows output around one call; the SDK logs from its
// own goroutines, so a tee that stays installed is what is needed here).
// lockedBuffer is shared with the USM interop test.
func tapLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buf := &lockedBuffer{}
	prev := log.Writer()
	log.SetOutput(io.MultiWriter(prev, buf))
	t.Cleanup(func() { log.SetOutput(prev) })
	return buf
}

func postProfiling(t *testing.T, body string) (*httptest.ResponseRecorder, ProfilingStatus) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/v1/profiling", bytes.NewReader([]byte(body)))
	w := httptest.NewRecorder()
	profilingToggleHandler(w, r)
	var resp struct {
		Data ProfilingStatus `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	return w, resp.Data
}

func getProfiling(t *testing.T) ProfilingStatus {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/profiling", nil)
	w := httptest.NewRecorder()
	profilingStatusHandler(w, r)
	var resp struct {
		Data ProfilingStatus `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("GET body is not the documented envelope: %v (body %q)", err, w.Body.String())
	}
	return resp.Data
}

// goroutineProfileText is the debug=1 goroutine profile, the one surface that
// prints each goroutine's pprof labels.
func goroutineProfileText(t *testing.T) string {
	t.Helper()
	var buf bytes.Buffer
	if err := runtimepprof.Lookup("goroutine").WriteTo(&buf, 1); err != nil {
		t.Fatalf("goroutine profile: %v", err)
	}
	return buf.String()
}

// labelsOfGoroutineWithFrame finds the goroutine stanza whose stack contains
// frame and returns its `# labels:` line, or "" when the goroutine carries
// none. Fails when no goroutine has that frame at all, because "no label"
// and "no goroutine" must not read the same.
func labelsOfGoroutineWithFrame(t *testing.T, frame string) string {
	t.Helper()
	for _, stanza := range strings.Split(goroutineProfileText(t), "\n\n") {
		if !strings.Contains(stanza, frame) {
			continue
		}
		for _, line := range strings.Split(stanza, "\n") {
			if strings.HasPrefix(line, "# labels:") {
				return strings.TrimSpace(strings.TrimPrefix(line, "# labels:"))
			}
		}
		return ""
	}
	t.Fatalf("no goroutine has %q on its stack", frame)
	return ""
}

func wantSubsystemLabel(t *testing.T, frame, subsystem string) {
	t.Helper()
	got := labelsOfGoroutineWithFrame(t, frame)
	want := `{"subsystem":"` + subsystem + `"}`
	if got != want {
		t.Errorf("goroutine with %s: labels %q, want %s", frame, got, want)
	}
}

// settledGoroutineCount waits (up to 2 s) for runtime.NumGoroutine to hold
// still across 100 ms, then returns it.
func settledGoroutineCount() int {
	deadline := time.Now().Add(2 * time.Second)
	n := runtime.NumGoroutine()
	for time.Now().Before(deadline) {
		time.Sleep(100 * time.Millisecond)
		m := runtime.NumGoroutine()
		if m == n {
			return n
		}
		n = m
	}
	return n
}

// pprofVia serves one /debug/pprof request through the real router.
func pprofVia(t *testing.T, router http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

// TestProfilingOffByDefaultPaysNothing is the gate's whole promise. With no
// flag and no POST a request to the pull surface is refused with the remedy in
// the body, spawns nothing, and no SDK goroutine exists anywhere.
func TestProfilingOffByDefaultPaysNothing(t *testing.T) {
	withProfiling(t)
	// Counted BEFORE setupRoutes: building the router must spawn nothing
	// either. The count is taken once it has been stable for a moment, so a
	// neighbouring test's goroutine winding down does not read as a change
	// of ours.
	before := settledGoroutineCount()
	router := setupRoutes()
	rr := pprofVia(t, router, "/debug/pprof/heap")
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("/debug/pprof/heap with profiling off: got %d, want 503 (body %q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "POST /api/v1/profiling") {
		t.Errorf("503 body does not name the remedy: %q", rr.Body.String())
	}
	// Transient goroutines (a finished handler's) need a moment to exit, so
	// the comparison waits for equality rather than asserting it at once.
	deadline := time.Now().Add(time.Second)
	after := runtime.NumGoroutine()
	for after != before && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
		after = runtime.NumGoroutine()
	}
	if after != before {
		t.Errorf("goroutines: %d before setupRoutes, %d after the refused request; a closed gate must spawn nothing", before, after)
	}
	if text := goroutineProfileText(t); strings.Contains(text, "pyroscope") {
		t.Errorf("an SDK goroutine exists with profiling off:\n%s", text)
	}
	st := getProfiling(t)
	if st.Enabled || st.Pushing || st.ServerAddress != "" || st.StartupFlag != "" || st.RevertPending {
		t.Errorf("status with profiling off: %+v", st)
	}
}

// TestProfilingStatus_BootNoFlagIsTheDocumentedShape pins the GET body an
// operator sees on a process booted without the flag.
func TestProfilingStatus_BootNoFlagIsTheDocumentedShape(t *testing.T) {
	withProfiling(t)
	r := httptest.NewRequest(http.MethodGet, "/api/v1/profiling", nil)
	w := httptest.NewRecorder()
	profilingStatusHandler(w, r)
	want := `{"success":true,"message":"Success","data":{"enabled":false,"startup_flag":"",` +
		`"server_address":"","pushing":false,"pprof_path":"/debug/pprof/","revert_pending":false}}`
	if got := strings.TrimSpace(w.Body.String()); got != want {
		t.Errorf("GET /api/v1/profiling:\n got %s\nwant %s", got, want)
	}
}

// TestProfilingDefaultServeMuxIsNeverServed keeps the pprof registration on
// http.DefaultServeMux inert. Importing net/http/pprof (and godeltaprof's
// http/pprof) registers handlers there in init(); nl6 serves its own router,
// so nothing reaches them, and this test is what stops a future
// http.ListenAndServe(addr, nil) from exposing an ungated pprof.
func TestProfilingDefaultServeMuxIsNeverServed(t *testing.T) {
	// Premise: the registration really happened, so the guard guards something.
	req := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)
	if _, pattern := http.DefaultServeMux.Handler(req); pattern == "" {
		t.Fatal("net/http/pprof did not register on DefaultServeMux; the premise of this guard is gone")
	}
	req = httptest.NewRequest(http.MethodGet, "/debug/pprof/delta_heap", nil)
	if _, pattern := http.DefaultServeMux.Handler(req); pattern == "" {
		t.Fatal("godeltaprof did not register on DefaultServeMux; the premise of this guard is gone")
	}

	// The rule: no production file serves a nil handler. Checked on the AST
	// rather than by grep so a rename or a reformat cannot dodge it.
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
	}
	isHTTPServerType := func(e ast.Expr) bool {
		sel, ok := e.(*ast.SelectorExpr)
		if !ok {
			return false
		}
		id, ok := sel.X.(*ast.Ident)
		return ok && id.Name == "http" && sel.Sel.Name == "Server"
	}
	isNil := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "nil"
	}
	servers := 0
	{
		for _, f := range files {
			ast.Inspect(f, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					// new(http.Server) is a zero Handler, i.e. DefaultServeMux.
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "new" && len(x.Args) == 1 && isHTTPServerType(x.Args[0]) {
						t.Errorf("%s: new(http.Server) has a nil Handler and serves DefaultServeMux", fset.Position(x.Pos()))
						return true
					}
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					id, ok := sel.X.(*ast.Ident)
					if !ok || id.Name != "http" {
						return true
					}
					switch sel.Sel.Name {
					case "ListenAndServe", "Serve", "ListenAndServeTLS", "ServeTLS":
						if isNil(x.Args[len(x.Args)-1]) {
							t.Errorf("%s: http.%s with a nil handler serves DefaultServeMux, and with it an ungated /debug/pprof/",
								fset.Position(x.Pos()), sel.Sel.Name)
						}
					}
				case *ast.ValueSpec:
					// var s http.Server: zero Handler, same as new().
					if x.Type != nil && isHTTPServerType(x.Type) {
						t.Errorf("%s: a zero-value http.Server variable serves DefaultServeMux", fset.Position(x.Pos()))
					}
				case *ast.AssignStmt:
					// srv.Handler = nil reinstates DefaultServeMux after the fact.
					for i, lhs := range x.Lhs {
						sel, ok := lhs.(*ast.SelectorExpr)
						if ok && sel.Sel.Name == "Handler" && i < len(x.Rhs) && isNil(x.Rhs[i]) {
							t.Errorf("%s: assigning a nil Handler serves DefaultServeMux", fset.Position(x.Pos()))
						}
					}
				case *ast.CompositeLit:
					if !isHTTPServerType(x.Type) {
						return true
					}
					servers++
					handlerSet := false
					for _, elt := range x.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Handler" && !isNil(kv.Value) {
							handlerSet = true
						}
					}
					if !handlerSet {
						t.Errorf("%s: http.Server literal without a Handler serves DefaultServeMux", fset.Position(x.Pos()))
					}
				}
				return true
			})
		}
	}
	if servers == 0 {
		t.Fatal("no http.Server literal found in the package; the scan is looking at the wrong tree")
	}
}

// alloyDefaultPaths is what Grafana Alloy's unmodified pyroscope.scrape block
// asks a Go target for, plus the two godeltaprof paths the docs add and the
// plain heap. Each must answer 200 with a gzip pprof body while on, and 503
// while off.
var alloyDefaultPaths = []string{
	"/debug/pprof/profile?seconds=1",
	"/debug/pprof/allocs",
	"/debug/pprof/goroutine",
	"/debug/pprof/mutex",
	"/debug/pprof/block",
	"/debug/pprof/heap",
	"/debug/pprof/delta_heap",
	"/debug/pprof/delta_mutex",
	"/debug/pprof/delta_block",
}

// TestProfilingPullOnlyServesEveryAlloyDefaultPath is the scrape half of the
// gate: `{"enabled":true}` with no address opens the pull surface without
// starting the SDK, and every default-scraped path answers a gzip profile.
func TestProfilingPullOnlyServesEveryAlloyDefaultPath(t *testing.T) {
	withProfiling(t)
	router := setupRoutes()

	w, st := postProfiling(t, `{"enabled":true}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST pull-only: got %d (body %q)", w.Code, w.Body.String())
	}
	if !st.Enabled || st.Pushing || st.ServerAddress != "" {
		t.Fatalf("pull-only status: %+v", st)
	}
	if text := goroutineProfileText(t); strings.Contains(text, "pyroscope") {
		t.Errorf("pull-only started the SDK:\n%s", text)
	}
	for _, path := range alloyDefaultPaths {
		rr := pprofVia(t, router, path)
		if rr.Code != http.StatusOK {
			t.Errorf("%s while on: got %d (body %q)", path, rr.Code, rr.Body.String())
			continue
		}
		if b := rr.Body.Bytes(); len(b) < 2 || b[0] != 0x1f || b[1] != 0x8b {
			t.Errorf("%s while on: body is not gzip (first bytes % x)", path, b[:min(len(b), 4)])
		}
	}

	// cmdline is deliberately NOT served: it prints os.Args, which carries
	// -profiling-pyroscope-basic-auth user:pass.
	if rr := pprofVia(t, router, "/debug/pprof/cmdline"); rr.Code != http.StatusNotFound {
		t.Errorf("/debug/pprof/cmdline while on: got %d, want 404 (it would print the basic-auth flag)", rr.Code)
	}
	// The bare prefix redirects onto the gated surface rather than 404ing.
	if rr := pprofVia(t, router, "/debug/pprof"); rr.Code != http.StatusMovedPermanently ||
		rr.Header().Get("Location") != "/debug/pprof/" {
		t.Errorf("/debug/pprof: got %d %q, want 301 to /debug/pprof/", rr.Code, rr.Header().Get("Location"))
	}

	if w, _ = postProfiling(t, `{"enabled":false}`); w.Code != http.StatusOK {
		t.Fatalf("POST off: got %d", w.Code)
	}
	for _, path := range alloyDefaultPaths {
		if rr := pprofVia(t, router, path); rr.Code != http.StatusServiceUnavailable {
			t.Errorf("%s after off: got %d, want 503", path, rr.Code)
		}
	}
}

// TestProfilingPushStartsAndStops covers the SDK half: a POST with an address
// starts a push (an ingest reaches the server), and the off POST stops it
// with no SDK goroutine left behind, having flushed the last upload.
func TestProfilingPushStartsAndStops(t *testing.T) {
	withProfiling(t)
	srv, ingests := fakePyroscope(t)

	w, st := postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("POST push: got %d (body %q)", w.Code, w.Body.String())
	}
	if !st.Enabled || !st.Pushing || st.ServerAddress != srv.URL {
		t.Fatalf("push status: %+v", st)
	}
	if text := goroutineProfileText(t); !strings.Contains(text, "pyroscope") {
		t.Fatal("pushing, but no SDK goroutine exists")
	}

	// Stop flushes the session before returning, so at least one ingest has
	// landed by the time the off POST answers.
	if w, st = postProfiling(t, `{"enabled":false}`); w.Code != http.StatusOK || st.Enabled || st.Pushing {
		t.Fatalf("POST off: %d %+v", w.Code, st)
	}
	if ingests.Load() == 0 {
		t.Error("no upload reached the server across start and stop; the push never happened")
	}
	// The SDK's goroutines exit inside Stop (session and uploader both join)
	// and the transport's idle connections are closed. Give the connection
	// goroutines a moment to notice the close.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && strings.Contains(goroutineProfileText(t), "pyroscope") {
		time.Sleep(10 * time.Millisecond)
	}
	if text := goroutineProfileText(t); strings.Contains(text, "pyroscope") {
		t.Errorf("SDK goroutine survived the off POST:\n%s", text)
	}
}

// TestProfilingToggle_IdempotentOnAndRetarget: the same address twice is a
// no-op (one profiler), a different address replaces it (a new profiler, one
// transition), and the address from the startup flag is the default for a
// bare `{"enabled":true}`.
func TestProfilingToggle_IdempotentOnAndRetarget(t *testing.T) {
	withProfiling(t)
	a, _ := fakePyroscope(t)
	b, _ := fakePyroscope(t)

	postProfiling(t, `{"enabled":true,"server_address":"`+a.URL+`"}`)
	profiling.mu.Lock()
	first := profiling.profiler
	profiling.mu.Unlock()
	if first == nil {
		t.Fatal("no profiler after the first on")
	}

	if w, _ := postProfiling(t, `{"enabled":true,"server_address":"`+a.URL+`"}`); w.Code != http.StatusOK {
		t.Fatalf("second on: %d", w.Code)
	}
	profiling.mu.Lock()
	second := profiling.profiler
	profiling.mu.Unlock()
	if second != first {
		t.Error("an idempotent on started a second profiler")
	}

	_, st := postProfiling(t, `{"enabled":true,"server_address":"`+b.URL+`"}`)
	profiling.mu.Lock()
	third := profiling.profiler
	profiling.mu.Unlock()
	if third == first || third == nil {
		t.Error("a re-target did not replace the profiler")
	}
	if st.ServerAddress != b.URL || !st.Pushing {
		t.Errorf("re-target status: %+v", st)
	}

	// Startup-flag default: off, then a bare on pushes to the flag's address.
	profilingStartupFlag.Store(a.URL)
	postProfiling(t, `{"enabled":false}`)
	_, st = postProfiling(t, `{"enabled":true}`)
	if st.ServerAddress != a.URL || !st.Pushing || st.StartupFlag != a.URL {
		t.Errorf("bare on with a startup flag: %+v", st)
	}
}

// TestProfilingToggle_StartFailureIs500WithState drives a Start failure
// through the pyroscopeStart seam. The gate stays open, nothing pushes, and
// the error is reported by both the POST and a later GET.
func TestProfilingToggle_StartFailureIs500WithState(t *testing.T) {
	withProfiling(t)
	prev := pyroscopeStart
	pyroscopeStart = func(pyroscope.Config) (*pyroscope.Profiler, error) {
		return nil, errors.New("induced start failure")
	}
	t.Cleanup(func() { pyroscopeStart = prev })

	w, st := postProfiling(t, `{"enabled":true,"server_address":"http://127.0.0.1:1"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("start failure: got %d, want 500 (body %q)", w.Code, w.Body.String())
	}
	if !st.Enabled || st.Pushing || !strings.Contains(st.LastError, "induced start failure") {
		t.Errorf("status after a failed start: %+v", st)
	}
	got := getProfiling(t)
	if !got.Enabled || got.Pushing || got.LastError == "" {
		t.Errorf("GET after a failed start: %+v", got)
	}
	// A later good start clears the error.
	pyroscopeStart = prev
	srv, _ := fakePyroscope(t)
	if _, st = postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`); st.LastError != "" || !st.Pushing {
		t.Errorf("a successful re-target did not clear last_error: %+v", st)
	}
}

// TestProfilingToggle_Rejections is the 400 table: the required key, an
// unknown key, trailing content, bad durations, and bad addresses.
func TestProfilingToggle_Rejections(t *testing.T) {
	withProfiling(t)
	cases := []struct {
		name, body, want string
	}{
		{"missing enabled", `{"duration":"5m"}`, `enabled\" is required`},
		{"typo", `{"enable":true}`, "unknown field"},
		{"trailing", `{"enabled":true}{"enabled":false}`, "unexpected content"},
		{"zero duration", `{"enabled":true,"duration":"0s"}`, "must be positive"},
		{"negative duration", `{"enabled":true,"duration":"-1s"}`, "must be positive"},
		{"unparseable duration", `{"enabled":true,"duration":"soon"}`, "invalid duration"},
		{"over cap", `{"enabled":true,"duration":"25h"}`, "exceeds maximum"},
		{"ftp address", `{"enabled":true,"server_address":"ftp://x"}`, "server_address"},
		{"no host", `{"enabled":true,"server_address":"http://"}`, "no host"},
		{"not a url", `{"enabled":true,"server_address":"::bad"}`, "server_address"},
		{"userinfo", `{"enabled":true,"server_address":"http://u:p@x:4040"}`, "must not embed credentials"},
		{"address on off", `{"enabled":false,"server_address":"http://x:4040"}`, "only meaningful with enabled:true"},
		{"empty address on off", `{"enabled":false,"server_address":""}`, "only meaningful with enabled:true"},
		{"query", `{"enabled":true,"server_address":"http://x:4040?a=b"}`, "query or fragment"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w, _ := postProfiling(t, tc.body)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400 (body %q)", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), tc.want) {
				t.Errorf("body %q does not mention %q", w.Body.String(), tc.want)
			}
		})
	}
	if st := getProfiling(t); st.Enabled {
		t.Error("a rejected request changed the gate")
	}
}

// TestProfilingAddressValidationTable pins the flag validator directly, since
// main() fatals on it before any subsystem starts.
func TestProfilingAddressValidationTable(t *testing.T) {
	good := []string{"http://pyroscope:4040", "https://p.example:443/", "http://127.0.0.1:4040"}
	for _, a := range good {
		if err := validateProfilingAddress(a); err != nil {
			t.Errorf("%q rejected: %v", a, err)
		}
	}
	bad := []string{"", "ftp://x", "pyroscope:4040", "http://", "://x", "unix:///tmp/sock",
		"http://user:secret@pyroscope:4040", "https://user@pyroscope:4040",
		"http://pyroscope:4040?tenant=x", "http://pyroscope:4040/#frag"}
	for _, a := range bad {
		if err := validateProfilingAddress(a); err == nil {
			t.Errorf("%q accepted", a)
		}
	}
	// The refusal must not echo the secret it refuses.
	if err := validateProfilingAddress("http://user:hunter2@pyroscope:4040"); err == nil ||
		strings.Contains(err.Error(), "hunter2") || !strings.Contains(err.Error(), "-profiling-pyroscope-basic-auth") {
		t.Errorf("userinfo refusal: %v", err)
	}
}

// TestProfilingRefusesTheAdhocEnv: the SDK replaces ServerAddress from
// PYROSCOPE_ADHOC_SERVER_ADDRESS inside Start, silently. nl6 refuses to start
// with it set rather than push somewhere the flag does not say.
func TestProfilingRefusesTheAdhocEnv(t *testing.T) {
	unset := func(string) (string, bool) { return "", false }
	if err := validateProfilingEnvironment(unset); err != nil {
		t.Errorf("unset: %v", err)
	}
	set := func(k string) (string, bool) { return "http://elsewhere:4040", k == profilingAdhocEnv }
	err := validateProfilingEnvironment(set)
	if err == nil || !strings.Contains(err.Error(), profilingAdhocEnv) || !strings.Contains(err.Error(), "unset it") {
		t.Errorf("set: %v", err)
	}
}

// TestProfilingToggle_TimedRevert: on with a duration reverts to off, logged
// once, and the status reports the deadline and the target meanwhile.
func TestProfilingToggle_TimedRevert(t *testing.T) {
	withProfiling(t)
	logs := tapLog(t)
	w, st := postProfiling(t, `{"enabled":true,"duration":"120ms"}`)
	if w.Code != http.StatusOK || !st.Enabled || !st.RevertPending || st.RevertAt == "" || st.RevertTo == nil || *st.RevertTo {
		t.Fatalf("timed on: %d %+v", w.Code, st)
	}
	if _, err := time.Parse(time.RFC3339, st.RevertAt); err != nil {
		t.Errorf("revert_at %q is not RFC3339: %v", st.RevertAt, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for profilingGateOpen.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if profilingGateOpen.Load() {
		t.Fatal("the revert did not fire")
	}
	if st := getProfiling(t); st.Enabled || st.RevertPending {
		t.Errorf("after the revert: %+v", st)
	}
	if n := strings.Count(logs.String(), "[auto-revert after"); n != 1 {
		t.Errorf("auto-revert logged %d times, want exactly 1:\n%s", n, logs.String())
	}
}

// TestProfilingToggle_LaterRequestSupersedes copies the fidelity shape: watch
// past the FIRST timer's deadline to prove it did not survive.
func TestProfilingToggle_LaterRequestSupersedes(t *testing.T) {
	withProfiling(t)
	postProfiling(t, `{"enabled":true,"duration":"400ms"}`) // superseded
	postProfiling(t, `{"enabled":true,"duration":"80ms"}`)  // wins

	deadline := time.Now().Add(2 * time.Second)
	for profilingGateOpen.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if profilingGateOpen.Load() {
		t.Fatal("the second timer did not fire")
	}

	// Re-enable, then wait past the FIRST timer's deadline. If it survived,
	// it fires here and drags the gate closed.
	postProfiling(t, `{"enabled":true}`)
	time.Sleep(600 * time.Millisecond)
	if !profilingGateOpen.Load() {
		t.Error("a superseded timer fired after its own deadline; timers stacked instead of superseding")
	}
}

// TestProfilingToggle_ChainKeepsTheDestination: same-direction timed toggles
// keep the original restore target; a direction change starts a new chain.
func TestProfilingToggle_ChainKeepsTheDestination(t *testing.T) {
	withProfiling(t)
	postProfiling(t, `{"enabled":true,"duration":"10s"}`)
	_, st := postProfiling(t, `{"enabled":true,"duration":"100ms"}`)
	if st.RevertTo == nil || *st.RevertTo {
		t.Fatalf("same-direction chain lost its destination: %+v", st)
	}
	deadline := time.Now().Add(2 * time.Second)
	for profilingGateOpen.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if profilingGateOpen.Load() {
		t.Fatal("chain did not revert to off")
	}

	// Standing on, then a brief off: the off's revert restores ON.
	postProfiling(t, `{"enabled":true}`)
	_, st = postProfiling(t, `{"enabled":false,"duration":"100ms"}`)
	if st.Enabled || st.RevertTo == nil || !*st.RevertTo {
		t.Fatalf("opposite-direction toggle: %+v", st)
	}
	deadline = time.Now().Add(2 * time.Second)
	for !profilingGateOpen.Load() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !profilingGateOpen.Load() {
		t.Error("the peek's revert did not restore the standing on")
	}
}

// TestProfilingToggle_FiredCallbackCannotClobber: a revert whose deadline
// elapsed while a standing POST held the lock must recognise itself as
// superseded (the generation counter).
func TestProfilingToggle_FiredCallbackCannotClobber(t *testing.T) {
	withProfiling(t)
	postProfiling(t, `{"enabled":true,"duration":"60ms"}`)
	// Hold the lock past the deadline so the callback fires and blocks on it,
	// then supersede it under that same hold.
	profiling.mu.Lock()
	time.Sleep(120 * time.Millisecond)
	cancelProfilingRevertLocked()
	profiling.mu.Unlock()
	// The blocked callback now acquires the lock: it must not close the gate.
	time.Sleep(50 * time.Millisecond)
	if !profilingGateOpen.Load() {
		t.Error("a stale revert callback closed the gate after being superseded")
	}
}

// blockProfileRecordsAContendedWait is the behavioural read-back of the block
// profile rate, which the runtime exposes no getter for: with the rate at 0
// a deliberate wait on a channel records nothing.
func blockProfileRecordsAContendedWait() bool {
	// Sum the event COUNT over every record rather than counting records: a
	// record is keyed by stack, so a repeat of this probe (-count=3) would
	// update an existing record and add none.
	total := func() int64 {
		var recs []runtime.BlockProfileRecord
		for {
			n, ok := runtime.BlockProfile(recs)
			if ok {
				recs = recs[:n]
				break
			}
			recs = make([]runtime.BlockProfileRecord, n+8)
		}
		var sum int64
		for _, r := range recs {
			sum += r.Count
		}
		return sum
	}
	before := total()
	ch := make(chan struct{})
	go func() { time.Sleep(2 * time.Millisecond); close(ch) }()
	<-ch
	return total() > before
}

// TestProfilingRuntimeGlobalsStayZero pins that this change does NOT set
// runtime.SetMutexProfileFraction or runtime.SetBlockProfileRate: both read
// 0 before, during and after an on/off/on cycle. A later change that sets them
// inside the on-branch has to restore them on stop, or this fails.
func TestProfilingRuntimeGlobalsStayZero(t *testing.T) {
	withProfiling(t)
	srv, _ := fakePyroscope(t)

	// Detection power for the block half: at rate 1 the probe DOES record.
	runtime.SetBlockProfileRate(1)
	if !blockProfileRecordsAContendedWait() {
		runtime.SetBlockProfileRate(0)
		t.Fatal("the block-profile probe cannot see a rate of 1; it would not see a leaked rate either")
	}
	runtime.SetBlockProfileRate(0)

	check := func(stage string) {
		t.Helper()
		if f := runtime.SetMutexProfileFraction(-1); f != 0 {
			t.Errorf("%s: mutex profile fraction is %d, want 0", stage, f)
		}
		if blockProfileRecordsAContendedWait() {
			t.Errorf("%s: block profile rate is non-zero", stage)
		}
	}
	check("before")
	postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`)
	check("on (pushing)")
	postProfiling(t, `{"enabled":false}`)
	check("off")
	postProfiling(t, `{"enabled":true}`)
	check("on (pull-only)")
	postProfiling(t, `{"enabled":false}`)
	check("after")
}

// TestProfilingCPUContentionIsNotMasked: the runtime allows one CPU profile
// at a time, so while the SDK's collector runs a scrape of /profile is a 500
// from net/http/pprof, not a silent empty profile.
func TestProfilingCPUContentionIsNotMasked(t *testing.T) {
	withProfiling(t)
	srv, ingests := fakePyroscope(t)
	router := setupRoutes()
	withFastUploads(t)
	postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`)
	// Wait for the first upload rather than probing the runtime's CPU slot:
	// a probe can collide with the SDK's own StartCPUProfile, which the SDK
	// retries only at its next interval.
	deadline := time.Now().Add(10 * time.Second)
	for ingests.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ingests.Load() == 0 {
		t.Fatal("the SDK never uploaded; its CPU collector is not running")
	}
	// The collector re-arms between intervals, so a scrape can land in the
	// gap and then hold the slot itself, which makes the SDK's next re-arm
	// fail and retry only at its next tick. So after a scrape that got
	// through, wait longer than one interval for the SDK to re-acquire;
	// at least one of three must hit the contention.
	var rr *httptest.ResponseRecorder
	for i := 0; i < 3; i++ {
		rr = pprofVia(t, router, "/debug/pprof/profile?seconds=1")
		if rr.Code == http.StatusInternalServerError {
			break
		}
		time.Sleep(1500 * time.Millisecond)
	}
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("CPU scrape while the SDK collects: got %d on three tries, want at least one 500 (body %q)", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "already in use") {
		t.Errorf("500 body does not say why: %q", rr.Body.String())
	}
	// The heap paths are unaffected by the CPU collector.
	if rr := pprofVia(t, router, "/debug/pprof/heap"); rr.Code != http.StatusOK {
		t.Errorf("heap while pushing: got %d", rr.Code)
	}
}

// TestProfilingShutdownStopsThePush: manager.Shutdown stops the SDK beside
// cancelFidelityRevert and cancels the pending revert.
func TestProfilingShutdownStopsThePush(t *testing.T) {
	withProfiling(t)
	srv, _ := fakePyroscope(t)
	postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`","duration":"10s"}`)
	if !profilingGateOpen.Load() {
		t.Fatal("not on")
	}
	stopProfiling()
	st := getProfiling(t)
	if st.Enabled || st.Pushing || st.RevertPending {
		t.Errorf("after stopProfiling: %+v", st)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && strings.Contains(goroutineProfileText(t), "pyroscope") {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(goroutineProfileText(t), "pyroscope") {
		t.Error("SDK goroutine survived stopProfiling")
	}
	// And Shutdown really calls it, behaviourally: a real manager (no
	// namespace) with a push running, then Shutdown.
	sm := NewSimulatorManagerWithOptions(false, WithFlowTickInterval(30*time.Second))
	postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`","duration":"10s"}`)
	if !getProfiling(t).Pushing {
		t.Fatal("not pushing before Shutdown")
	}
	if err := sm.Shutdown(); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if st := getProfiling(t); st.Enabled || st.Pushing || st.RevertPending {
		t.Errorf("after Shutdown: %+v", st)
	}
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && strings.Contains(goroutineProfileText(t), "pyroscope") {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(goroutineProfileText(t), "pyroscope") {
		t.Error("SDK goroutine survived manager.Shutdown")
	}
}

// TestProfilingRoutes_RegisteredOnTheRouter mirrors the fidelity router test.
func TestProfilingRoutes_RegisteredOnTheRouter(t *testing.T) {
	withProfiling(t)
	router := setupRoutes()

	post := httptest.NewRequest(http.MethodPost, "/api/v1/profiling", bytes.NewReader([]byte(`{"enabled":true}`)))
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, post)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST via router: got %d (body %q)", rr.Code, rr.Body.String())
	}
	if !profilingGateOpen.Load() {
		t.Fatal("POST routed to a handler that did not open the gate")
	}
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/profiling", nil))
	var resp struct {
		Data ProfilingStatus `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || !resp.Data.Enabled {
		t.Errorf("GET via router: %d %q (%v)", rr.Code, rr.Body.String(), err)
	}
	rr = httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodDelete, "/api/v1/profiling", nil))
	if rr.Code == http.StatusOK {
		t.Error("DELETE returned 200; only GET and POST are registered")
	}
}

// ── Labels ──────────────────────────────────────────────────────────────────
//
// Each subsystem entry point tags its goroutine, or its fire through
// pprof.Do. The long-lived goroutines are read back from the goroutine
// profile; the pprof.Do funnels are read back from INSIDE the funnel, through
// a callback the funnel already calls (ifIndexFn, writeOverride), because a
// label scoped to the fire is gone by the time the fire returns.

func TestProfilingLabel_SNMPReadLoop(t *testing.T) {
	srv := deviceForProfile(t, "asr9k.json")
	srv.device.IP = net.IPv4(127, 0, 0, 1)
	srv.device.SNMPPort = 0
	if err := srv.Start(); err != nil {
		t.Fatalf("SNMPServer.Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })
	// The goroutine is parked in ReadFromUDP by the time Start returns, or
	// shortly after.
	time.Sleep(20 * time.Millisecond)
	wantSubsystemLabel(t, "(*SNMPServer).handleRequests", subsystemSNMP)
}

func TestProfilingLabel_TrapFireFunnel(t *testing.T) {
	cat, _ := LoadEmbeddedCatalog()
	mc := newMockCollector(t, false)
	defer mc.Close()
	conn := openTestUDPConn(t)
	var seen string
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeTrap,
		Collector: mc.addr,
		IfIndexFn: func() int {
			seen = labelsOfGoroutineWithFrame(t, "(*TrapExporter).fireWithSource")
			return 1
		},
	})
	e.SetConn(conn)
	e.StartBackgroundLoops(context.Background())
	defer e.Close()
	if e.Fire(cat.ByName["linkDown"], nil) == 0 {
		t.Fatal("Fire returned 0")
	}
	if want := `{"subsystem":"trap"}`; seen != want {
		t.Errorf("labels inside the trap fire funnel: %q, want %s", seen, want)
	}
}

func TestProfilingLabel_SyslogFireFunnel(t *testing.T) {
	cat := testSyslogCatalog(t)
	_, collectorAddr := newLocalUDPCollector(t)
	var seen string
	e := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP:   net.IPv4(10, 42, 0, 7),
		Encoder:    &RFC5424Encoder{},
		Collector:  collectorAddr,
		SharedConn: newTestSharedSocket(t),
		SysName:    "rtr",
		IfIndexFn: func() int {
			seen = labelsOfGoroutineWithFrame(t, "(*SyslogExporter).fireWithSource")
			return 3
		},
		IfNameFn: func(i int) string { return "Gi0/3" },
	})
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Fire(cat.ByName["interface-down"], nil); err != nil {
		t.Fatal(err)
	}
	if want := `{"subsystem":"syslog"}`; seen != want {
		t.Errorf("labels inside the syslog fire funnel: %q, want %s", seen, want)
	}
}

func TestProfilingLabel_FlowTickFunnel(t *testing.T) {
	sm := newTestManager()
	sm.flowBufPool = *testPool()
	fe := newTestFlowExporter(testDevice("10.0.0.1"), flowProfileEdgeRouter, time.Second, time.Second, time.Minute)
	conn := testSender(t)
	defer conn.Close()
	fe.conn.Store(conn)
	var seen string
	fe.writeOverride = func([]byte) error {
		if seen == "" {
			seen = labelsOfGoroutineWithFrame(t, "(*SimulatorManager).tickFlowExporter")
		}
		return nil
	}
	// The first tick writes the NetFlow v9 template, so one tick suffices.
	sm.tickFlowExporter(context.Background(), fe, time.Now())
	if want := `{"subsystem":"flow"}`; seen != want {
		t.Errorf("labels inside the flow tick funnel: %q, want %s", seen, want)
	}
}

func TestProfilingLabel_GNMISubscribeStream(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := newFakeSubscribeStream(ctx)
	stream.recvQueue <- &gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{
		Subscribe: &gnmipb.SubscriptionList{
			Mode: gnmipb.SubscriptionList_STREAM,
			Subscription: []*gnmipb.Subscription{{
				Path:           pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"),
				Mode:           gnmipb.SubscriptionMode_SAMPLE,
				SampleInterval: uint64(time.Second),
			}},
		},
	}}
	done := make(chan struct{})
	go func() { defer close(done); _ = srv.Subscribe(stream) }()
	// The stream goroutine is live once the first sync lands.
	select {
	case <-stream.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("no first update from the stream")
	}
	wantSubsystemLabel(t, "(*gnmiServer).Subscribe", subsystemGNMI)
	cancel()
	<-done
}

func TestProfilingLabel_GNMIGet(t *testing.T) {
	srv, _, _, _ := newTestGnmiServer(t, 1)
	// pprof.Do propagates the labels into the context it hands the body, and
	// the runtime carries them on the goroutine for the call's duration.
	// Get's body discards its context, so the read-back is the goroutine's
	// own labels, sampled by a Get racing against a goroutine profile: run
	// Gets in a loop and look for the labelled stack.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		req := &gnmipb.GetRequest{Path: []*gnmipb.Path{
			pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets")}}
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = srv.Get(context.Background(), req)
			}
		}
	}()
	defer func() { close(stop); <-done }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, stanza := range strings.Split(goroutineProfileText(t), "\n\n") {
			if strings.Contains(stanza, "(*gnmiServer).getLabelled") &&
				strings.Contains(stanza, `# labels: {"subsystem":"gnmi"}`) {
				return
			}
		}
	}
	t.Error("never observed a Get running under the gnmi label")
}

func TestProfilingLabel_GNMIDialoutRunLoop(t *testing.T) {
	_, addr, stop := startTestDialoutCollector(t, "127.0.0.1:0")
	defer stop()
	dev := newTestGnmiDevice(t, 1)
	e := newTestDialoutExporter(t, dev, addr, "sample",
		[]string{"/interfaces/interface[name=*]/state/counters/in-octets"})
	e.Start()
	t.Cleanup(func() { _ = e.Close() })
	time.Sleep(50 * time.Millisecond)
	wantSubsystemLabel(t, "(*GnmiDialoutExporter).run", subsystemGNMIDialout)
}

func TestProfilingLabel_ScenarioFunnels(t *testing.T) {
	// The controller's funnels wrap through withSubsystem; pin the helper's
	// contract (label visible on the goroutine for the body's duration, gone
	// after) and that the three wraps are present in the source, since a
	// scenario start needs a fleet this test does not build.
	var inside string
	withSubsystem(context.Background(), subsystemScenario, func(ctx context.Context) {
		inside = labelsOfGoroutineWithFrame(t, "TestProfilingLabel_ScenarioFunnels")
		if v, ok := runtimepprof.Label(ctx, subsystemLabelKey); !ok || v != subsystemScenario {
			t.Errorf("label not in the body's context: %q %v", v, ok)
		}
	})
	if want := `{"subsystem":"scenario"}`; inside != want {
		t.Errorf("inside withSubsystem: %q, want %s", inside, want)
	}
	if after := labelsOfGoroutineWithFrame(t, "TestProfilingLabel_ScenarioFunnels"); after != "" {
		t.Errorf("label leaked past withSubsystem: %q", after)
	}
	// Secondary only: the ticker, startLocked (via ScheduleStart) and finish
	// are each read back behaviourally by the tests below.
	src, err := os.ReadFile("scenario_controller.go")
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(string(src), "subsystemScenario"); n < 3 {
		t.Errorf("scenario_controller.go references subsystemScenario %d times, want at least 3 (flow ticker, startLocked, finish)", n)
	}
}

// TestProfilingBootFlagStartsThePush drives the boot path main takes for
// -profiling-pyroscope: the startup flag is recorded, the push starts, GET
// reports both, and the pull surface opens. The empty-flag branch is the
// off-by-default row from the other side, so it is pinned here too.
func TestProfilingBootFlagStartsThePush(t *testing.T) {
	withProfiling(t)

	startProfilingFromFlag("")
	if st := getProfiling(t); st.Enabled || st.Pushing || st.StartupFlag != "" {
		t.Fatalf("an empty flag started something: %+v", st)
	}

	sink, _ := fakePyroscope(t)
	startProfilingFromFlag(sink.URL)
	st := getProfiling(t)
	if !st.Enabled || !st.Pushing || st.ServerAddress != sink.URL || st.StartupFlag != sink.URL {
		t.Fatalf("boot with the flag: %+v", st)
	}
	r := httptest.NewRequest(http.MethodGet, "/debug/pprof/heap", nil)
	w := httptest.NewRecorder()
	setupRoutes().ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Errorf("/debug/pprof/heap after boot with the flag: got %d, want 200", w.Code)
	}
}

// ── Review patches (nl6#635 review) ────────────────────────────────────────

// TestProfilingCredentialsAreBoundToTheFlagAddress: the flag's basic auth and
// tenant reach the flag's address (Authorization + X-Scope-OrgID arrive), and
// are WITHHELD from a REST-supplied address that differs, with the transition
// log saying so. Otherwise an unauthenticated POST could redirect heap
// profiles plus the operator's credentials to any host.
func TestProfilingCredentialsAreBoundToTheFlagAddress(t *testing.T) {
	withProfiling(t)
	withFastUploads(t)
	user, pass, err := parseProfilingBasicAuth("alice:hunter2")
	if err != nil {
		t.Fatal(err)
	}
	withProfilingCredentials(t, user, pass, "tenant-7")
	logs := tapLog(t)
	flagSrv, flagRec := fakePyroscopeAnswering(t, http.StatusOK)
	otherSrv, otherRec := fakePyroscopeAnswering(t, http.StatusOK)
	profilingStartupFlag.Store(flagSrv.URL)

	waitIngest := func(rec *fakeIngest) http.Header {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for rec.ingests.Load() == 0 && time.Now().Before(deadline) {
			time.Sleep(50 * time.Millisecond)
		}
		if rec.ingests.Load() == 0 {
			t.Fatal("no upload arrived")
		}
		return rec.lastHeader()
	}

	// The flag's address, spelled differently (upper-case host, trailing
	// slash): still the flag's address, credentials attached.
	spelled := strings.Replace(flagSrv.URL, "http://127.0.0.1", "HTTP://127.0.0.1", 1) + "/"
	if _, _, _, withheld := profilingCredentialsFor(spelled); withheld {
		t.Errorf("%q is the flag's address %q spelled differently and must not be treated as foreign", spelled, flagSrv.URL)
	}
	if _, err := setProfiling(true, &spelled, 0); err != nil {
		t.Fatal(err)
	}
	h := waitIngest(flagRec)
	user, pass, ok := (&http.Request{Header: h}).BasicAuth()
	if !ok || user != "alice" || pass != "hunter2" {
		t.Errorf("flag address: Authorization = %q, want Basic alice:hunter2", h.Get("Authorization"))
	}
	if got := h.Get("X-Scope-OrgID"); got != "tenant-7" {
		t.Errorf("flag address: X-Scope-OrgID = %q, want tenant-7", got)
	}

	// A different address from REST: nothing attached, and the log says why.
	if _, err := setProfiling(true, &otherSrv.URL, 0); err != nil {
		t.Fatal(err)
	}
	h = waitIngest(otherRec)
	if h.Get("Authorization") != "" || h.Get("X-Scope-OrgID") != "" {
		t.Errorf("other address received the flag's credentials: Authorization=%q X-Scope-OrgID=%q",
			h.Get("Authorization"), h.Get("X-Scope-OrgID"))
	}
	if !strings.Contains(logs.String(), "credentials withheld: address differs from -profiling-pyroscope") {
		t.Errorf("transition log does not say the credentials were withheld:\n%s", logs.String())
	}
	if _, _, _, withheld := profilingCredentialsFor(otherSrv.URL); !withheld {
		t.Error("profilingCredentialsFor reports nothing withheld for a foreign address")
	}
}

// TestProfilingSDKErrorsAreCounted: pyroscope.Start never touches the
// network, so a rejecting collector is invisible to Start. The SDK's Errorf
// is where it shows: counted in sdk_errors, kept as last_error, and
// logged once per push.
func TestProfilingSDKErrorsAreCounted(t *testing.T) {
	withProfiling(t)
	withFastUploads(t)
	logs := tapLog(t)
	srv, rec := fakePyroscopeAnswering(t, http.StatusUnauthorized)

	_, st := postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`)
	if !st.Pushing || st.SDKErrors != 0 || st.LastError != "" {
		t.Fatalf("right after start: %+v (Start does not touch the network, so nothing has failed yet)", st)
	}
	deadline := time.Now().Add(10 * time.Second)
	for st.SDKErrors == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		st = getProfiling(t)
	}
	if st.SDKErrors == 0 {
		t.Fatalf("no upload failure counted against a 401 collector after %d ingest attempts", rec.ingests.Load())
	}
	if !st.Pushing || st.LastError == "" {
		t.Errorf("after failures: %+v (pushing must stay true: the SDK is running; last_error must carry the message)", st)
	}
	// Logged once per push, not once per failure.
	deadline = time.Now().Add(3 * time.Second)
	for st.SDKErrors < 2 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		st = getProfiling(t)
	}
	if n := strings.Count(logs.String(), "[profiling] push to "+srv.URL+" failing"); n != 1 {
		t.Errorf("failure logged %d times across %d failures, want exactly 1 (sync.Once per push)", n, st.SDKErrors)
	}
	// A re-target starts a fresh count.
	good, _ := fakePyroscope(t)
	if _, st = postProfiling(t, `{"enabled":true,"server_address":"`+good.URL+`"}`); st.SDKErrors != 0 || st.LastError != "" {
		t.Errorf("after re-target: %+v (counter and error belong to the CURRENT push)", st)
	}
}

// TestProfilingRevertRestoresThePushAddress: the revert target is the whole
// (gate, address) pair. A timed off over a standing push must bring the push
// BACK, to the same address, with a new profiler, and the status reports that
// address in revert_to_address while the window is open.
func TestProfilingRevertRestoresThePushAddress(t *testing.T) {
	withProfiling(t)
	a, _ := fakePyroscope(t)
	postProfiling(t, `{"enabled":true,"server_address":"`+a.URL+`"}`)
	profiling.mu.Lock()
	first := profiling.profiler
	profiling.mu.Unlock()

	_, st := postProfiling(t, `{"enabled":false,"duration":"80ms"}`)
	if st.Enabled || st.Pushing || st.RevertTo == nil || !*st.RevertTo || st.RevertToAddress != a.URL {
		t.Fatalf("timed off: %+v (revert_to_address must name the address the revert restores)", st)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		st = getProfiling(t)
		if st.Pushing && st.ServerAddress == a.URL {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !st.Pushing || st.ServerAddress != a.URL || st.RevertPending {
		t.Fatalf("after the revert: %+v, want pushing to %s with nothing pending", st, a.URL)
	}
	profiling.mu.Lock()
	second := profiling.profiler
	profiling.mu.Unlock()
	if second == nil || second == first {
		t.Error("the revert did not start a NEW profiler for the restored address")
	}
}

// TestProfilingLabel_BirthLabelSurvivesAFunnel pins the nested-label rule:
// pprof.Do restores the labels of the context it was GIVEN, so a goroutine
// labelled at birth keeps its label across a funnel only when it hands the
// funnel its birth context. The control shows the erasure the rule prevents.
func TestProfilingLabel_BirthLabelSurvivesAFunnel(t *testing.T) {
	sm := newTestManager()
	sm.flowBufPool = *testPool()
	fe := newTestFlowExporter(testDevice("10.0.0.2"), flowProfileEdgeRouter, time.Second, time.Second, time.Minute)
	conn := testSender(t)
	defer conn.Close()
	fe.conn.Store(conn)
	fe.writeOverride = func([]byte) error { return nil }

	read := func() string { return labelsOfGoroutineWithFrame(t, "TestProfilingLabel_BirthLabelSurvivesAFunnel") }
	ctx := labelSubsystem(subsystemScenario)
	want := `{"subsystem":"scenario"}`
	if got := read(); got != want {
		t.Fatalf("birth label: %q, want %s", got, want)
	}
	sm.tickFlowExporter(ctx, fe, time.Now())
	if got := read(); got != want {
		t.Errorf("after a funnel given the birth context: %q, want %s", got, want)
	}
	// Control: the erasure this rule exists to prevent.
	sm.tickFlowExporter(context.Background(), fe, time.Now())
	if got := read(); got == want {
		t.Errorf("after a funnel given context.Background(): %q; the control did not erase, so this test cannot detect the regression", got)
	}
	runtimepprof.SetGoroutineLabels(context.Background())
}

// scenarioFlowHarness builds an in-process controller over one flow
// participant whose writes go through writeOverride, the shape of
// TestScenarioIPFIX_CadenceAdaptationDeterministic without synctest.
func scenarioFlowHarness(t *testing.T, write func([]byte) error) (*ScenarioController, *FlowExporter) {
	t.Helper()
	send, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = send.Close() })
	dev := testDevice("10.42.0.1")
	dev.ID = "device-10.42.0.1"
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9}
	p := *flowProfileEdgeRouter
	fe := NewFlowExporter(dev, &p, time.Millisecond, time.Millisecond, time.Hour,
		"127.0.0.1:9", addr, "ipfix", IPFIXEncoder{}, 0)
	fe.conn.Store(send)
	fe.writeOverride = write
	dev.flowExporter = fe
	sm := &SimulatorManager{
		devices: map[string]*DeviceSimulator{dev.ID: dev}, deviceIPs: map[string]struct{}{"10.42.0.1": {}},
		deviceTypesByIP: map[string]string{}, devicesByIP: map[string]*DeviceSimulator{"10.42.0.1": dev},
	}
	sm.flowBufPool.New = func() any { b := make([]byte, 1500); return &b }
	c := newScenarioController(sm, time.Now)
	// rate 5 over a 2 s window: the scenario ticker fires every ~200 ms.
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "ipfix", Rate: 5, Window: 2 * time.Second, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	return c, fe
}

// TestProfilingLabel_ScenarioFlowTicker reads the scenario ticker's label
// BEHAVIOURALLY: the goroutine carries `scenario` at birth, and still does
// after ticks have run through the flow funnel (the nested-label rule).
func TestProfilingLabel_ScenarioFlowTicker(t *testing.T) {
	var ticks atomic.Int64
	c, _ := scenarioFlowHarness(t, func([]byte) error { ticks.Add(1); return nil })
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Stop() })

	// The ticker goroutine is the anonymous func started by startScenarioFlowTicker.
	const tickerFrame = "(*ScenarioController).startScenarioFlowTicker.func"
	wantSubsystemLabel(t, tickerFrame, subsystemScenario)

	deadline := time.Now().Add(5 * time.Second)
	for ticks.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if ticks.Load() < 2 {
		t.Fatal("the scenario flow ticker never wrote")
	}
	// Sample BETWEEN ticks (inside one the funnel's own label is in force):
	// the birth label must have survived the funnel.
	for time.Now().Before(deadline) {
		for _, stanza := range strings.Split(goroutineProfileText(t), "\n\n") {
			if !strings.Contains(stanza, tickerFrame) || strings.Contains(stanza, "tickFlowExporter") {
				continue
			}
			if !strings.Contains(stanza, `# labels: {"subsystem":"scenario"}`) {
				t.Fatalf("the ticker lost its birth label after passing through the flow funnel:\n%s", stanza)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("never sampled the ticker between ticks")
}

// TestProfilingLabel_ScenarioFinish reads finish's label while it is
// blocked joining the flow ticker, which a parked writeOverride holds inside a
// tick.
func TestProfilingLabel_ScenarioFinish(t *testing.T) {
	release := make(chan struct{})
	parked := make(chan struct{})
	var once sync.Once
	c, _ := scenarioFlowHarness(t, func([]byte) error {
		once.Do(func() { close(parked); <-release })
		return nil
	})
	if err := c.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("the scenario flow ticker never wrote")
	}
	done := make(chan struct{})
	go func() { defer close(done); _, _ = c.Stop() }()
	defer func() { close(release); <-done }()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, stanza := range strings.Split(goroutineProfileText(t), "\n\n") {
			if strings.Contains(stanza, "(*ScenarioController).finishLabelled") {
				if !strings.Contains(stanza, `# labels: {"subsystem":"scenario"}`) {
					t.Fatalf("finish runs without the scenario label:\n%s", stanza)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("never observed finish on a goroutine")
}

// TestProfilingOpensNoListenerByConstruction: the feature's two files never
// call anything that opens a socket, so "off by default opens no listener" is
// a property of the code rather than of a runtime observation.
func TestProfilingOpensNoListenerByConstruction(t *testing.T) {
	forbidden := map[string]bool{
		"net.Listen": true, "net.ListenPacket": true, "net.ListenUDP": true, "net.ListenTCP": true,
		"http.ListenAndServe": true, "http.ListenAndServeTLS": true, "http.Serve": true, "http.ServeTLS": true,
	}
	fset := token.NewFileSet()
	for _, name := range []string{"profiling.go", "profiling_api.go"} {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); ok && forbidden[pkg.Name+"."+sel.Sel.Name] {
				t.Errorf("%s: %s.%s opens a socket; the profiling feature must open no listener",
					fset.Position(call.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
}

// ── Second review pass ─────────────────────────────────────────────────────

// TestProfilingBasicAuthParseTable pins parseProfilingBasicAuth: both halves
// are required, because the SDK sends nothing when either is empty.
func TestProfilingBasicAuthParseTable(t *testing.T) {
	user, pass, err := parseProfilingBasicAuth("alice:hunter2")
	if err != nil || user != "alice" || pass != "hunter2" {
		t.Errorf("alice:hunter2 -> %q %q %v", user, pass, err)
	}
	// A password containing a colon keeps everything after the first one.
	if user, pass, err := parseProfilingBasicAuth("alice:hun:ter2"); err != nil || user != "alice" || pass != "hun:ter2" {
		t.Errorf("alice:hun:ter2 -> %q %q %v", user, pass, err)
	}
	for _, bad := range []string{"alice:", ":hunter2", "alicehunter2", "", ":"} {
		if _, _, err := parseProfilingBasicAuth(bad); err == nil {
			t.Errorf("%q accepted; it would push unauthenticated while looking configured", bad)
		}
	}
}

// TestProfilingAddressNormalisation: two spellings of one collector are one
// address for the credential binding.
func TestProfilingAddressNormalisation(t *testing.T) {
	withProfiling(t)
	withProfilingCredentials(t, "alice", "hunter2", "")
	profilingStartupFlag.Store("http://p:4040/")
	for _, same := range []string{"http://p:4040", "http://P:4040", "HTTP://p:4040/", "http://P:4040/"} {
		if _, _, _, withheld := profilingCredentialsFor(same); withheld {
			t.Errorf("%q treated as foreign to the flag address http://p:4040/", same)
		}
	}
	for _, other := range []string{"https://p:4040", "http://p:4041", "http://q:4040", "http://p:4040/pyroscope"} {
		if _, _, _, withheld := profilingCredentialsFor(other); !withheld {
			t.Errorf("%q treated as the flag address http://p:4040/", other)
		}
	}
}

// TestProfilingAdhocEnvRefusedAtPushStart: with the SDK's override variable
// set, a runtime push is refused at start (500, last_error, log) rather than
// pushing somewhere the operator did not name. The boot-time fatal covers
// only a process started WITH -profiling-pyroscope; one that never profiles
// is not stopped by an unrelated tool's environment.
func TestProfilingAdhocEnvRefusedAtPushStart(t *testing.T) {
	withProfiling(t)
	t.Setenv(profilingAdhocEnv, "http://elsewhere:4040")
	logs := tapLog(t)
	srv, rec := fakePyroscopeAnswering(t, http.StatusOK)

	w, st := postProfiling(t, `{"enabled":true,"server_address":"`+srv.URL+`"}`)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("push with %s set: got %d, want 500 (body %q)", profilingAdhocEnv, w.Code, w.Body.String())
	}
	if !st.Enabled || st.Pushing || !strings.Contains(st.LastError, profilingAdhocEnv) {
		t.Errorf("status: %+v", st)
	}
	if !strings.Contains(logs.String(), profilingAdhocEnv) {
		t.Errorf("refusal not logged:\n%s", logs.String())
	}
	if rec.ingests.Load() != 0 {
		t.Error("an upload happened despite the refusal")
	}
	// Pull-only is unaffected: the variable only matters to a push.
	if w, st := postProfiling(t, `{"enabled":true,"server_address":""}`); w.Code != http.StatusOK || !st.Enabled || st.Pushing {
		t.Errorf("pull-only with the variable set: %d %+v", w.Code, st)
	}
}

// TestProfilingServerAddressSemantics pins the three shapes of
// server_address: omitted keeps a REST push, an explicit "" is pull-only even
// with the flag set, and omitted with nothing in force uses the flag.
func TestProfilingServerAddressSemantics(t *testing.T) {
	withProfiling(t)
	flagSrv, _ := fakePyroscope(t)
	restSrv, _ := fakePyroscope(t)
	profilingStartupFlag.Store(flagSrv.URL)

	// Omitted with nothing in force: the flag's address.
	_, st := postProfiling(t, `{"enabled":true}`)
	if !st.Pushing || st.ServerAddress != flagSrv.URL {
		t.Fatalf("omitted, nothing in force: %+v, want the flag's address", st)
	}

	// A REST re-target, then a bare timed on: the REST push is KEPT.
	postProfiling(t, `{"enabled":true,"server_address":"`+restSrv.URL+`"}`)
	_, st = postProfiling(t, `{"enabled":true,"duration":"30m"}`)
	if !st.Pushing || st.ServerAddress != restSrv.URL {
		t.Errorf("omitted while pushing: %+v, want the REST address kept", st)
	}

	// Explicit "" with the flag set: pull-only, the one way to reach it.
	_, st = postProfiling(t, `{"enabled":true,"server_address":""}`)
	if !st.Enabled || st.Pushing || st.ServerAddress != "" {
		t.Errorf("explicit empty: %+v, want pull-only", st)
	}
	if text := goroutineProfileText(t); strings.Contains(text, "pyroscope") {
		t.Error("pull-only left the SDK running")
	}
	// Omitted from pull-only: no address in force, so the flag's again.
	_, st = postProfiling(t, `{"enabled":true}`)
	if !st.Pushing || st.ServerAddress != flagSrv.URL {
		t.Errorf("omitted from pull-only: %+v, want the flag's address", st)
	}
}

// TestProfilingWithSubsystemSkipsARedundantRelabel: a context that already
// carries the label runs the body directly, so the fleet flow ticker (labelled
// flow at birth) allocates no label map per exporter per tick.
func TestProfilingWithSubsystemSkipsARedundantRelabel(t *testing.T) {
	ctx := labelSubsystem(subsystemFlow)
	t.Cleanup(func() { runtimepprof.SetGoroutineLabels(context.Background()) })
	if n := testing.AllocsPerRun(100, func() { withSubsystem(ctx, subsystemFlow, func(context.Context) {}) }); n != 0 {
		t.Errorf("withSubsystem with an already-labelled context allocates %.0f per call, want 0", n)
	}
	// A DIFFERENT label still relabels (the scenario ticker's tick reads flow).
	var inside string
	withSubsystem(labelSubsystem(subsystemScenario), subsystemFlow, func(context.Context) {
		inside = labelsOfGoroutineWithFrame(t, "TestProfilingWithSubsystemSkipsARedundantRelabel")
	})
	if inside != `{"subsystem":"flow"}` {
		t.Errorf("inside a relabel from scenario to flow: %q", inside)
	}
}

// TestProfilingLabel_FleetFlowTicker reads the fleet ticker's birth label
// from the goroutine profile, on the real constructor's ticker.
func TestProfilingLabel_FleetFlowTicker(t *testing.T) {
	sm := NewSimulatorManagerWithOptions(false, WithFlowTickInterval(30*time.Second))
	t.Cleanup(func() { _ = sm.Shutdown() })
	time.Sleep(20 * time.Millisecond)
	wantSubsystemLabel(t, "(*SimulatorManager).startFlowTicker.func", subsystemFlow)
}

// TestProfilingLabel_ScheduledStartInheritsScenario: a goroutine spawned by
// a SCHEDULED start (inside startLocked's funnel, on the timer goroutine)
// inherits subsystem=scenario. The read-back is the scheduler's stop-watch
// goroutine (Run.func1), spawned at the top of SyslogScheduler.Run and never
// running a fire: the scheduler's OWN goroutine carries the inherited label
// only until its first fire, because the syslog funnel restores
// context.Background() on the way out (the documented by-design caveat), so
// it is asserted UNLABELLED here once fires have run.
func TestProfilingLabel_ScheduledStartInheritsScenario(t *testing.T) {
	sm, _ := scenarioTestManager(t, 1)
	c := newScenarioController(sm, time.Now)
	spec := &Scenario{Participants: []string{"10.42.0.1"}, Protocol: "syslog", Rate: 10, Window: 5 * time.Second, Seed: 1}
	if err := c.Submit(spec, "s-000001"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.Arm(); err != nil {
		t.Fatal(err)
	}
	if err := c.ScheduleStart(context.Background(), time.Now().Add(50*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = c.Stop() })
	deadline := time.Now().Add(5 * time.Second)
	for c.Phase() != phaseRunning && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Phase() != phaseRunning {
		t.Fatalf("scheduled start did not run: phase %v", c.Phase())
	}
	wantSubsystemLabel(t, "(*SyslogScheduler).Run.func", subsystemScenario)
	// Rate 10: fires have run by now. The scheduler's own loop goroutine has
	// been through the syslog funnel and reads unlabelled between fires.
	time.Sleep(250 * time.Millisecond)
	for _, stanza := range strings.Split(goroutineProfileText(t), "\n\n") {
		if strings.Contains(stanza, "(*SyslogScheduler).Run+") && strings.Contains(stanza, "# labels:") {
			t.Errorf("the scheduler loop still carries a label after fires; the inherited-label caveat in profiling.go is no longer true:\n%s", stanza)
		}
	}
}

// TestProfilingLabel_TrapInformLoops: the INFORM reader and retry goroutines
// are per device and long-lived, labelled at birth.
func TestProfilingLabel_TrapInformLoops(t *testing.T) {
	mc := newMockCollector(t, true)
	defer mc.Close()
	conn := openTestUDPConn(t)
	e := NewTrapExporter(TrapExporterOptions{
		DeviceIP:  net.IPv4(127, 0, 0, 1),
		Community: "public",
		Mode:      TrapModeInform,
		Collector: mc.addr,
	})
	e.SetConn(conn)
	e.StartBackgroundLoops(context.Background())
	defer e.Close()
	time.Sleep(20 * time.Millisecond)
	wantSubsystemLabel(t, "(*TrapExporter).readerLoop", subsystemTrap)
	wantSubsystemLabel(t, "(*TrapExporter).retryLoop", subsystemTrap)
}
