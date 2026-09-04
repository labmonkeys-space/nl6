/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grafana/pyroscope-go"
)

// profiling_interop_test.go — the check with detection power (nl6#635).
//
// Every other profiling test in the package reads nl6's own handlers with
// nl6's own client. This one pushes to a REAL Pyroscope and is scraped by a
// REAL Grafana Alloy (both started by `make test-interop-pyroscope`), and asks
// Pyroscope's query API what it holds. The nl6#624 lesson applies verbatim:
// an in-process round trip proves nothing about what the collector ingests.
//
// Gated on NL6_PYROSCOPE_INTEROP=1 because no plain `go test` has the
// containers, and gated the nl6#624 way: env unset skips, env set with the
// server unreachable FAILS, because a silent skip asserts nothing.
//
// Three rows, and the third is what makes the first two mean anything:
//
//	1. PUSH:    the SDK pushes under a distinct service_name; the pushed CPU
//	            profile is queryable, and the `subsystem` label is FILTERABLE
//	            (a selector on it returns ticks, a selector on a label nothing
//	            carried returns none).
//	2. SCRAPE:  nl6 serves its router pull-only; Alloy's unmodified default
//	            pyroscope.scrape block plus the godeltaprof endpoints
//	            (examples/pyroscope/alloy-scrape.alloy) scrapes it; Pyroscope
//	            holds process_cpu AND goroutine series for it within 90 s.
//	3. CONTROL: a service_name nothing pushed under returns no ticks. Without
//	            it rows 1-2 prove reachability, not ingestion.

const (
	interopEnvGate       = "NL6_PYROSCOPE_INTEROP"
	interopEnvURL        = "NL6_PYROSCOPE_URL"
	interopEnvScrapeAddr = "NL6_PYROSCOPE_SCRAPE_ADDR"
	interopDefaultURL    = "http://127.0.0.1:4040"
	// interopDefaultScrapeAddr must match the target in
	// examples/pyroscope/alloy-scrape.alloy.
	interopDefaultScrapeAddr = "127.0.0.1:18080"
	// interopScrapeServiceName must match the service_name label in the
	// same file.
	interopScrapeServiceName = "nl6-interop-scrape"
)

// pyroscopeRenderTicks asks the render API for the flame graph of one
// selector and returns its numTicks. A non-200 is returned as an ERROR, not a
// fatal, so a poller can ride out a transient Pyroscope 503 rather than fail
// the CI gate on it.
func pyroscopeRenderTicks(base, profileType, selector string) (int, error) {
	q := url.Values{}
	q.Set("query", profileType+selector)
	q.Set("from", "now-5m")
	q.Set("until", "now")
	q.Set("format", "json")
	resp, err := http.Get(base + "/pyroscope/render?" + q.Encode())
	if err != nil {
		return 0, fmt.Errorf("render %s%s: %w", profileType, selector, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("render %s%s: HTTP %d: %s", profileType, selector, resp.StatusCode, body)
	}
	var out struct {
		Flamebearer struct {
			NumTicks int `json:"numTicks"`
		} `json:"flamebearer"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, fmt.Errorf("render %s%s: body is not the render JSON: %w (%s)", profileType, selector, err, body)
	}
	return out.Flamebearer.NumTicks, nil
}

// mustTicks is pyroscopeRenderTicks for a one-shot read whose failure IS the
// finding.
func mustTicks(t *testing.T, base, profileType, selector string) int {
	t.Helper()
	n, err := pyroscopeRenderTicks(base, profileType, selector)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// waitTicks polls until the selector has ticks or the deadline passes,
// retrying through transient query errors. Returns the last count and the
// last error, so a caller failing on zero can say which it was.
func waitTicks(base, profileType, selector string, within time.Duration) (int, error) {
	deadline := time.Now().Add(within)
	for {
		n, err := pyroscopeRenderTicks(base, profileType, selector)
		if (err == nil && n > 0) || time.Now().After(deadline) {
			return n, err
		}
		time.Sleep(2 * time.Second)
	}
}

// pyroscopeProfileTypes lists the __profile_type__ values Pyroscope holds for
// a selector, through the Connect JSON querier API (the legacy
// /pyroscope/label-values route needs a `name` Pyroscope 2 no longer reads
// from the query string). Used rather than hard-coding type IDs, because the
// SDK and an Alloy scrape name the goroutine profile differently.
func pyroscopeProfileTypes(t *testing.T, base, selector string) []string {
	t.Helper()
	now := time.Now()
	req, _ := json.Marshal(map[string]any{
		"name":     "__profile_type__",
		"matchers": []string{selector},
		"start":    now.Add(-5 * time.Minute).UnixMilli(),
		"end":      now.UnixMilli(),
	})
	resp, err := http.Post(base+"/querier.v1.QuerierService/LabelValues", "application/json", strings.NewReader(string(req)))
	if err != nil {
		t.Fatalf("LabelValues: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("LabelValues: HTTP %d: %s", resp.StatusCode, body)
	}
	var out struct {
		Names []string `json:"names"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("LabelValues: %v (%s)", err, body)
	}
	return out.Names
}

// burnCPU spins until the context ends, so a CPU profile has samples.
func burnCPU(ctx context.Context) {
	x := 0
	for ctx.Err() == nil {
		for i := 0; i < 1<<16; i++ {
			x += i * i
		}
	}
	_ = x
}

func TestPyroscopeInterop(t *testing.T) {
	if os.Getenv(interopEnvGate) != "1" {
		t.Skipf("set %s=1 (via `make test-interop-pyroscope`) to run the Pyroscope + Alloy interop check", interopEnvGate)
	}
	base := os.Getenv(interopEnvURL)
	if base == "" {
		base = interopDefaultURL
	}
	base = strings.TrimRight(base, "/")
	if resp, err := http.Get(base + "/ready"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("%s=1 but Pyroscope at %s is not ready: err=%v", interopEnvGate, base, err)
	}

	cpuType := "process_cpu:cpu:nanoseconds:cpu:nanoseconds"

	// ── Row 1: PUSH ─────────────────────────────────────────────────────────
	pushService := fmt.Sprintf("nl6-interop-%d", os.Getpid())
	cfg := newProfilerConfig(base)
	cfg.ApplicationName = pushService
	cfg.UploadRate = 2 * time.Second
	p, err := pyroscope.Start(cfg)
	if err != nil {
		t.Fatalf("pyroscope.Start: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	withSubsystem(ctx, "interop-probe", func(ctx context.Context) { burnCPU(ctx) })
	cancel()
	if err := p.Stop(); err != nil {
		t.Fatalf("profiler Stop: %v", err)
	}

	sel := func(service string, kv ...string) string {
		parts := []string{fmt.Sprintf(`service_name=%q`, service)}
		for i := 0; i+1 < len(kv); i += 2 {
			parts = append(parts, fmt.Sprintf(`%s=%q`, kv[i], kv[i+1]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	if n, err := waitTicks(base, cpuType, sel(pushService), 30*time.Second); n == 0 {
		t.Fatalf("row 1: Pyroscope holds no CPU ticks for %s after the push (last error: %v)", sel(pushService), err)
	}
	if n, err := waitTicks(base, cpuType, sel(pushService, "subsystem", "interop-probe"), 30*time.Second); n == 0 {
		t.Errorf("row 1: the subsystem label is not filterable: %s has no ticks (last error: %v)",
			sel(pushService, "subsystem", "interop-probe"), err)
	}
	if n := mustTicks(t, base, cpuType, sel(pushService, "subsystem", "no-such-label")); n != 0 {
		t.Errorf("row 1: a selector on a label nothing carried returned %d ticks; the label filter is not selective", n)
	}
	// The heap profiles pushed too: find the alloc_space type among what
	// Pyroscope holds for the service, then require ticks on it.
	allocType := ""
	for _, pt := range pyroscopeProfileTypes(t, base, sel(pushService)) {
		if strings.HasPrefix(pt, "memory:alloc_space:") {
			allocType = pt
		}
	}
	if allocType == "" {
		t.Errorf("row 1: no memory:alloc_space profile type for %s; Pyroscope holds %v",
			sel(pushService), pyroscopeProfileTypes(t, base, sel(pushService)))
	} else if n, err := waitTicks(base, allocType, sel(pushService), 30*time.Second); n == 0 {
		t.Errorf("row 1: %s has no ticks for %s (last error: %v)", allocType, sel(pushService), err)
	}

	// ── Row 3: CONTROL (before row 2, so a slow scrape cannot mask it) ───────
	control := fmt.Sprintf(`{service_name="nl6-interop-control-%d"}`, os.Getpid())
	if n := mustTicks(t, base, cpuType, control); n != 0 {
		t.Fatalf("row 3: control selector %s returned %d ticks; the query API is not selective, so rows 1-2 prove nothing", control, n)
	}

	// ── Row 2: SCRAPE ──────────────────────────────────────────────────────
	withProfiling(t)
	scrapeAddr := os.Getenv(interopEnvScrapeAddr)
	if scrapeAddr == "" {
		scrapeAddr = interopDefaultScrapeAddr
	}
	ln, err := net.Listen("tcp", scrapeAddr)
	if err != nil {
		t.Fatalf("listen %s for the Alloy scrape: %v", scrapeAddr, err)
	}
	srv := &http.Server{Handler: setupRoutes(), ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	if _, err := setProfiling(true, "", 0); err != nil {
		t.Fatal(err)
	}
	// Keep the process busy so the 14 s CPU scrape has samples, and do it
	// UNDER A LABEL, because row 2 also answers whether pprof labels survive
	// an Alloy scrape (they are sample labels inside the pprof body, so they
	// should; this is the measurement rather than the assumption).
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	go withSubsystem(ctx, "interop-probe", func(ctx context.Context) { burnCPU(ctx) })

	scrapeSel := sel(interopScrapeServiceName)
	deadline := time.Now().Add(90 * time.Second)
	var haveCPU, haveGoroutine bool
	for time.Now().Before(deadline) && !(haveCPU && haveGoroutine) {
		for _, pt := range pyroscopeProfileTypes(t, base, scrapeSel) {
			if n, err := pyroscopeRenderTicks(base, pt, scrapeSel); err != nil || n == 0 {
				continue
			}
			if strings.HasPrefix(pt, "process_cpu:") {
				haveCPU = true
			}
			if strings.HasPrefix(pt, "goroutine") {
				haveGoroutine = true
			}
		}
		if !(haveCPU && haveGoroutine) {
			time.Sleep(3 * time.Second)
		}
	}
	if !haveCPU {
		t.Errorf("row 2: no process_cpu series with ticks for %s within 90 s of the Alloy scrape", scrapeSel)
	}
	if !haveGoroutine {
		t.Errorf("row 2: no goroutine series with ticks for %s within 90 s of the Alloy scrape", scrapeSel)
	}
	if haveCPU {
		// Labels through the scrape path: the probe's label must be filterable
		// on the SCRAPED service, and a label nothing carried must match
		// nothing.
		if n, err := waitTicks(base, cpuType, sel(interopScrapeServiceName, "subsystem", "interop-probe"), 45*time.Second); n == 0 {
			t.Errorf("row 2: pprof labels did not survive the Alloy scrape: %s has no ticks (last error: %v)",
				sel(interopScrapeServiceName, "subsystem", "interop-probe"), err)
		}
		if n := mustTicks(t, base, cpuType, sel(interopScrapeServiceName, "subsystem", "no-such-label")); n != 0 {
			t.Errorf("row 2: a bogus label matched %d ticks on the scraped service", n)
		}
	}
	if t.Failed() {
		t.Logf("profile types Pyroscope holds for %s: %v", scrapeSel, pyroscopeProfileTypes(t, base, scrapeSel))
	}
}

// TestAlloyScrapeConfigMatchesTheInteropTest pins the two values the interop
// row and the checked-in Alloy config must agree on: the scrape target the
// test listens on and the service_name it queries for. A drift here would
// make row 2 fail against a healthy stack, or pass against nothing.
func TestAlloyScrapeConfigMatchesTheInteropTest(t *testing.T) {
	cfg, err := os.ReadFile("../../examples/pyroscope/alloy-scrape.alloy")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"` + interopDefaultScrapeAddr + `"`,
		`"service_name" = "` + interopScrapeServiceName + `"`,
		"profile.godeltaprof_memory",
		"profile.godeltaprof_mutex",
		"profile.godeltaprof_block",
	} {
		if !strings.Contains(string(cfg), want) {
			t.Errorf("alloy-scrape.alloy does not contain %s", want)
		}
	}
}
