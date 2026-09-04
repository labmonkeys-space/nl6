/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/pprof"
	"net/url"
	"os"
	runtimepprof "runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/grafana/pyroscope-go"
	deltapprof "github.com/grafana/pyroscope-go/godeltaprof/http/pprof"
)

// profiling.go — continuous profiling behind ONE gate, off by default (nl6#635).
//
// Two things live here and in profiling_api.go and nowhere else, so the whole
// feature is two files, three go.mod lines (pyroscope-go, its godeltaprof
// submodule, and klauspost/compress as their indirect), and deletable in one
// commit:
//
//   - the gate. `enabled` is the switch; `server_address` (flag or POST body)
//     decides whether the pyroscope-go SDK PUSHES as well. With the gate
//     closed nothing runs: no profiler goroutine, no outbound connection, and
//     /debug/pprof/* answers 503. With it open and no address, the process is
//     scrapeable (pull-only) by an Alloy `pyroscope.scrape` block. With an
//     address it also pushes. Pull-only exists because the Go runtime allows
//     ONE CPU profile at a time, so an operator who wants Alloy to scrape CPU
//     needs the push collector off.
//
//   - the labels. Every subsystem entry point tags its goroutine (or its fire,
//     through pprof.Do) with `subsystem=<name>`, so a CPU profile can be
//     filtered per subsystem. Labels are set UNCONDITIONALLY, whether or not
//     profiling is on: a goroutine label is a pointer swap, and pprof.Do on a
//     shared scheduler goroutine is one small map per fire. Re-labelling live
//     goroutines on toggle would need every long-lived loop to poll the gate,
//     which costs more than the label. So "off by default pays nothing" reads
//     as "pays a label", and docs/ops/profiling.md says so.
//
// The runtime toggle copies fidelity_api.go's shape exactly (one timer that
// supersedes, a generation counter so a fired-but-blocked callback recognises
// it is stale, chain-aware restore). Read that file's comments for the WHY of
// each of those; they are not restated here.
//
// NOT set here, by decision: runtime.SetMutexProfileFraction and
// runtime.SetBlockProfileRate. Mutex and block profiles ship OFF until their
// cost is measured; TestProfilingRuntimeGlobalsStayZero pins that both read 0
// before, during and after a cycle, so a later change that sets them inside
// the on-branch has to restore them on stop.

// Subsystem label values. One key, seven values, matching the subsystem names
// an operator already knows from the status endpoints.
const (
	subsystemLabelKey = "subsystem"

	subsystemSNMP        = "snmp"
	subsystemTrap        = "trap"
	subsystemSyslog      = "syslog"
	subsystemFlow        = "flow"
	subsystemGNMI        = "gnmi"
	subsystemGNMIDialout = "gnmi-dialout"
	subsystemScenario    = "scenario"
)

// profilingPprofPath is where the gated net/http/pprof surface is mounted, on
// the ROOT router rather than under /api/v1, so Alloy's default scrape paths
// resolve without configuration.
const profilingPprofPath = "/debug/pprof/"

// profilingApplicationName is the Pyroscope service_name for a pushing nl6.
const profilingApplicationName = "nl6"

// profilingStartupFlag records what -profiling-pyroscope was set to at
// process start (a string; empty when the flag was not given). Written once
// during flag parsing, read by the status handler and as the default push
// address for a runtime `{"enabled":true}` with no address of its own. Kept
// separate from the value in force so the two can diverge and be reported
// as diverging (the fidelity_api.go rule).
var profilingStartupFlag atomic.Value // string

// profilingGateOpen is the gate the HTTP wrapper reads on every /debug/pprof
// request. It mirrors profiling.enabled and is an atomic so the request path
// takes no lock.
var profilingGateOpen atomic.Bool

// Flag-only settings. Basic-auth and the tenant are deliberately NOT settable
// over REST: GET /api/v1/profiling echoes the REST-settable state, so a
// REST-settable secret would be a secret the API prints (nl6#93's ca_pem
// lesson in reverse). Force-GC is startup-only because its default is a
// measured number (see docs/ops/profiling.md), not an operator preference.
var (
	profilingBasicAuthUser     string
	profilingBasicAuthPassword string
	profilingTenantID          string
	profilingForceGC           = profilingForceGCDefault
)

// profilingForceGCDefault is the -profiling-force-gc default, SET FROM A
// MEASUREMENT rather than chosen. The rule was pre-registered in the spec so
// the number could not be picked after the fact: run
// BenchmarkForcedGCOnFleetHeap; if one runtime.GC() on a heap built from
// N=5000 TUN-less devices, extrapolated linearly to 30,000, exceeds 150 ms
// (1% of one core per 15 s upload window), the default is false
// (DisableGCRuns: true); otherwise true (the SDK default).
//
// Measured on an Apple M1 Max (darwin/arm64, Go 1.27.0, 3 runs of
// -benchtime=5x), asr9k profile: N=1000 -> 1.0-1.5 ms/GC on a 16.7 MiB live
// heap, N=5000 -> 4.3-5.8 ms/GC on 78.5 MiB. Linear from the N=5000 median
// (4.8 ms): ~29 ms at 30,000, worst run ~35 ms. Well under the 150 ms line,
// so the SDK default stands. It is an in-process proxy (no sockets, TUN or
// namespace on the heap); the figures and the extrapolation are recorded in
// docs/ops/profiling.md, and the fleet-scale VM measurement is listed in that
// page's "Follow-ups" section.
const profilingForceGCDefault = true

// profilingUploadTimeout bounds one profile upload. A profile is ~100 KB;
// 10 s is generous.
const profilingUploadTimeout = 10 * time.Second

// profilingFlushBound is how long a stop waits for the SDK to flush its last
// profiles before abandoning the flush: two upload timeouts, because a flush
// is a final CPU/heap snapshot followed by the queued uploads, and one timeout
// covers one upload. This is the ceiling on an off POST, the revert callback
// and Shutdown against a dead collector.
const profilingFlushBound = 2 * profilingUploadTimeout

// profilingAdhocEnv is the environment variable the SDK reads in
// pyroscope.Start to REPLACE ServerAddress silently. nl6 refuses to run with
// it set: an address the operator did not configure would be echoed by
// nothing and honoured by everything, the nl6#445 accepted-echoed-ignored
// shape in reverse.
const profilingAdhocEnv = "PYROSCOPE_ADHOC_SERVER_ADDRESS"

// pyroscopeStart is the SDK entry point behind a seam (the writeOverride
// pattern), so a Start failure can be driven in a test without depending on
// the SDK's deprecated cloud-token check.
var pyroscopeStart = pyroscope.Start

// subsystemContexts holds one labelled context per shipped subsystem name,
// built once: SetGoroutineLabels needs only the pointer, so a per-device
// goroutine labelling itself at birth allocates nothing.
var subsystemContexts = func() map[string]context.Context {
	m := make(map[string]context.Context)
	for _, name := range []string{subsystemSNMP, subsystemTrap, subsystemSyslog, subsystemFlow,
		subsystemGNMI, subsystemGNMIDialout, subsystemScenario} {
		m[name] = runtimepprof.WithLabels(context.Background(), runtimepprof.Labels(subsystemLabelKey, name))
	}
	return m
}()

// parseProfilingBasicAuth splits -profiling-pyroscope-basic-auth. BOTH halves
// must be non-empty: the SDK sends Basic auth only when both are set, so
// `user:` would push unauthenticated while looking configured.
func parseProfilingBasicAuth(s string) (user, pass string, err error) {
	user, pass, ok := strings.Cut(s, ":")
	if !ok || user == "" || pass == "" {
		return "", "", errors.New("-profiling-pyroscope-basic-auth must be user:pass with both parts " +
			"non-empty (the SDK sends no Authorization header when either is empty)")
	}
	return user, pass, nil
}

// normaliseProfilingAddress reduces an already-validated push URL to the form
// two spellings of one collector share: lowercased scheme and host, path with
// its trailing slash trimmed. So http://P:4040/ and http://p:4040 are the same
// address for the credential binding.
func normaliseProfilingAddress(addr string) string {
	u, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.Path, "/")
}

// profilingTarget is a (gate, push address) pair: the unit the revert timer
// restores. An address is meaningful only with the gate open; a closed gate
// carries an empty address.
type profilingTarget struct {
	enabled bool
	addr    string
}

// profilingLifecycle serialises every MUTATION of the profiling state (the
// POST handler, the revert callback, the boot path and Shutdown), and is held
// across the SDK stop that runs AFTER profiling.mu is released. Lock order is
// profilingLifecycle -> profiling.mu, never the reverse.
//
// Why two locks: Profiler.Stop flushes the last upload through the HTTP
// client, bounded by profilingUploadTimeout, and doing that under profiling.mu
// parked every GET behind a dead collector. So profiling.mu now covers only
// the state, and the stop runs outside it. The lifecycle mutex is what keeps
// a concurrent start from racing that stop: without it a second POST could
// start a new profiler while the old one was still flushing.
var profilingLifecycle sync.Mutex

// profiling is the process-global profiling state. Process-global rather than
// manager state for the fidelity reason: the SDK profiles the PROCESS, and
// Shutdown stops it beside cancelFidelityRevert().
var profiling struct {
	mu sync.Mutex
	// enabled is the gate in force. serverAddress is the push address in
	// force, empty for pull-only. profiler is non-nil while the SDK pushes.
	enabled       bool
	serverAddress string
	profiler      *pyroscope.Profiler
	// transport is the profiler's own HTTP transport, so stopping can close
	// its idle connections: the SDK's default transport keeps them open
	// forever, each holding two goroutines, which is what "no profiler
	// goroutine remains" would otherwise trip over.
	transport *http.Transport
	// uploads is the current push's error sink (see profilerLogger). Replaced
	// on every start, so its counter and message describe THIS push.
	uploads *profilerLogger
	// lastError is the most recent Start failure, cleared by the next
	// successful transition. Reported so `enabled:true, pushing:false` is
	// explained rather than mysterious.
	lastError string

	// The revert machinery, fidelity_api.go's shape. See that file.
	timer    *time.Timer
	restore  profilingTarget
	deadline time.Time
	gen      uint64
}

// profilingSnapshot is the state as it was when a request committed, captured
// under the lock (the fidelitySnapshot rule: handlers must not re-read the
// globals, a concurrent toggle would produce a composite of two states).
type profilingSnapshot struct {
	enabled   bool
	addr      string
	pushing   bool
	lastError string
	sdkErrors uint64
	pending   bool
	deadline  time.Time
	revertTo  profilingTarget
}

// profilerLogger is the SDK's Logger for one push. pyroscope.Start never
// touches the network, so a collector that is down, answers 401, or rejects
// the tenant is invisible to Start: the SDK reports it through Errorf from
// its upload goroutines, and with the no-op logger it reported it to nobody.
// Errorf counts every error the SDK reports (a failed upload, a refused CPU
// collector, a full upload queue), keeps the latest message for GET, and logs
// the FIRST one per push (the logFirstEncodeErr convention: ungated, a dead
// collector is one line per profile type per upload interval, forever). Infof
// and Debugf are discarded.
//
// Lock-free on purpose: Errorf runs on SDK goroutines, and the one place nl6
// calls into the SDK under profiling.mu is Start, so a logger that took that
// lock could deadlock if the SDK ever logged synchronously from Start.
type profilerLogger struct {
	addr     string
	failures atomic.Uint64
	last     atomic.Value // string
	once     sync.Once
}

func (l *profilerLogger) Infof(string, ...interface{})  {}
func (l *profilerLogger) Debugf(string, ...interface{}) {}
func (l *profilerLogger) Errorf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	l.failures.Add(1)
	l.last.Store(msg)
	l.once.Do(func() {
		log.Printf("[profiling] push to %s failing: %s (first occurrence; later ones are counted in "+
			"sdk_errors on GET /api/v1/profiling, not logged)", l.addr, msg)
	})
}

// lastMessage is the latest upload error, or "" when none.
func (l *profilerLogger) lastMessage() string {
	if l == nil {
		return ""
	}
	m, _ := l.last.Load().(string)
	return m
}

// validateProfilingAddress accepts an http:// or https:// URL with a host and
// no embedded credentials. Anything else is refused: the flag fatals at
// startup, the POST body 400s.
func validateProfilingAddress(addr string) error {
	u, err := url.Parse(addr)
	if err != nil {
		return fmt.Errorf("%q is not a URL: %v", addr, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%q must use http:// or https:// (scheme %q is not supported)", addr, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%q has no host", addr)
	}
	// net/http would send userinfo as Basic auth, and the address is echoed
	// by GET, by startup_flag and by every transition log line.
	if u.User != nil {
		return fmt.Errorf("%q must not embed credentials; use -profiling-pyroscope-basic-auth", u.Redacted())
	}
	// The SDK appends /ingest?... to the address; a query or fragment would
	// be silently mangled.
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("%q must not carry a query or fragment (the SDK appends /ingest to it)", addr)
	}
	return nil
}

// validateProfilingEnvironment refuses to start with the SDK's override
// variable set (see profilingAdhocEnv). Checked in main beside the flags.
func validateProfilingEnvironment(lookup func(string) (string, bool)) error {
	if _, set := lookup(profilingAdhocEnv); set {
		return fmt.Errorf("%s is set; nl6 refuses it because it would override "+
			"-profiling-pyroscope silently; unset it", profilingAdhocEnv)
	}
	return nil
}

// profilingCredentialsFor returns the flag credentials for a push to addr,
// and whether they were WITHHELD. They are bound to the flag's own address:
// a REST-supplied server_address that differs gets none, because otherwise an
// unauthenticated POST could redirect heap profiles plus the operator's Basic
// auth to any host. With no credentials configured nothing is withheld.
func profilingCredentialsFor(addr string) (user, pass, tenant string, withheld bool) {
	configured := profilingBasicAuthUser != "" || profilingTenantID != ""
	if !configured {
		return "", "", "", false
	}
	flag, _ := profilingStartupFlag.Load().(string)
	if flag == "" || normaliseProfilingAddress(addr) != normaliseProfilingAddress(flag) {
		return "", "", "", true
	}
	return profilingBasicAuthUser, profilingBasicAuthPassword, profilingTenantID, false
}

// newProfilerConfig builds the SDK configuration for a push to addr. The six
// shipped profile types are CPU, goroutines and the four heap views; mutex
// and block are NOT listed, because their runtime globals are not set (see
// the file comment). DisableGCRuns follows -profiling-force-gc. Credentials
// follow profilingCredentialsFor.
func newProfilerConfig(addr string) pyroscope.Config {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown"
	}
	user, pass, tenant, _ := profilingCredentialsFor(addr)
	return pyroscope.Config{
		ApplicationName: profilingApplicationName,
		ServerAddress:   addr,
		Tags: map[string]string{
			"version":  Version,
			"hostname": host,
		},
		ProfileTypes: []pyroscope.ProfileType{
			pyroscope.ProfileCPU,
			pyroscope.ProfileGoroutines,
			pyroscope.ProfileAllocObjects,
			pyroscope.ProfileAllocSpace,
			pyroscope.ProfileInuseObjects,
			pyroscope.ProfileInuseSpace,
		},
		DisableGCRuns:     !profilingForceGC,
		BasicAuthUser:     user,
		BasicAuthPassword: pass,
		TenantID:          tenant,
	}
}

// newProfilerTransport is the transport the profiler uploads through. It is
// ours rather than the SDK's so a stop can close its idle connections. The
// connection caps mirror the SDK's five upload threads (idle matched to max,
// so a burst does not churn connections); the timeout and the no-redirect
// rule live on the http.Client in startProfilerLocked.
func newProfilerTransport() *http.Transport {
	return &http.Transport{
		MaxConnsPerHost:     5,
		MaxIdleConnsPerHost: 5,
		IdleConnTimeout:     30 * time.Second,
	}
}

// startProfilerLocked starts a push to addr. Caller holds profiling.mu.
func startProfilerLocked(addr string) error {
	// The SDK would replace addr from this variable inside Start, silently.
	// Refused HERE rather than only at boot, so a process that never enables
	// profiling is not stopped by an unrelated tool's environment.
	if err := validateProfilingEnvironment(os.LookupEnv); err != nil {
		return err
	}
	cfg := newProfilerConfig(addr)
	tr := newProfilerTransport()
	cfg.HTTPClient = &http.Client{
		Transport: tr,
		Timeout:   profilingUploadTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	logger := &profilerLogger{addr: addr}
	cfg.Logger = logger
	p, err := pyroscopeStart(cfg)
	if err != nil {
		tr.CloseIdleConnections()
		return err
	}
	profiling.profiler = p
	profiling.transport = tr
	profiling.uploads = logger
	return nil
}

// detachProfilerLocked takes the running push OUT of the state and returns
// the function that stops it. Caller holds profiling.mu; the returned stop
// MUST run after the lock is released (it flushes the last upload, bounded by
// profilingUploadTimeout) and under profilingLifecycle. A no-op when nothing
// pushes.
func detachProfilerLocked() func() {
	p, tr := profiling.profiler, profiling.transport
	profiling.profiler, profiling.transport, profiling.uploads = nil, nil, nil
	if p == nil {
		return func() {}
	}
	return func() {
		// Profiler.Stop alone does NOT flush: session.Stop takes the stopCh
		// path (stops the CPU collector, uploads nothing) and Remote.Stop
		// closes `done`, after which handleJobs may drop a queued job. So
		// Flush(true) first, which takes a final snapshot and waits for the
		// uploads, then Stop. Bounded, because Flush against a dead
		// collector waits through the upload timeout per queued job.
		done := make(chan struct{})
		go func() {
			defer close(done)
			p.Flush(true)
			if err := p.Stop(); err != nil {
				log.Printf("[profiling] stop: %v", err)
			}
			if tr != nil {
				tr.CloseIdleConnections()
			}
		}()
		select {
		case <-done:
		case <-time.After(profilingFlushBound):
			log.Printf("[profiling] flush abandoned after %s; the last profiles may not have reached the collector", profilingFlushBound)
		}
	}
}

// cancelProfilingRevertLocked stops any pending revert. Caller holds the
// mutex. The generation bump is unconditional for the fidelity reason: a
// callback that already fired may be waiting on the mutex right now.
func cancelProfilingRevertLocked() {
	if profiling.timer != nil {
		profiling.timer.Stop()
		profiling.timer = nil
	}
	profiling.deadline = time.Time{}
	profiling.gen++
}

// applyLocked moves the state to `to`, starting the SDK as the difference
// requires, and logs the transition. Caller holds profiling.mu AND
// profilingLifecycle. It returns the stop of any push it detached, which the
// caller runs after releasing profiling.mu.
//
// The one deliberate asymmetry: a Start failure leaves the gate OPEN with no
// profiler and records the error. The operator asked for profiling; the pull
// surface can still serve, and GET explains why nothing is pushing.
func applyLocked(to profilingTarget, d time.Duration, reason string) (stop func(), err error) {
	from := profilingTarget{enabled: profiling.enabled, addr: profiling.serverAddress}
	pushing := profiling.profiler != nil
	stop = func() {}

	switch {
	case !to.enabled:
		stop = detachProfilerLocked()
		profiling.enabled = false
		profiling.serverAddress = ""
		profiling.lastError = ""
	case from == to && (to.addr == "" || pushing):
		// Idempotent: same gate, same address, and the push (if any) is
		// actually running. No second Start, no second profiler.
	default:
		if pushing && from.addr != to.addr {
			stop = detachProfilerLocked()
		}
		profiling.enabled = true
		profiling.serverAddress = to.addr
		profiling.lastError = ""
		if to.addr != "" && profiling.profiler == nil {
			if err = startProfilerLocked(to.addr); err != nil {
				profiling.lastError = err.Error()
			}
		}
	}
	profilingGateOpen.Store(profiling.enabled)
	logProfilingTransition(from, to, d, reason, err)
	return stop, err
}

// logProfilingTransition leaves a trace of every runtime change, including an
// arming that changes no value (the fidelity lesson: the window matters even
// when the value does not).
func logProfilingTransition(from, to profilingTarget, d time.Duration, reason string, err error) {
	describe := func(t profilingTarget) string {
		switch {
		case !t.enabled:
			return "off"
		case t.addr == "":
			return "on (pull-only: /debug/pprof/ served, nothing pushed)"
		default:
			return "on, pushing to " + t.addr
		}
	}
	msg := "[profiling] " + describe(to)
	if from == to {
		msg += " (unchanged)"
	} else {
		msg += " (was " + describe(from) + ")"
	}
	if err != nil {
		msg += fmt.Sprintf("; push NOT started: %v", err)
	}
	if to.enabled && to.addr != "" {
		if _, _, _, withheld := profilingCredentialsFor(to.addr); withheld {
			msg += "; credentials withheld: address differs from -profiling-pyroscope"
		}
	}
	if d > 0 {
		msg += fmt.Sprintf(", auto-reverting in %s", d)
	}
	if reason != "" {
		msg += " [" + reason + "]"
	}
	log.Print(msg)
}

// snapshotLocked captures the state under the lock.
func snapshotLocked() profilingSnapshot {
	deadline := profiling.deadline
	// An already-fired callback clears `timer` only after it wins the mutex,
	// so a reader landing in that gap would otherwise report a pending revert
	// whose time has passed.
	pending := profiling.timer != nil && deadline.After(time.Now())
	snap := profilingSnapshot{
		enabled:   profiling.enabled,
		addr:      profiling.serverAddress,
		pushing:   profiling.profiler != nil,
		lastError: profiling.lastError,
		pending:   pending,
		deadline:  deadline,
		revertTo:  profiling.restore,
	}
	if u := profiling.uploads; u != nil {
		snap.sdkErrors = u.failures.Load()
		if snap.lastError == "" {
			snap.lastError = u.lastMessage()
		}
	}
	return snap
}

// profilingSnapshotNow is the status read, for GET. It takes profiling.mu
// only, so a GET never waits behind a stop flushing to a dead collector.
func profilingSnapshotNow() profilingSnapshot {
	profiling.mu.Lock()
	defer profiling.mu.Unlock()
	return snapshotLocked()
}

// setProfiling applies a gate value and, when d > 0, arms a revert. addr is
// the push address to use when enabling: nil (omitted) keeps the address in
// force if one is, else the startup flag's, else pull-only, so a bare
// `{"enabled":true,"duration":"30m"}` on a pushing process keeps pushing; an
// explicit "" is pull-only even when the flag is set, which is the only way
// to reach pull-only once a flag was given. Returns the state as committed,
// plus the Start error if the push could not begin. Any push it stopped has
// finished flushing (or been abandoned after profilingFlushBound) by the time
// it returns.
func setProfiling(enabled bool, addr *string, d time.Duration) (profilingSnapshot, error) {
	profilingLifecycle.Lock()
	defer profilingLifecycle.Unlock()
	profiling.mu.Lock()

	// Supersede rather than stack (fidelity_api.go).
	hadPending := profiling.timer != nil
	cancelProfilingRevertLocked()

	// Chain-aware restore: same direction keeps the destination, a direction
	// change starts a new chain (fidelity_api.go explains both halves).
	sameDirection := hadPending && enabled == profiling.enabled
	if !sameDirection {
		profiling.restore = profilingTarget{enabled: profiling.enabled, addr: profiling.serverAddress}
	}

	to := profilingTarget{enabled: enabled}
	if enabled {
		switch {
		case addr != nil:
			to.addr = *addr
		case profiling.enabled && profiling.serverAddress != "":
			to.addr = profiling.serverAddress
		default:
			to.addr, _ = profilingStartupFlag.Load().(string)
		}
	}
	stop, err := applyLocked(to, d, "")

	if d <= 0 {
		// A standing change: there is no chain left to return to.
		profiling.restore = profilingTarget{enabled: profiling.enabled, addr: profiling.serverAddress}
	} else {
		restore := profiling.restore
		deadline := time.Now().Add(d)
		profiling.deadline = deadline
		gen := profiling.gen
		profiling.timer = time.AfterFunc(d, func() { revertProfiling(gen, restore, d) })
	}
	snap := snapshotLocked()
	profiling.mu.Unlock()
	stop()
	return snap, err
}

// revertProfiling is the timer callback: restore the pre-chain target unless
// superseded (the generation counter, fidelity_api.go).
func revertProfiling(gen uint64, restore profilingTarget, after time.Duration) {
	profilingLifecycle.Lock()
	defer profilingLifecycle.Unlock()
	profiling.mu.Lock()
	if profiling.gen != gen {
		// Superseded or cancelled while this callback waited for the lock.
		profiling.mu.Unlock()
		return
	}
	profiling.timer = nil
	profiling.deadline = time.Time{}
	stop, err := applyLocked(restore, 0, fmt.Sprintf("auto-revert after %s", after))
	profiling.mu.Unlock()
	stop()
	if err != nil {
		log.Printf("[profiling] auto-revert: %v", err)
	}
}

// stopProfiling is the Shutdown hook: drop any pending revert and stop the
// SDK, flushing its last upload (bounded by profilingUploadTimeout). Safe when
// profiling was never enabled.
func stopProfiling() {
	profilingLifecycle.Lock()
	defer profilingLifecycle.Unlock()
	profiling.mu.Lock()
	cancelProfilingRevertLocked()
	if !profiling.enabled && profiling.profiler == nil {
		profiling.mu.Unlock()
		return
	}
	stop, err := applyLocked(profilingTarget{}, 0, "shutdown")
	profiling.mu.Unlock()
	stop()
	if err != nil {
		log.Printf("[profiling] shutdown: %v", err)
	}
}

// startProfilingFromFlag is the boot path for -profiling-pyroscope. The
// address was validated before any subsystem started. pyroscope.Start never
// touches the network, so a collector that is down at boot is not a Start
// failure: it surfaces as upload_failures and last_error on GET, and as one
// log line per push (profilerLogger). The pull surface serves regardless.
func startProfilingFromFlag(addr string) {
	profilingStartupFlag.Store(addr)
	if addr == "" {
		return
	}
	if _, err := setProfiling(true, &addr, 0); err != nil {
		log.Printf("[profiling] -profiling-pyroscope %s: push not started: %v", addr, err)
	}
}

// errProfilingOff is the gate's refusal, worded so the operator knows what to
// do next rather than what went wrong.
var errProfilingOff = errors.New("profiling is off; enable it with POST /api/v1/profiling " +
	`{"enabled":true} (add "server_address" to push to Pyroscope, set it to "" for scrape-only), ` +
	"or boot with -profiling-pyroscope")

// profilingGate refuses every request while the gate is closed. It wraps the
// whole pprof mux, so no path under /debug/pprof/ is reachable "for
// convenience" while profiling is off.
func profilingGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !profilingGateOpen.Load() {
			sendErrorResponse(w, errProfilingOff.Error(), http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newPprofHandler builds the gated /debug/pprof/ surface: net/http/pprof's
// index, profile, symbol and trace, the named runtime profiles, and
// godeltaprof's delta_heap / delta_block / delta_mutex for an Alloy scrape.
//
// NOT cmdline: it prints os.Args, which carries
// -profiling-pyroscope-basic-auth user:pass, and Alloy never scrapes it. It
// answers 404 (pinned).
//
// The handlers are referenced BY NAME rather than through the blank import,
// but importing the package still registers them on http.DefaultServeMux in
// its init(). That is inert only because nl6 serves its own mux.Router
// (simulator.go), and TestProfilingDefaultServeMuxIsNeverServed is what keeps
// it inert.
func newPprofHandler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc(profilingPprofPath, pprof.Index)
	m.HandleFunc(profilingPprofPath+"profile", pprof.Profile)
	m.HandleFunc(profilingPprofPath+"symbol", pprof.Symbol)
	m.HandleFunc(profilingPprofPath+"trace", pprof.Trace)
	for _, name := range []string{"heap", "allocs", "goroutine", "threadcreate", "block", "mutex"} {
		m.Handle(profilingPprofPath+name, pprof.Handler(name))
	}
	m.HandleFunc(profilingPprofPath+"delta_heap", deltapprof.Heap)
	m.HandleFunc(profilingPprofPath+"delta_block", deltapprof.Block)
	m.HandleFunc(profilingPprofPath+"delta_mutex", deltapprof.Mutex)
	return profilingGate(m)
}

// labelSubsystem tags the CURRENT goroutine for the rest of its life and
// returns the labelled context. For long-lived per-device goroutines (the
// SNMP read loop, a dial-out run loop, a scenario's flow ticker): called once
// at loop start, never per datagram.
//
// KEEP THE RETURNED CONTEXT AND PASS IT TO EVERY FUNNEL THE GOROUTINE CALLS.
// pprof.Do restores the labels of the context it was GIVEN when the body
// returns, not the goroutine's previous labels, so a funnel called with
// context.Background() erases a birth label on its way out. That is why
// tickFlowExporter takes a context and why the scenario ticker hands it its
// birth context (pinned by TestProfilingLabel_BirthLabelSurvivesAFunnel).
func labelSubsystem(name string) context.Context {
	ctx, ok := subsystemContexts[name]
	if !ok {
		ctx = runtimepprof.WithLabels(context.Background(), runtimepprof.Labels(subsystemLabelKey, name))
	}
	runtimepprof.SetGoroutineLabels(ctx)
	return ctx
}

// withSubsystem runs fn with the goroutine labelled for its duration, for the
// funnels that run on SHARED goroutines (schedulers, HTTP handlers, gRPC
// handlers), where a permanent label would mislabel the next caller. ctx is
// what the labels revert to afterwards, so a caller with a birth label passes
// the context labelSubsystem returned; a caller with nothing to preserve
// passes context.Background() (or nil).
//
// A label merely INHERITED by a goroutine (spawned while its parent ran under
// a funnel, as the scenario scheduler is under startLocked) does not survive
// a trap or syslog funnel, by design: those fires are trap and syslog work.
//
// A context that ALREADY carries this label (the fleet flow ticker calling
// the flow funnel once per exporter per tick) runs fn directly: pprof.Do
// would allocate a label map to set what is already set.
func withSubsystem(ctx context.Context, name string, fn func(context.Context)) {
	if ctx == nil {
		ctx = context.Background()
	}
	if v, ok := runtimepprof.Label(ctx, subsystemLabelKey); ok && v == name {
		fn(ctx)
		return
	}
	runtimepprof.Do(ctx, runtimepprof.Labels(subsystemLabelKey, name), fn)
}
