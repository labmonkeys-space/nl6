/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// e2e_test.go drives the REAL nl6 through the nl6-ci verbs in three separate
// fixture cycles. The first reconciles a syslog window exactly. The second
// asks a NetFlow v5 fleet for a rate above its flow ceiling and expects run to
// fail with the reason per device. The third freezes nl6 during the window and
// expects run to give up at the deadline. Every cycle ends with a down that must exit
// 0 and remove the nl6sim namespace. Every other test in this package runs
// against a fake nl6, so this is the only one that proves the verbs, nl6's REST
// API, the scenario report and nl6-reconcile agree on a real host.
//
// Gated on NL6_CI_E2E=1: unset skips, set on a host that cannot run nl6 FAILS,
// because a silent skip asserts nothing. The devices need Linux, root (through
// sudo -n), TUN and the nl6sim network namespace. `make test-interop-ci-fixture`
// sets the environment and builds the binaries.
//
// Environment (the Makefile sets all of them, as absolute paths):
//
//	NL6_CI_BIN         the nl6-ci binary under test
//	NL6_RECONCILE_BIN  the nl6-reconcile binary check runs
//	NL6_BIN            the nl6 simulator binary
//	NL6_WORKDIR        the directory holding resources/, web/ and worldcities/
const (
	e2eGate      = "NL6_CI_E2E"
	e2eListen    = "0.0.0.0:5514"
	e2eCollector = "10.254.0.1:5514" // where the devices send; the host end of the nl6sim veth
	e2eRate      = "5"
	e2eWindow    = "10s"
	e2eSettle    = 2 * time.Second
	e2eStepLimit = 4 * time.Minute
	// e2eWaitDelay bounds the wait for the output pipe after the step limit
	// kills a command. A killed sudo cannot forward SIGKILL, so nl6-ci can
	// keep the pipe open long after.
	e2eWaitDelay = 10 * time.Second
	e2eNetns     = "/run/netns/nl6sim"
)

var e2eDevices = []string{"10.42.0.1", "10.42.0.2", "10.42.0.3", "10.42.0.4"}

// e2eManifest is one batch of four devices. The syslog block is the REST
// block from docs/reference/web-api.md. Transport defaults to udp and format
// to 5424, so only the collector is set.
const e2eManifest = `[{"start_ip":"10.42.0.1","device_count":4,"syslog":{"collector":"` + e2eCollector + `"}}]`

// e2eFlowManifest is four NetFlow v5 exporters. No collector listens on 2055:
// the scenario never starts, because every device is excluded at arm.
const e2eFlowManifest = `[{"start_ip":"10.42.0.1","device_count":4,"flow":{"collector":"10.254.0.1:2055","protocol":"netflow5"}}]`

// e2eFlowRate is above the per-device flow ceiling of every shipped profile
// (8.6 to 9.7 records per second, see flowRateReachable in go/nl6).
const e2eFlowRate = "10"

// e2eExec runs a command, returns its combined output and exit code, and
// prints the output of every command that fails so the CI log explains why.
func e2eExec(t *testing.T, env []string, name string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), e2eStepLimit)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.WaitDelay = e2eWaitDelay
	cmd.Stdout, cmd.Stderr = &out, &out
	if env != nil {
		cmd.Env = env
	}
	err := cmd.Run()
	code := 0
	if err != nil {
		code = -1
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
	}
	if code != 0 {
		t.Logf("command failed (exit %d): %s %s\n%s", code, name, strings.Join(args, " "), out.String())
	}
	return out.String(), code
}

func e2eEnv(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Fatalf("%s is empty; run this through make test-interop-ci-fixture", key)
	}
	return v
}

// e2eCounter counts UDP datagrams per source address.
type e2eCounter struct {
	conn *net.UDPConn
	done chan struct{}
	mu   sync.Mutex
	n    map[string]int
}

func e2eListenUDP(t *testing.T) *e2eCounter {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp4", e2eListen)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("listen on %s: %v", e2eListen, err)
	}
	// A burst of four devices must not overflow the socket queue, or the
	// test would report loss that nl6 did not cause.
	_ = conn.SetReadBuffer(4 << 20)
	c := &e2eCounter{conn: conn, done: make(chan struct{}), n: map[string]int{}}
	go func() {
		defer close(c.done)
		buf := make([]byte, 65535)
		for {
			_, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return // closed
			}
			c.mu.Lock()
			c.n[from.IP.String()]++
			c.mu.Unlock()
		}
	}()
	return c
}

// stop closes the socket, waits for the reader and returns the counts.
func (c *e2eCounter) stop() map[string]int {
	c.conn.Close()
	<-c.done
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.n))
	for k, v := range c.n {
		out[k] = v
	}
	return out
}

// e2eWriteCSV writes protocol,source_ip,collector,received, one row per source.
func e2eWriteCSV(t *testing.T, path string, counts map[string]int) {
	t.Helper()
	ips := make([]string, 0, len(counts))
	for ip := range counts {
		ips = append(ips, ip)
	}
	sort.Strings(ips)
	var b strings.Builder
	b.WriteString("protocol,source_ip,collector,received\n")
	for _, ip := range ips {
		fmt.Fprintf(&b, "syslog,%s,%s,%d\n", ip, e2eCollector, counts[ip])
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// e2eBins are the absolute paths the Makefile hands to the test.
type e2eBins struct{ ci, reconcile, nl6, workdir string }

func TestCIFixtureInterop(t *testing.T) {
	if os.Getenv(e2eGate) != "1" {
		t.Skipf("%s=1 is not set; run `make test-interop-ci-fixture` on a Linux host with sudo", e2eGate)
	}
	b := e2eBins{
		ci:        e2eEnv(t, "NL6_CI_BIN"),
		reconcile: e2eEnv(t, "NL6_RECONCILE_BIN"),
		nl6:       e2eEnv(t, "NL6_BIN"),
		workdir:   e2eEnv(t, "NL6_WORKDIR"),
	}
	for _, p := range []string{b.ci, b.reconcile, b.nl6, b.workdir} {
		if !filepath.IsAbs(p) {
			t.Fatalf("%q is not absolute; sudo and the nl6 child resolve it from another directory", p)
		}
	}
	// Each subtest is one fixture cycle. Its down runs in the subtest's
	// cleanup, so the second up starts on a host the first down cleaned.
	t.Run("syslog exact reconcile", func(t *testing.T) { e2eSyslogCycle(t, b) })
	t.Run("netflow5 above the flow ceiling", func(t *testing.T) { e2eCeilingCycle(t, b) })
	t.Run("nl6 hangs during the window", func(t *testing.T) { e2eHungCycle(t, b) })
}

// e2eUp writes the manifest, registers the teardown and runs sudo nl6-ci up.
// It returns the state directory.
func e2eUp(t *testing.T, b e2eBins, manifestBody string) string {
	t.Helper()
	tmp := t.TempDir()
	// The state directory does not exist yet. The root `up` creates it and
	// hands it to the sudo caller, so the unprivileged run can write
	// report.json there. This is the flow a lab host uses too.
	state := filepath.Join(tmp, "state")
	manifest := filepath.Join(tmp, "manifest.json")
	if err := os.WriteFile(manifest, []byte(manifestBody), 0o644); err != nil {
		t.Fatal(err)
	}

	// Teardown always runs, also when up fails half way (nl6 may be running
	// and the namespace may exist). It is registered before up, and runs
	// before TempDir removes the state directory.
	t.Cleanup(func() {
		out, code := e2eExec(t, nil, "sudo", "-n", b.ci, "-state", state, "down", "-log-tail")
		t.Logf("down (exit %d):\n%s", code, out)
		if code != 0 {
			t.Errorf("down exited %d, want 0", code)
		}
		if _, err := os.Stat(e2eNetns); err == nil {
			t.Errorf("%s still exists after down", e2eNetns)
		}
		if t.Failed() {
			log, err := os.ReadFile(filepath.Join(state, "nl6.log"))
			t.Logf("nl6.log (read error %v):\n%s", err, log)
		}
	})

	out, code := e2eExec(t, nil, "sudo", "-n", b.ci, "-state", state, "up",
		"-manifest", manifest, "-nl6", b.nl6, "-workdir", b.workdir)
	t.Logf("up:\n%s", out)
	if code != 0 {
		t.Fatalf("up exited %d, want 0", code)
	}
	return state
}

// e2eSyslogCycle is issue scenarios 1 and 2: an exact match passes, one lost
// record fails and names the device.
func e2eSyslogCycle(t *testing.T, b e2eBins) {
	state := e2eUp(t, b, e2eManifest)
	received := filepath.Join(t.TempDir(), "received.csv")

	// check finds nl6-reconcile through PATH.
	checkEnv := append(os.Environ(), "PATH="+filepath.Dir(b.reconcile)+string(os.PathListSeparator)+os.Getenv("PATH"))

	counter := e2eListenUDP(t)
	stopped := false
	defer func() {
		if !stopped {
			counter.stop()
		}
	}()

	out, code := e2eExec(t, nil, b.ci, "-state", state, "run",
		"-protocol", "syslog", "-rate", e2eRate, "-window", e2eWindow)
	t.Logf("run:\n%s", out)
	if code != 0 {
		t.Fatalf("run exited %d, want 0", code)
	}

	// Let datagrams already in flight arrive before the socket closes.
	time.Sleep(e2eSettle)
	counts := counter.stop()
	stopped = true
	t.Logf("received per source: %v", counts)

	// A wrong source here (the host or veth address instead of the device
	// IP) means nl6's per-device bind fell back to the shared socket.
	var got []string
	for ip := range counts {
		got = append(got, ip)
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(e2eDevices, ",") {
		t.Fatalf("datagram sources = %v, want exactly the device IPs %v (see -syslog-source-per-device)", got, e2eDevices)
	}

	e2eWriteCSV(t, received, counts)
	out, code = e2eExec(t, checkEnv, b.ci, "-state", state, "check", "-received", received)
	t.Logf("check (exact):\n%s", out)
	if code != 0 {
		t.Fatalf("check exited %d on the exact counts, want 0", code)
	}

	// One lost record on one device must fail the gate and name the device.
	lossy := map[string]int{}
	for ip, n := range counts {
		lossy[ip] = n
	}
	lossy["10.42.0.1"]--
	e2eWriteCSV(t, received, lossy)
	out, code = e2eExec(t, checkEnv, b.ci, "-state", state, "check", "-received", received)
	t.Logf("check (one record short):\n%s", out)
	if code != 1 {
		t.Errorf("check exited %d with one record missing on 10.42.0.1, want 1", code)
	}
	if !strings.Contains(out, "10.42.0.1") || !strings.Contains(out, "LOSS") {
		t.Errorf("check output must name 10.42.0.1 and LOSS, got:\n%s", out)
	}
}

// e2eCeilingCycle is issue scenario 4: a flow rate above the ceiling makes run
// exit 1 and print the exclusion reason for each device.
func e2eCeilingCycle(t *testing.T, b e2eBins) {
	state := e2eUp(t, b, e2eFlowManifest)
	out, code := e2eExec(t, nil, b.ci, "-state", state, "run",
		"-protocol", "netflow5", "-rate", e2eFlowRate, "-window", "5s")
	t.Logf("run (netflow5 at %s/s):\n%s", e2eFlowRate, out)
	if code != 1 {
		t.Errorf("run exited %d above the flow ceiling, want 1", code)
	}
	lines := strings.Split(out, "\n")
	for _, ip := range e2eDevices {
		found := false
		for _, l := range lines {
			if strings.HasPrefix(l, "run: excluded "+ip+": ") && strings.Contains(l, "exceeds this device's flow ceiling") {
				found = true
			}
		}
		if !found {
			t.Errorf("no flow-ceiling exclusion line for %s", ip)
		}
	}
}

// e2eHungCycle freezes nl6 with SIGSTOP while a scenario runs. A frozen nl6
// keeps its pid and its command name and answers no HTTP request, as a hung
// one does. run must give up at the deadline and must not wait for a stop
// call on top: that call has a 75s budget (finalizeBudget).
func e2eHungCycle(t *testing.T, b e2eBins) {
	const (
		window = 5 * time.Second
		grace  = 60 * time.Second // the default of run, which has no flag for it
		// One status call can be in flight at the deadline, for up to
		// requestTimeout. The rest is slack. A stop call would add 75s.
		limit = window + grace + 30*time.Second
	)
	state := e2eUp(t, b, e2eManifest)
	s, err := loadState(state)
	if err != nil {
		t.Fatal(err)
	}
	pid := strconv.Itoa(s.PID)
	// A frozen nl6 does not act on SIGTERM. This cleanup runs before the down
	// that e2eUp registered, so down finds an nl6 that can exit.
	t.Cleanup(func() {
		if _, code := e2eExec(t, nil, "sudo", "-n", "kill", "-CONT", pid); code != 0 {
			t.Errorf("kill -CONT %s exited %d", pid, code)
		}
	})

	type result struct {
		out  string
		code int
	}
	done := make(chan result, 1)
	begin := time.Now()
	go func() {
		out, code := e2eExec(t, nil, b.ci, "-state", state, "run",
			"-protocol", "syslog", "-rate", e2eRate, "-window", window.String())
		done <- result{out, code}
	}()
	// run submits, arms and starts within a second. A freeze before the start
	// fails run with another message, and the check below catches that.
	time.Sleep(2 * time.Second)
	if _, code := e2eExec(t, nil, "sudo", "-n", "kill", "-STOP", pid); code != 0 {
		t.Errorf("kill -STOP %s exited %d", pid, code)
	}
	r := <-done
	took := time.Since(begin)
	t.Logf("run against a frozen nl6 (%s):\n%s", took.Round(time.Second), r.out)
	if r.code != 1 {
		t.Errorf("run exited %d against a frozen nl6, want 1", r.code)
	}
	if !strings.Contains(r.out, "nl6 did not finish the window: no status after") {
		t.Errorf("run must report that nl6 gave no status, got:\n%s", r.out)
	}
	if took > limit {
		t.Errorf("run took %s, want at most %s: it waited on a stop call to an nl6 that does not answer", took.Round(time.Second), limit)
	}
}
