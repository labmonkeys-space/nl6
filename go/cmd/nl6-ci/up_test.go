/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

type fakes struct {
	env       upEnv
	out       *bytes.Buffer
	spawned   []upOptions
	killed    []int // pids sent SIGTERM
	sigkilled []int // pids sent SIGKILL
	isAlive   bool
	nsExists  bool
	spawnFail error
	broken    string // API path the fake answers with an error
	survives  bool   // the fake nl6 ignores SIGTERM
	exit      func() // makes the fake nl6 exit, set by spawn
	onPost    func() // called on each device POST
}

func newFakes(t *testing.T) *fakes {
	f := &fakes{out: &bytes.Buffer{}, isAlive: true}
	f.env = upEnv{
		probe: func() probe { return probe{goos: "linux", euid: 0, capEff: fullCaps} },
		spawn: func(o upOptions, logPath string) (child, error) {
			f.spawned = append(f.spawned, o)
			_ = os.WriteFile(logPath, []byte("nl6 log line\n"), 0o644)
			if f.spawnFail != nil {
				return child{}, f.spawnFail
			}
			done := make(chan struct{})
			f.exit = sync.OnceFunc(func() { close(done) })
			term := func() error {
				f.killed = append(f.killed, 4242)
				if !f.survives {
					f.isAlive = false
					f.exit()
				}
				return nil
			}
			kill := func() error {
				f.sigkilled = append(f.sigkilled, 4242)
				f.isAlive = false
				f.exit()
				return nil
			}
			return child{pid: 4242, start: 9001, term: term, kill: kill, done: done}, nil
		},
		inspect: func(pid int, comm string, start uint64) procState {
			if f.isAlive {
				return procOurs
			}
			return procGone
		},
		kill: func(pid int, sig syscall.Signal) error {
			if sig == syscall.SIGKILL {
				f.sigkilled = append(f.sigkilled, pid)
				f.isAlive = false
				return nil
			}
			f.killed = append(f.killed, pid)
			if !f.survives {
				f.isAlive = false
			}
			return nil
		},
		nsExist: func() bool { return f.nsExists },
		out:     f.out,
		poll:    time.Millisecond,
	}
	return f
}

// fakeAPI answers like nl6 but is down until the first spawn, so the
// "already answers on the port" check does not fire.
func fakeAPI(t *testing.T, f *fakes, total int) (upOptions, *int) {
	posts := new(int)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/version", func(w http.ResponseWriter, r *http.Request) {
		if len(f.spawned) == 0 || f.broken == r.URL.Path {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.Write([]byte(`{"version":"v1"}`))
	})
	mux.HandleFunc("/api/v1/status", func(w http.ResponseWriter, r *http.Request) {
		if f.broken == r.URL.Path {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		w.Write([]byte(`{"success":true,"message":"Success","data":{"create_batch_in_progress":false,"total_devices":` + strconv.Itoa(total) + `}}`))
	})
	mux.HandleFunc("/api/v1/devices", func(w http.ResponseWriter, r *http.Request) {
		*posts++
		if f.onPost != nil {
			f.onPost()
		}
		w.Write([]byte(`{"success":true}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	u, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(u.Port())
	return upOptions{Port: port, NL6: "/x/nl6", Workdir: "/x"}, posts
}

func writeManifest(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "m.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

const manifest4 = `[{"start_ip":"10.42.0.1","device_count":4,"syslog":{"collector":"10.254.0.1:5514"}}]`

func TestUpCreatesDevicesAndSavesState(t *testing.T) {
	f := newFakes(t)
	o, posts := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	o.Extra = []string{"-foo", "bar"}
	dir := filepath.Join(t.TempDir(), "st")
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if len(f.spawned) != 1 || f.spawned[0].Port != o.Port || !reflect.DeepEqual(f.spawned[0].Extra, o.Extra) {
		t.Fatalf("spawn %+v", f.spawned)
	}
	if *posts != 1 {
		t.Errorf("%d posts", *posts)
	}
	s, err := loadState(dir)
	if err != nil || s.Devices != 4 || s.PID != 4242 || s.StartTicks != 9001 || s.Log != filepath.Join(dir, "nl6.log") || s.NL6 != "/x/nl6" {
		t.Fatalf("state %+v, %v", s, err)
	}
	if !contains(f.out.String(), "up: 4 devices, api http://127.0.0.1:") {
		t.Errorf("out %q", f.out.String())
	}
}

func TestUpRefusesWhenPreflightFails(t *testing.T) {
	f := newFakes(t)
	f.env.probe = func() probe { return probe{goos: "linux", euid: 0, capEff: 0xa80425fb} }
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "cap_net_admin") || len(f.spawned) != 0 {
		t.Fatalf("err %v, spawned %d", err, len(f.spawned))
	}
}

func TestUpRefusesStaleState(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 99}); err != nil {
		t.Fatal(err)
	}
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "already running") || !contains(err.Error(), dir) || len(f.spawned) != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestUpReplacesStateOfDeadProcess(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 99}); err != nil {
		t.Fatal(err)
	}
	f.env.inspect = func(pid int, comm string, start uint64) procState {
		if pid == 4242 {
			return procOurs
		}
		return procGone
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if !contains(f.out.String(), "stale state for dead pid 99 in "+dir) {
		t.Errorf("out %q", f.out.String())
	}
}

func TestNL6Args(t *testing.T) {
	got := nl6Args(upOptions{Port: 18080, Extra: []string{"-netconf-enable"}})
	want := []string{"-port", "18080", "-fidelity", "-netconf-enable"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestUpRefusesRunningNL6(t *testing.T) {
	f := newFakes(t)
	f.nsExists = true
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "leftover network namespace nl6sim") ||
		!contains(err.Error(), "sudo ip netns delete nl6sim") || len(f.spawned) != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestUpTimeoutsNameTheLastError(t *testing.T) {
	for _, tc := range []struct{ name, broken, want string }{
		{"api never ready", "/api/v1/version", "wait for nl6 API: not ready after 20ms: GET /api/v1/version: 503"},
		{"status fails", "/api/v1/status", "wait for device creation: not ready after 20ms: GET /api/v1/status: 500 Internal Server Error: boom"},
	} {
		f := newFakes(t)
		f.env.budget = 20 * time.Millisecond
		f.broken = tc.broken
		o, _ := fakeAPI(t, f, 4)
		o.Manifest = writeManifest(t, manifest4)
		err := up(t.TempDir(), o, f.env)
		if err == nil || !contains(err.Error(), tc.want) {
			t.Errorf("%s: err %v, want %q", tc.name, err, tc.want)
		}
	}
}

func TestUpRefusesAnsweringPort(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	f.spawned = append(f.spawned, upOptions{}) // makes the fake API answer
	f.spawned = f.spawned[:1]
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "an nl6 instance already runs on this host") || len(f.killed) != 0 {
		t.Fatalf("err %v", err)
	}
}

func TestUpRejectsBadManifest(t *testing.T) {
	for _, body := range []string{"not json", "[]", `[{"start_ip":"10.42.0.1","device_count":0}]`, `[{"device_count":2}]`} {
		f := newFakes(t)
		o, _ := fakeAPI(t, f, 4)
		o.Manifest = writeManifest(t, body)
		if err := up(t.TempDir(), o, f.env); err == nil || len(f.spawned) != 0 {
			t.Errorf("%q: err %v spawned %d", body, err, len(f.spawned))
		}
	}
}

func TestUpFailsOnCountMismatch(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 3)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "created 3 of 4 devices") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.killed, []int{4242}) {
		t.Errorf("killed %v", f.killed)
	}
	if !contains(f.out.String(), "nl6 log line") {
		t.Errorf("no log tail in %q", f.out.String())
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state saved after failure: %v", err)
	}
}

// nl6 that exits during startup is reaped at once, so its pid is free. up must
// not signal that number: the failure path runs as root.
func TestUpNeverSignalsAnNL6ThatDiedDuringStartup(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	f.broken = "/api/v1/version" // a dead nl6 never answers
	spawn := f.env.spawn
	f.env.spawn = func(o upOptions, logPath string) (child, error) {
		c, err := spawn(o, logPath)
		f.exit()
		// The pid is free once nl6 is reaped. A real handle refuses to signal.
		c.term = func() error { return os.ErrProcessDone }
		return c, err
	}
	// The pid now belongs to another process, which must never be signalled.
	f.env.inspect = func(pid int, comm string, start uint64) procState { return procForeign }
	dir := t.TempDir()
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "exited during startup") {
		t.Fatalf("err %v", err)
	}
	if len(f.killed) != 0 {
		t.Errorf("signalled pid %v by number after nl6 was reaped", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left after failure: %v", err)
	}
}

// nl6 creates its namespace before it binds the API port. One that dies on
// the bind leaves the namespace, and the next up would refuse to start.
func TestUpRemovesTheNamespaceOfAnNL6ThatDiedDuringStartup(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	f.broken = "/api/v1/version" // a dead nl6 never answers
	spawn := f.env.spawn
	f.env.spawn = func(o upOptions, logPath string) (child, error) {
		c, err := spawn(o, logPath)
		f.nsExists = true
		f.exit()
		c.term = func() error { return os.ErrProcessDone }
		return c, err
	}
	deleted := 0
	f.env.nsDelete = func() error {
		deleted++
		f.nsExists = false
		return nil
	}
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "exited during startup") {
		t.Fatalf("err %v", err)
	}
	if deleted != 1 || !contains(f.out.String(), "Its network namespace nl6sim was removed") {
		t.Errorf("namespace deleted %d times, out %q", deleted, f.out.String())
	}
}

// The Nix package wraps nl6, so the kernel shows another command name than
// the -nl6 path. down could not identify that process, so up refuses it and
// stops what it started.
func TestUpRefusesAWrappedNL6(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	f.env.inspect = func(pid int, comm string, start uint64) procState { return procForeign }
	dir := t.TempDir()
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "not a wrapper script") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.killed, []int{4242}) {
		t.Errorf("killed %v: the wrapped nl6 keeps running", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left after failure: %v", err)
	}
}

// A start that fails leaves the state directory and nl6.log behind. Under sudo
// they must go to the caller, who could not remove them otherwise.
func TestUpHandsTheStateDirBackWhenTheStartFails(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	f.spawnFail = errors.New("-workdir: stat /nope: no such file or directory")
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := filepath.Join(t.TempDir(), "st")
	if err := up(dir, o, f.env); err == nil || !contains(err.Error(), "start nl6: -workdir") {
		t.Fatalf("err %v", err)
	}
	handed := map[string]bool{}
	for _, c := range *calls {
		handed[c.path] = true
	}
	if !handed[dir] || !handed[filepath.Join(dir, "nl6.log")] {
		t.Fatalf("chown calls %+v: the sudo caller cannot remove what a failed start left", *calls)
	}
}

// up creates missing parents of the state directory as root, so each of them
// goes to the sudo caller, not only the leaf.
func TestUpHandsOverTheParentsItCreated(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b")
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	want := []chownCall{
		{filepath.Join(base, "a"), 1001, 1001},
		{dir, 1001, 1001},
		{filepath.Join(dir, "nl6.log"), 1001, 1001},
		{filepath.Join(dir, "state.json"), 1001, 1001},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("chown calls %+v, want %+v", *calls, want)
	}
}

func TestSpawnNL6NamesAMissingWorkdir(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "nope")
	logPath := filepath.Join(dir, "nl6.log")
	_, err := spawnNL6(upOptions{NL6: "/bin/sh", Workdir: missing}, logPath)
	if err == nil || !contains(err.Error(), "-workdir") || !contains(err.Error(), missing) {
		t.Fatalf("err %v, want one that names the missing -workdir", err)
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("nl6.log was created before the workdir check: %v", err)
	}
}

// A real nl6 that already exited must not be signalled by pid: the number may
// belong to another process by then.
func TestSpawnedChildRefusesToSignalAfterExit(t *testing.T) {
	dir := t.TempDir()
	// sh rejects the nl6 flags and exits at once.
	c, err := spawnNL6(upOptions{NL6: "/bin/sh", Workdir: dir}, filepath.Join(dir, "nl6.log"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-c.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the child did not exit")
	}
	if err := c.term(); !errors.Is(err, os.ErrProcessDone) {
		t.Fatalf("term after exit: %v, want os.ErrProcessDone", err)
	}
	if err := stopChild(c, upEnv{}); err != nil {
		t.Fatalf("stopChild after exit: %v", err)
	}
}

// nl6 that dies while the devices are created must fail up at once, not after
// the whole creation budget.
func TestUpFailsWhenNL6DiesDuringCreation(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	f.broken = "/api/v1/status" // a dead nl6 never reports the batch as done
	f.onPost = func() { f.exit() }
	f.env.budget = 2 * time.Second
	start := time.Now()
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "exited during device creation") {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("up took %s, it waited out the budget", d)
	}
}

// The state directory may be shared and world-writable (-state /tmp under
// sudo), so up must not write through a symlink planted there.
// A symlink planted under the log name is removed, never followed.
func TestSpawnNL6ReplacesASymlinkedLog(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "nl6.log")
	if err := os.Symlink(target, logPath); err != nil {
		t.Fatal(err)
	}
	c, err := spawnNL6(upOptions{NL6: "/bin/sh", Workdir: dir}, logPath)
	if err != nil {
		t.Fatal(err)
	}
	<-c.done
	if fi, err := os.Lstat(logPath); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("the log is not a regular file: %v, %v", fi, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the symlink target was written: %q", b)
	}
}

// The log of an earlier fixture belongs to the sudo caller. In /tmp root
// cannot open it with O_CREAT (fs.protected_regular), so spawnNL6 starts a new
// file instead of truncating the old one.
func TestSpawnNL6StartsAFreshLog(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "nl6.log")
	if err := os.WriteFile(logPath, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A second link keeps the old inode alive. Without it the filesystem may
	// give the new file the freed inode number, and SameFile reports a reuse.
	kept := filepath.Join(dir, "old.log")
	if err := os.Link(logPath, kept); err != nil {
		t.Fatal(err)
	}
	c, err := spawnNL6(upOptions{NL6: "/bin/sh", Workdir: dir}, logPath)
	if err != nil {
		t.Fatal(err)
	}
	<-c.done
	old, err := os.Stat(kept)
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := os.Stat(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(old, fresh) {
		t.Fatal("spawnNL6 reused the log file of the earlier fixture")
	}
	if b, _ := os.ReadFile(kept); string(b) != "old" {
		t.Errorf("the earlier log was written: %q", b)
	}
}

// A refused up must not leave the state of a dead fixture: check would accept
// an old report at a -report path by that fixture's start time.
func TestUpRemovesStaleStateWhenItRefuses(t *testing.T) {
	for name, st := range map[string]procState{"dead": procGone, "foreign": procForeign} {
		f := newFakes(t)
		o, _ := fakeAPI(t, f, 4)
		o.Manifest = writeManifest(t, manifest4)
		dir := t.TempDir()
		if err := saveState(dir, state{PID: 99, NL6: "/usr/bin/nl6"}); err != nil {
			t.Fatal(err)
		}
		f.env.inspect = func(int, string, uint64) procState { return st }
		f.nsExists = true
		if err := up(dir, o, f.env); err == nil || !contains(err.Error(), "leftover network namespace") {
			t.Fatalf("%s: err %v", name, err)
		}
		if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: load state %v: the stale state.json is still there", name, err)
		}
	}
}

// After a finished cycle there is no state.json, so check cannot tell an old
// report.json from a new one. A bad manifest must not keep it.
func TestUpRemovesTheEarlierReportOnABadManifest(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = filepath.Join(t.TempDir(), "missing.json")
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := up(dir, o, f.env); err == nil {
		t.Fatal("expected an error")
	}
	if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %v: the report of the earlier cycle is still there", err)
	}
}

// A live fixture keeps its report, whatever the manifest says.
func TestUpKeepsTheReportOfALiveFixture(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = filepath.Join(t.TempDir(), "missing.json")
	dir := savedFixture(t)
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := up(dir, o, f.env); err == nil || !contains(err.Error(), "already running") {
		t.Fatalf("err %v", err)
	}
	if _, err := os.Stat(report); err != nil {
		t.Fatalf("the report of the live fixture is gone: %v", err)
	}
}

// An up that is interrupted during the waits never reaches its end. down then
// removes state.json only, so the directories and the log must already belong
// to the sudo caller. state.json stays with root meanwhile: in /tmp root could
// not rewrite a file the sudo caller owns.
func TestUpHandsTheStateDirOverBeforeItWaits(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	base := t.TempDir()
	dir := filepath.Join(base, "a", "b")
	var early []chownCall
	// The wrapper check runs once the API answers, still before the devices.
	f.env.inspect = func(int, string, uint64) procState {
		early = append([]chownCall(nil), *calls...)
		return procOurs
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	want := []chownCall{
		{filepath.Join(base, "a"), 1001, 1001},
		{dir, 1001, 1001},
		{filepath.Join(dir, "nl6.log"), 1001, 1001},
	}
	if !reflect.DeepEqual(early, want) {
		t.Fatalf("chown calls during startup %+v, want %+v", early, want)
	}
}

// One budget covers every batch and the wait after them.
// -create-timeout replaces the 5 minute budget for a fleet that needs longer.
func TestUpCreatesWithinTheGivenBudget(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	o.CreateTimeout = 30 * time.Millisecond
	f.broken = "/api/v1/status"
	err := up(t.TempDir(), o, f.env)
	if err == nil || !contains(err.Error(), "wait for device creation: not ready after 30ms") {
		t.Fatalf("err %v", err)
	}
}

func TestUpSharesOneBudgetAcrossBatches(t *testing.T) {
	f := newFakes(t)
	f.env.budget = 300 * time.Millisecond
	o, _ := fakeAPI(t, f, 4)
	var posts atomic.Int32 // a POST that timed out is still in its handler
	f.onPost = func() {
		posts.Add(1)
		time.Sleep(200 * time.Millisecond)
	}
	o.Manifest = writeManifest(t, `[{"start_ip":"10.42.0.1","device_count":2},{"start_ip":"10.42.0.3","device_count":2},{"start_ip":"10.42.0.5","device_count":2}]`)
	err := up(t.TempDir(), o, f.env)
	if n := posts.Load(); err == nil || n > 2 {
		t.Fatalf("err %v after %d posts: each batch got a budget of its own", err, n)
	}
}

type chownCall struct {
	path     string
	uid, gid int
}

// withSudoEnv fakes the environment and records chown calls.
func withSudoEnv(f *fakes, vars map[string]string, fail error) *[]chownCall {
	calls := new([]chownCall)
	f.env.getenv = func(k string) string { return vars[k] }
	f.env.chown = func(path string, uid, gid int) error {
		*calls = append(*calls, chownCall{path, uid, gid})
		return fail
	}
	return calls
}

func TestUpHandsStateToSudoCaller(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := filepath.Join(t.TempDir(), "st")
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	want := []chownCall{
		{dir, 1001, 1001},
		{filepath.Join(dir, "nl6.log"), 1001, 1001},
		{filepath.Join(dir, "state.json"), 1001, 1001},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("chown calls %+v, want %+v", *calls, want)
	}
}

func TestUpLeavesOwnershipWithoutSudoVars(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	if err := up(filepath.Join(t.TempDir(), "st"), o, f.env); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("chown called: %+v", *calls)
	}
}

func TestUpIgnoresNonNumericSudoUID(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "bob", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	if err := up(filepath.Join(t.TempDir(), "st"), o, f.env); err != nil {
		t.Fatal(err)
	}
	if len(*calls) != 0 {
		t.Fatalf("chown called: %+v", *calls)
	}
}

func TestUpSkipsChownWhenNotRoot(t *testing.T) {
	f := newFakes(t)
	f.env.probe = func() probe { return probe{goos: "linux", euid: 1000, capEff: fullCaps} }
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	// Not root: preflight refuses first, so up fails before any chown.
	_ = up(filepath.Join(t.TempDir(), "st"), o, f.env)
	if len(*calls) != 0 {
		t.Fatalf("chown called: %+v", *calls)
	}
}

func TestUpFailsAndKillsWhenChownFails(t *testing.T) {
	f := newFakes(t)
	withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, errors.New("operation not permitted"))
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := filepath.Join(t.TempDir(), "st")
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), dir) || !contains(err.Error(), "operation not permitted") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.killed, []int{4242}) {
		t.Errorf("killed %v", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left after failure: %v", err)
	}
}

func TestUpRecordsThePidBeforeItWaits(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := filepath.Join(t.TempDir(), "st")
	var early state
	var earlyErr error
	// The wrapper check runs once the API answers, still before the devices.
	f.env.inspect = func(pid int, comm string, start uint64) procState {
		early, earlyErr = loadState(dir)
		return procOurs
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if earlyErr != nil || early.PID != 4242 {
		t.Fatalf("state during startup %+v, %v: an interrupted up would leave nl6 without a pid for down", early, earlyErr)
	}
}

// nl6 reads one signal only, so an nl6 that ignores SIGTERM is killed. It
// leaves its namespace behind, and the output says how to remove it.
func TestUpKillsAnNL6ThatDoesNotStop(t *testing.T) {
	f := newFakes(t)
	f.survives = true
	f.env.budget = 20 * time.Millisecond
	o, _ := fakeAPI(t, f, 3)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "created 3 of 4 devices") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.killed, []int{4242}) || !reflect.DeepEqual(f.sigkilled, []int{4242}) {
		t.Errorf("SIGTERM to %v, SIGKILL to %v", f.killed, f.sigkilled)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left for a killed nl6: %v", err)
	}
	if !contains(f.out.String(), "pid 4242") || !contains(f.out.String(), "sudo ip netns delete nl6sim") {
		t.Errorf("out %q", f.out.String())
	}
}

// nl6 can finish its exit on SIGTERM just as the stop budget ends. The kill
// then finds no process, and nothing was killed: no namespace is left behind.
func TestUpTreatsAnNL6ThatExitedBeforeTheKillAsStopped(t *testing.T) {
	f := newFakes(t)
	f.survives = true
	f.env.budget = 20 * time.Millisecond
	o, _ := fakeAPI(t, f, 3)
	o.Manifest = writeManifest(t, manifest4)
	spawn := f.env.spawn
	f.env.spawn = func(o upOptions, logPath string) (child, error) {
		c, err := spawn(o, logPath)
		c.kill = func() error {
			f.exit()
			return os.ErrProcessDone
		}
		return c, err
	}
	dir := t.TempDir()
	err := up(dir, o, f.env)
	if err == nil || !contains(err.Error(), "created 3 of 4 devices") {
		t.Fatalf("err %v", err)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left for an nl6 that exited: %v", err)
	}
	if contains(f.out.String(), "was killed") || contains(f.out.String(), "ip netns delete") {
		t.Errorf("out reports a kill that did not happen: %q", f.out.String())
	}
}

// A failed up or a run that never started writes no report. The one an
// earlier fixture left must not pass for this fixture after down.
func TestUpRemovesTheReportOfAnEarlierFixture(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	report := filepath.Join(dir, "report.json")
	if err := os.WriteFile(report, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(report); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stat %v: the report of the earlier fixture is still there", err)
	}
}

func TestUpHandsTheStateDirBackAfterAFailure(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 3)
	o.Manifest = writeManifest(t, manifest4)
	dir := filepath.Join(t.TempDir(), "st")
	if err := up(dir, o, f.env); err == nil {
		t.Fatal("expected an error")
	}
	handed := map[string]bool{}
	for _, c := range *calls {
		handed[c.path] = true
	}
	if !handed[dir] || !handed[filepath.Join(dir, "nl6.log")] {
		t.Fatalf("chown calls %+v: the sudo caller cannot remove what a failed up left", *calls)
	}
}

func TestUpKeepsTheOwnerOfASharedStateDir(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir() // stands for /tmp: it holds a file of someone else
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	want := []chownCall{
		{filepath.Join(dir, "nl6.log"), 1001, 1001},
		{filepath.Join(dir, "state.json"), 1001, 1001},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("chown calls %+v, want %+v", *calls, want)
	}
	if strings.Count(f.out.String(), "keeps its owner") != 1 {
		t.Errorf("out %q", f.out.String())
	}
}

// sudo nl6-ci up -state /tmp on a host where /tmp is empty. Once up has
// written nl6.log the directory holds nothing but nl6-ci files, and it is
// still not nl6-ci's own.
func TestUpKeepsTheOwnerOfAnEmptyStateDir(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir() // exists and is empty
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	for _, c := range *calls {
		if c.path == dir {
			t.Fatalf("chown calls %+v: an empty directory of someone else changed hands", *calls)
		}
	}
	if strings.Count(f.out.String(), "keeps its owner") != 1 {
		t.Errorf("out %q", f.out.String())
	}
}

// The preflight probe opens /dev/net/tun and searches PATH. The ownership
// hand-overs need its euid only, so they reuse the one result.
func TestUpProbesOnce(t *testing.T) {
	f := newFakes(t)
	withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	probes := 0
	inner := f.env.probe
	f.env.probe = func() probe { probes++; return inner() }
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	if err := up(filepath.Join(t.TempDir(), "state"), o, f.env); err != nil {
		t.Fatal(err)
	}
	if probes != 1 {
		t.Errorf("probed %d times, want 1", probes)
	}
}

// A later verb may run in another directory, so the recorded log path must
// not depend on the directory up ran in.
func TestUpRecordsAnAbsoluteLogPath(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	t.Chdir(t.TempDir())
	if err := up(".nl6-ci", o, f.env); err != nil {
		t.Fatal(err)
	}
	s, err := loadState(".nl6-ci")
	if err != nil || !filepath.IsAbs(s.Log) {
		t.Fatalf("log %q, %v: want an absolute path", s.Log, err)
	}
	if _, err := os.Stat(s.Log); err != nil {
		t.Errorf("the recorded log does not exist: %v", err)
	}
}

func TestUpHandsOverALeftoverStateDir(t *testing.T) {
	f := newFakes(t)
	calls := withSudoEnv(f, map[string]string{"SUDO_UID": "1001", "SUDO_GID": "1001"}, nil)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir() // left by an earlier run: nothing but nl6-ci files
	for _, n := range []string{"nl6.log", "report.json"} {
		if err := os.WriteFile(filepath.Join(dir, n), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if len(*calls) == 0 || (*calls)[0].path != dir {
		t.Fatalf("chown calls %+v: the leftover directory stays with root", *calls)
	}
}

func TestSpawnNL6ResolvesARelativePath(t *testing.T) {
	bin, work := t.TempDir(), t.TempDir()
	if err := os.Symlink("/bin/sh", filepath.Join(bin, "fake-nl6")); err != nil {
		t.Fatal(err)
	}
	t.Chdir(bin)
	// A relative path names a file in the caller's directory, not in -workdir.
	if _, err := spawnNL6(upOptions{NL6: "./fake-nl6", Workdir: work}, filepath.Join(work, "nl6.log")); err != nil {
		t.Fatalf("spawn: %v", err)
	}
}

func TestDownStopsAndRemovesState(t *testing.T) {
	f := newFakes(t)
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 77, Log: filepath.Join(dir, "nl6.log")}); err != nil {
		t.Fatal(err)
	}
	if err := down(dir, f.env); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.killed, []int{77}) {
		t.Errorf("killed %v", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state remains: %v", err)
	}
}

func TestUpReplacesStateOfForeignProcess(t *testing.T) {
	f := newFakes(t)
	o, _ := fakeAPI(t, f, 4)
	o.Manifest = writeManifest(t, manifest4)
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 99, NL6: "/usr/bin/nl6"}); err != nil {
		t.Fatal(err)
	}
	f.env.inspect = func(pid int, comm string, start uint64) procState {
		if pid == 4242 {
			return procOurs
		}
		return procForeign
	}
	if err := up(dir, o, f.env); err != nil {
		t.Fatal(err)
	}
	if !contains(f.out.String(), "pid 99 now belongs to another process") || len(f.killed) != 0 {
		t.Errorf("out %q, killed %v", f.out.String(), f.killed)
	}
}

// savedFixture writes a state.json for pid 77 started from /usr/bin/nl6 at
// start time 555.
func savedFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 77, StartTicks: 555, NL6: "/usr/bin/nl6", Log: filepath.Join(dir, "nl6.log")}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestDownChecksTheRecordedCommand(t *testing.T) {
	f := newFakes(t)
	var comms []string
	var starts []uint64
	inner := f.env.inspect
	f.env.inspect = func(pid int, comm string, start uint64) procState {
		comms, starts = append(comms, comm), append(starts, start)
		return inner(pid, comm, start)
	}
	if err := down(savedFixture(t), f.env); err != nil {
		t.Fatal(err)
	}
	if len(comms) == 0 || comms[0] != "nl6" {
		t.Fatalf("inspect saw comm %v, want nl6", comms)
	}
	// Every check carries the recorded start time, the wait after SIGTERM
	// included: a pid that is reused meanwhile must read as gone.
	for _, s := range starts {
		if s != 555 {
			t.Fatalf("inspect saw start times %v, want 555 each", starts)
		}
	}
}

func TestDownWithoutPrivilegeFailsAndKeepsState(t *testing.T) {
	f := newFakes(t)
	f.env.kill = func(pid int, sig syscall.Signal) error { return syscall.EPERM }
	dir := savedFixture(t)
	err := down(dir, f.env)
	if err == nil || !contains(err.Error(), "sudo nl6-ci down") || !contains(err.Error(), "pid 77") {
		t.Fatalf("err %v", err)
	}
	if _, err := loadState(dir); err != nil {
		t.Errorf("state removed: %v", err)
	}
	if contains(f.out.String(), "stopped") {
		t.Errorf("out claims a stop: %q", f.out.String())
	}
}

func TestDownTreatsAProcessThatVanishedAsStopped(t *testing.T) {
	f := newFakes(t)
	f.env.kill = func(pid int, sig syscall.Signal) error { return syscall.ESRCH } // exited after the liveness check
	dir := savedFixture(t)
	if err := down(dir, f.env); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state remains: %v", err)
	}
	if !contains(f.out.String(), "down: nl6 (pid 77) was not running, removed stale state") {
		t.Errorf("out %q", f.out.String())
	}
}

func TestDownNeverSignalsAForeignProcess(t *testing.T) {
	f := newFakes(t)
	f.env.inspect = func(pid int, comm string, start uint64) procState { return procForeign }
	dir := savedFixture(t)
	if err := down(dir, f.env); err != nil {
		t.Fatal(err)
	}
	if len(f.killed) != 0 {
		t.Fatalf("killed %v", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale state remains: %v", err)
	}
	if !contains(f.out.String(), "down: pid 77 is not nl6 any more, removed stale state") {
		t.Errorf("out %q", f.out.String())
	}
}

func TestDownTreatsAGoneProcessAsStopped(t *testing.T) {
	f := newFakes(t)
	f.isAlive = false // a zombie or an exited nl6
	dir := savedFixture(t)
	if err := down(dir, f.env); err != nil {
		t.Fatal(err)
	}
	if len(f.killed) != 0 {
		t.Fatalf("killed %v", f.killed)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale state remains: %v", err)
	}
	if !contains(f.out.String(), "down: nl6 (pid 77) was not running, removed stale state") {
		t.Errorf("out %q", f.out.String())
	}
}

// A crashed nl6 leaves its namespace behind and the next up refuses to start
// on it. down did not end that nl6, so it names the namespace and leaves it.
func TestDownNamesTheNamespaceOfACrashedNL6(t *testing.T) {
	f := newFakes(t)
	f.isAlive = false
	f.nsExists = true
	deleted := 0
	f.env.nsDelete = func() error { deleted++; return nil }
	if err := down(savedFixture(t), f.env); err != nil {
		t.Fatal(err)
	}
	if !contains(f.out.String(), "nl6sim still exists") || !contains(f.out.String(), "sudo ip netns delete nl6sim") {
		t.Errorf("out %q", f.out.String())
	}
	if deleted != 0 {
		t.Errorf("namespace deleted %d times, want 0: another nl6 may own it", deleted)
	}
}

// nl6 reads one signal only, so a second down could not stop a hung nl6
// either. down kills it and reports the namespace it left behind.
func TestDownKillsAnNL6ThatDoesNotExit(t *testing.T) {
	f := newFakes(t)
	f.survives = true
	f.env.budget = 20 * time.Millisecond
	dir := savedFixture(t)
	err := down(dir, f.env)
	if err == nil || !contains(err.Error(), "pid 77") || !contains(err.Error(), "was killed") ||
		!contains(err.Error(), "sudo ip netns delete nl6sim") {
		t.Fatalf("err %v", err)
	}
	if !reflect.DeepEqual(f.killed, []int{77}) || !reflect.DeepEqual(f.sigkilled, []int{77}) {
		t.Errorf("SIGTERM to %v, SIGKILL to %v", f.killed, f.sigkilled)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state left for a killed nl6: %v", err)
	}
}

// down runs as root and has just killed the owner of the namespace, so it
// removes the namespace itself. The next up would refuse to start otherwise.
func TestDownRemovesTheNamespaceOfAKilledNL6(t *testing.T) {
	f := newFakes(t)
	f.survives = true
	f.env.budget = 20 * time.Millisecond
	deleted := 0
	f.env.nsDelete = func() error { deleted++; return nil }
	err := down(savedFixture(t), f.env)
	if err == nil || !contains(err.Error(), "was killed") || !contains(err.Error(), "nl6sim was removed") ||
		contains(err.Error(), "sudo ip netns delete") {
		t.Fatalf("err %v", err)
	}
	if deleted != 1 {
		t.Errorf("namespace deleted %d times, want 1", deleted)
	}
}

// nl6 can finish its exit on SIGTERM just as the stop budget ends. The kill
// then finds no process, and down has stopped nl6 as asked.
func TestDownTreatsAnNL6ThatExitedBeforeTheKillAsStopped(t *testing.T) {
	f := newFakes(t)
	f.env.kill = func(pid int, sig syscall.Signal) error {
		if sig == syscall.SIGKILL {
			f.isAlive = false
			return syscall.ESRCH
		}
		return nil
	}
	f.env.budget = 20 * time.Millisecond
	dir := savedFixture(t)
	if err := down(dir, f.env); err != nil {
		t.Fatalf("down: %v", err)
	}
	if _, err := loadState(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("state remains: %v", err)
	}
	if !contains(f.out.String(), "down: stopped pid 77") {
		t.Errorf("out %q", f.out.String())
	}
}

// Without the kill, state.json stays so that a later down can try again.
func TestDownKeepsStateWhenNL6SurvivesSIGKILL(t *testing.T) {
	f := newFakes(t)
	f.env.kill = func(pid int, sig syscall.Signal) error { return nil } // stays alive
	f.env.budget = 20 * time.Millisecond
	dir := savedFixture(t)
	err := down(dir, f.env)
	if err == nil || !contains(err.Error(), "pid 77") || !contains(err.Error(), "state.json is kept") {
		t.Fatalf("err %v", err)
	}
	if _, err := loadState(dir); err != nil {
		t.Errorf("state removed: %v", err)
	}
}

func TestParseProcStat(t *testing.T) {
	for _, tc := range []struct {
		name, stat, comm string
		start            uint64
		want             procState
	}{
		{"running nl6", "4242 (nl6) S 1 4242 4242 0 -1", "nl6", 0, procOurs},
		{"sleeping in disk", "4242 (nl6) D 1 4242", "nl6", 0, procOurs},
		{"zombie", "4242 (nl6) Z 1 4242", "nl6", 0, procGone},
		{"dead", "4242 (nl6) X 1 4242", "nl6", 0, procGone},
		{"reused pid", "4242 (sleep) S 1 4242", "nl6", 0, procForeign},
		{"comm with a paren and a space", "4242 (a) b) S 1", "a) b", 0, procOurs},
		{"malformed", "garbage", "nl6", 0, procForeign},
		{"the recorded start time", statLine, "nl6", 8812345, procOurs},
		// The packaged nl6.service runs as "nl6" too.
		{"reused pid with the same name", statLine, "nl6", 8800000, procForeign},
		{"no start time to compare", "4242 (nl6) S 1 4242", "nl6", 8812345, procForeign},
	} {
		if got := parseProcStat(tc.stat, tc.comm, tc.start); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// statLine is a /proc/<pid>/stat line. Field 22, the start time, is 8812345.
const statLine = "4242 (nl6) S 1 4242 4242 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 9 0 8812345 1000000 500"

func TestStatStart(t *testing.T) {
	if got := statStart(statLine); got != 8812345 {
		t.Errorf("got %d, want 8812345", got)
	}
	if got := statStart("4242 (nl6) S 1"); got != 0 {
		t.Errorf("short line: got %d, want 0", got)
	}
}

// A script keeps the pid while nl6 runs as its child. down would stop the
// script, report success and leave nl6 running.
func TestSpawnNL6RefusesAScript(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "nl6")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n/usr/bin/nl6 \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "nl6.log")
	_, err := spawnNL6(upOptions{NL6: script, Workdir: dir}, logPath)
	if err == nil || !contains(err.Error(), "not a wrapper script") {
		t.Fatalf("err %v, want a refusal of the script", err)
	}
	if _, err := os.Stat(logPath); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("nl6.log was created for a refused script: %v", err)
	}
}

func TestProcComm(t *testing.T) {
	if got := procComm("/usr/bin/nl6"); got != "nl6" {
		t.Errorf("got %q", got)
	}
	if got := procComm("/opt/a-very-long-simulator-name"); got != "a-very-long-sim" {
		t.Errorf("got %q, want the 15 byte kernel comm", got)
	}
}

func TestInspectProc(t *testing.T) {
	for _, pid := range []int{0, -1} {
		if got := inspectProc(pid, "nl6", 0); got != procGone {
			t.Errorf("pid %d: got %v, want gone (kill would signal a process group)", pid, got)
		}
	}
	if got := inspectProc(os.Getpid(), procComm(os.Args[0]), 0); got != procOurs {
		t.Errorf("own pid: got %v, want ours", got)
	}
}

func TestDownWithNothingRunning(t *testing.T) {
	f := newFakes(t)
	if err := down(t.TempDir(), f.env); err != nil || len(f.killed) != 0 {
		t.Fatalf("err %v killed %v", err, f.killed)
	}
}

func TestTailFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l")
	var b strings.Builder
	for i := 0; i < 50; i++ {
		b.WriteString("line" + strconv.Itoa(i) + "\n")
	}
	if err := os.WriteFile(p, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(tailFile(p, 40)), "\n")
	if len(got) != 40 || got[0] != "line10" || got[39] != "line49" {
		t.Fatalf("%d lines, first %q", len(got), got[0])
	}
}
