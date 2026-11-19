/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	startBudget = 60 * time.Second
	batchBudget = 5 * time.Minute
	// nl6 shuts down in bounded steps that add up to more than a few seconds:
	// it aborts a running scenario (up to 60s) and stops each gNMI server that
	// still has a client (2s per device). The wait ends when nl6 exits.
	stopBudget = 90 * time.Second
	// SIGKILL cannot be ignored, so this only covers the kernel's teardown.
	killBudget = 10 * time.Second
	logTail    = 40
)

// errKilled reports an nl6 that ignored SIGTERM for the whole stop budget.
// nl6 reads one signal only, so a second SIGTERM would change nothing.
var errKilled = errors.New("did not stop in time and was killed")

// clearNS removes the network namespace a killed or crashed nl6 left behind
// and says what became of it. up refused to start while the namespace existed,
// so it belongs to the nl6 that just ended.
func clearNS(env upEnv) string {
	if env.nsDelete != nil && env.nsDelete() == nil {
		return "Its network namespace nl6sim was removed"
	}
	return "Its network namespace nl6sim is left, remove it with: sudo ip netns delete nl6sim"
}

// deleteNS runs ip netns delete nl6sim. A namespace that is already gone is fine.
func deleteNS() error {
	out, err := exec.Command("ip", "netns", "delete", "nl6sim").CombinedOutput()
	if err != nil && !bytes.Contains(out, []byte("No such file")) {
		return fmt.Errorf("%w: %s", err, bytes.TrimSpace(out))
	}
	return nil
}

type upOptions struct {
	Manifest string // path, batch-manifest shape [{start_ip, device_count, ...}]
	Port     int    // default 18080
	NL6      string // default /usr/bin/nl6
	Workdir  string // default /usr/share/nl6
	// CreateTimeout is the budget for all batches and the wait after them.
	// 0 means batchBudget.
	CreateTimeout time.Duration
	Extra         []string // flags after "--", passed to nl6 unchanged
}

// upEnv holds everything up and down need from the host, so tests can fake it.
type upEnv struct {
	probe    func() probe
	spawn    func(o upOptions, logPath string) (child, error) // starts nl6 detached, Setsid, output to logPath
	inspect  func(pid int, comm string, start uint64) procState
	budget   time.Duration // overrides every wait budget when above 0 (tests)
	kill     func(pid int, sig syscall.Signal) error
	nsExist  func() bool                           // true when /run/netns/nl6sim exists
	nsDelete func() error                          // removes the nl6sim namespace, nil means it cannot
	getenv   func(string) string                   // nil means no environment
	chown    func(path string, uid, gid int) error // nil means never chown
	out      io.Writer
	poll     time.Duration // wait-loop interval, 0 means 250ms
}

// limit returns d, or the test override.
func (e upEnv) limit(d time.Duration) time.Duration {
	if e.budget > 0 {
		return e.budget
	}
	return d
}

func (e upEnv) interval() time.Duration {
	if e.poll > 0 {
		return e.poll
	}
	return 250 * time.Millisecond
}

func liveEnv(out io.Writer) upEnv {
	return upEnv{
		probe:   liveProbe,
		spawn:   spawnNL6,
		inspect: inspectProc,
		kill:    syscall.Kill,
		nsExist: func() bool {
			_, err := os.Stat("/run/netns/nl6sim")
			return err == nil
		},
		nsDelete: deleteNS,
		getenv:   os.Getenv,
		chown:    os.Lchown, // never follow a symlink planted in the state directory
		out:      out,
	}
}

// child is the nl6 that up started. term and done go through the process
// handle, so neither can reach another process that got the pid later.
type child struct {
	pid   int
	start uint64          // start time of the pid, see state.StartTicks
	term  func() error    // sends SIGTERM
	kill  func() error    // sends SIGKILL
	done  <-chan struct{} // closed once nl6 has exited
}

// exited reports whether nl6 has exited.
func (c child) exited() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// procState is what a recorded pid stands for now.
type procState int

const (
	procGone    procState = iota // no such process, or a zombie
	procOurs                     // the live process that was recorded
	procForeign                  // another live process that got the pid: never signal it
)

// procComm is the command name the kernel records for a binary at path: its
// base name, cut to 15 bytes (TASK_COMM_LEN less the NUL).
func procComm(path string) string {
	c := filepath.Base(path)
	if len(c) > 15 {
		c = c[:15]
	}
	return c
}

// parseProcStat judges the content of /proc/<pid>/stat, "pid (comm) S ...".
// comm may hold spaces and parentheses, so it ends at the last ")".
// The command name alone does not name a process: the packaged nl6.service
// runs as "nl6" too. start is the recorded start time, which a process that
// got the pid later cannot share. 0 means unknown, and only comm is compared.
func parseProcStat(stat, comm string, start uint64) procState {
	open, end := strings.IndexByte(stat, '('), strings.LastIndexByte(stat, ')')
	if open < 0 || end < open || len(stat) < end+3 {
		return procForeign // cannot tell, so do not signal it
	}
	switch stat[end+2] {
	case 'Z', 'X':
		return procGone
	}
	if stat[open+1:end] != comm {
		return procForeign
	}
	if start != 0 && statStart(stat) != start {
		return procForeign
	}
	return procOurs
}

// statStart returns the start time in /proc/<pid>/stat: field 22, in clock
// ticks since boot. 0 means the content has none.
func statStart(stat string) uint64 {
	end := strings.LastIndexByte(stat, ')')
	if end < 0 {
		return 0
	}
	f := strings.Fields(stat[end+1:]) // f[0] is field 3, the state
	if len(f) < 20 {
		return 0
	}
	n, _ := strconv.ParseUint(f[19], 10, 64)
	return n
}

// procStart reads the start time of pid. 0 means unknown (no procfs).
func procStart(pid int) uint64 {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	return statStart(string(b))
}

// isScript reports whether the file at path starts with "#!".
func isScript(path string) bool {
	f, err := os.Open(path) // #nosec G304 -- the path is the -nl6 binary the caller asked to run
	if err != nil {
		return false // exec reports it
	}
	defer f.Close()
	var magic [2]byte
	_, err = io.ReadFull(f, magic[:])
	return err == nil && string(magic[:]) == "#!"
}

// inspectProc reads /proc/<pid>/stat. Without that file (no procfs, as on
// macOS, or a pid hidden by hidepid) it falls back to kill(pid, 0), where
// EPERM means the process exists and belongs to another user.
func inspectProc(pid int, comm string, start uint64) procState {
	if pid <= 0 {
		return procGone // kill would address a process group
	}
	if b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
		return parseProcStat(string(b), comm, start)
	}
	if err := syscall.Kill(pid, 0); err == nil || errors.Is(err, syscall.EPERM) {
		return procOurs
	}
	return procGone
}

// spawnNL6 starts nl6 in its own session with output going to logPath.
// nl6 reads resources/, web/ and worldcities/ relative to its working
// directory, so the process starts in o.Workdir.
func spawnNL6(o upOptions, logPath string) (child, error) {
	// exec reports a missing cmd.Dir as "fork/exec <binary>: no such file or
	// directory", which blames the binary. Name the directory instead.
	if fi, err := os.Stat(o.Workdir); err != nil {
		return child{}, fmt.Errorf("-workdir: %w", err)
	} else if !fi.IsDir() {
		return child{}, fmt.Errorf("-workdir %s is not a directory", o.Workdir)
	}
	// exec resolves a relative path in cmd.Dir, so resolve it here first: the
	// caller named a file in its own directory, not in o.Workdir.
	bin, err := exec.LookPath(o.NL6)
	if err == nil {
		bin, err = filepath.Abs(bin)
	}
	if err != nil {
		return child{}, err
	}
	// A script keeps the pid while nl6 runs as its child, so down would stop
	// the script and leave nl6. One that execs nl6 does so under another name.
	if isScript(bin) {
		return child{}, fmt.Errorf("-nl6 %s is a script. -nl6 must name the nl6 binary itself, not a wrapper script", bin)
	}
	// A log an earlier up handed to the sudo caller goes first. In a sticky
	// world-writable directory such as /tmp, fs.protected_regular refuses even
	// root an O_CREAT open of a file that another user owns.
	if err := os.Remove(logPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return child{}, err
	}
	log, err := os.OpenFile(logPath, stateFileFlags, 0o644) // #nosec G302 -- nl6.log is world-readable on purpose: an unprivileged step must read what a root step wrote
	if err != nil {
		return child{}, err
	}
	cmd := exec.Command(bin, nl6Args(o)...)
	cmd.Dir = o.Workdir
	cmd.Stdout, cmd.Stderr = log, log
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return child{}, errors.Join(err, log.Close())
	}
	// The parent wrote nothing to this handle and nl6 holds its own
	// descriptor, so a close error loses no data. Failing here would orphan
	// the nl6 that was just started.
	_ = log.Close()
	start := procStart(cmd.Process.Pid) // before the reaper below can free the pid
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait() // reap, so a killed nl6 does not linger as a zombie
		close(done)
	}()
	return child{
		pid:   cmd.Process.Pid,
		start: start,
		term:  func() error { return cmd.Process.Signal(syscall.SIGTERM) },
		kill:  cmd.Process.Kill,
		done:  done,
	}, nil
}

// nl6Args is the argument list nl6 is started with.
func nl6Args(o upOptions) []string {
	return append([]string{"-port", strconv.Itoa(o.Port), "-fidelity"}, o.Extra...)
}

type batchSpec struct {
	StartIP     string `json:"start_ip"`
	DeviceCount int    `json:"device_count"`
}

// readManifest returns the raw batches and the total device count.
func readManifest(path string) ([]json.RawMessage, int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, err
	}
	var raw []json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, 0, fmt.Errorf("manifest %s: %w", path, err)
	}
	if len(raw) == 0 {
		return nil, 0, fmt.Errorf("manifest %s: no batches", path)
	}
	total := 0
	for i, r := range raw {
		var s batchSpec
		if err := json.Unmarshal(r, &s); err != nil {
			return nil, 0, fmt.Errorf("manifest %s: batch %d: %w", path, i, err)
		}
		if s.StartIP == "" || s.DeviceCount <= 0 {
			return nil, 0, fmt.Errorf("manifest %s: batch %d needs start_ip and a device_count above 0", path, i)
		}
		total += s.DeviceCount
	}
	return raw, total, nil
}

func up(dir string, o upOptions, env upEnv) error {
	// The state check and the report removal come before anything that can
	// refuse, the manifest included. A refused up must not leave the state or
	// the report of an earlier fixture for check.
	if s, err := loadState(dir); err == nil {
		switch env.inspect(s.PID, procComm(s.NL6), s.StartTicks) {
		case procOurs:
			return fmt.Errorf("nl6 already running (pid %d, state dir %s). Run nl6-ci down first", s.PID, dir)
		case procForeign:
			_, _ = fmt.Fprintf(env.out, "up: replacing stale state in %s, pid %d now belongs to another process\n", dir, s.PID)
		default:
			_, _ = fmt.Fprintf(env.out, "up: replacing stale state for dead pid %d in %s\n", s.PID, dir)
		}
		if err := removeState(dir); err != nil {
			return fmt.Errorf("remove the stale state: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// No fixture lives in dir, so its report.json is from an earlier one.
	// After down, check has no state.json to tell it apart by its window start.
	if err := os.Remove(filepath.Join(dir, "report.json")); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the report of an earlier fixture: %w", err)
	}
	batches, want, err := readManifest(o.Manifest)
	if err != nil {
		return err
	}
	api := fmt.Sprintf("http://127.0.0.1:%d", o.Port)
	c := newClient(api)
	if _, err := c.version(); err == nil {
		return fmt.Errorf("an nl6 instance already runs on this host (port %d answers)", o.Port)
	}
	if env.nsExist() {
		return fmt.Errorf("found a leftover network namespace nl6sim and no nl6 answering on port %d. "+
			"If no other nl6 runs on this host, remove it with: sudo ip netns delete nl6sim", o.Port)
	}
	// One probe serves the preflight and every ownership hand-over below.
	p := env.probe()
	env.probe = func() probe { return p }
	if fs := preflight(p); len(fs) > 0 {
		var parts []string
		for _, f := range fs {
			parts = append(parts, fmt.Sprintf("%s: %s. Fix: %s", f.ID, f.Problem, f.Fix))
		}
		return fmt.Errorf("preflight failed: %s", strings.Join(parts, "; "))
	}
	// Judged before up writes anything: once nl6.log exists, an empty
	// directory of someone else looks like one nl6-ci left.
	hand := missingDirs(dir)
	if len(hand) == 0 && ownDir(dir) {
		hand = []string{dir}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- state dir is 0755 on purpose: an unprivileged step must read what a root step wrote
		return err
	}
	// Absolute, so a verb that runs in another directory finds the log.
	logPath := filepath.Join(dir, "nl6.log")
	if abs, err := filepath.Abs(logPath); err == nil {
		logPath = abs
	}
	started := time.Now()
	nl6, err := env.spawn(o, logPath)
	if err != nil {
		_ = handState(dir, hand, env) // best-effort, so the sudo caller can remove the directory and the log
		return fmt.Errorf("start nl6: %w", err)
	}
	pid, comm := nl6.pid, procComm(o.NL6)
	st := state{PID: pid, StartTicks: nl6.start, API: api, Log: logPath, NL6: o.NL6, Started: started}
	fail := func(err error) error {
		// state.json goes only once nl6 is gone, so down can stop a survivor.
		stopErr := stopChild(nl6, env)
		switch {
		case stopErr == nil:
			// An nl6 that died by itself, for example on a port it could not
			// bind, exits without removing its namespace. The next up would
			// refuse to start until someone removed it by hand.
			if env.nsExist() {
				_, _ = fmt.Fprintf(env.out, "up: nl6 (pid %d) left its network namespace behind. %s\n", pid, clearNS(env))
			}
			_ = removeState(dir) // best-effort, the startup error is returned
		case errors.Is(stopErr, errKilled):
			_, _ = fmt.Fprintf(env.out, "up: nl6 (pid %d) %v. %s\n", pid, stopErr, clearNS(env))
			_ = removeState(dir) // best-effort, the startup error is returned
		default:
			_, _ = fmt.Fprintf(env.out, "up: nl6 (pid %d) did not stop: %v. Run nl6-ci down\n", pid, stopErr)
		}
		_ = handFile(filepath.Join(dir, stateFile), env) // best-effort, so the sudo caller can remove a state.json that stayed
		_, _ = fmt.Fprintf(env.out, "up: failed, last %d lines of %s:\n%s", logTail, logPath, tailFile(logPath, logTail))
		return err
	}
	// The directories and the log change hands before the waits. An up that is
	// interrupted during them never reaches its end, and down removes only
	// state.json. state.json follows at the end: every saveState replaces it
	// with a new file that root owns.
	if err := handState(dir, hand, env); err != nil {
		return fail(err)
	}
	// The pid is recorded before the waits. An up that is interrupted during
	// them leaves a detached nl6, and down finds it only through state.json.
	if err := saveState(dir, st); err != nil {
		return fail(err)
	}
	var last error
	if err := waitFor(env.limit(startBudget), env.interval(), &last, func() (bool, error) {
		if nl6.exited() {
			return false, fmt.Errorf("nl6 exited during startup")
		}
		_, last = c.version()
		return last == nil, nil
	}); err != nil {
		return fail(fmt.Errorf("wait for nl6 API: %w", err))
	}
	// down has only the pid and the command name to go by. A wrapper that
	// execs the real binary under another name (the Nix package does) would
	// start here and never be found again.
	if env.inspect(pid, comm, nl6.start) != procOurs {
		return fail(fmt.Errorf("pid %d does not run as %q, so down could not identify it. "+
			"-nl6 must name the nl6 binary itself, not a wrapper script", pid, comm))
	}
	// One budget covers every batch and the wait after them.
	if o.CreateTimeout == 0 {
		o.CreateTimeout = batchBudget
	}
	budget := env.limit(o.CreateTimeout)
	deadline := time.Now().Add(budget)
	for _, b := range batches {
		if err := c.createBatchBy(b, deadline, budget); err != nil {
			return fail(err)
		}
	}
	total := 0
	last = nil
	if err := waitUntil(deadline, budget, env.interval(), &last, func() (bool, error) {
		if nl6.exited() {
			return false, fmt.Errorf("nl6 exited during device creation")
		}
		busy, n, err := c.status()
		total, last = n, err
		return err == nil && !busy, nil
	}); err != nil {
		return fail(fmt.Errorf("wait for device creation: %w", err))
	}
	if total != want {
		return fail(fmt.Errorf("created %d of %d devices", total, want))
	}
	st.Devices = total
	if err := saveState(dir, st); err != nil {
		return fail(err)
	}
	if err := handFile(filepath.Join(dir, stateFile), env); err != nil {
		return fail(err)
	}
	_, _ = fmt.Fprintf(env.out, "up: %d devices, api %s, state %s\n", total, api, dir)
	return nil
}

// stateNames are the files nl6-ci keeps in a state directory.
var stateNames = map[string]bool{stateFile: true, "nl6.log": true, "report.json": true}

// ownDir reports whether an earlier run left dir: it holds nl6-ci files and
// nothing else. /tmp does not. An empty directory does not either, because
// nothing says nl6-ci made it.
func ownDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) == 0 {
		return false
	}
	for _, e := range entries {
		if !stateNames[e.Name()] {
			return false
		}
	}
	return true
}

// missingDirs lists dir and each parent that does not exist yet, parents
// first. These are the directories MkdirAll is about to create.
func missingDirs(dir string) []string {
	var out []string
	for d := filepath.Clean(dir); ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil || d == filepath.Dir(d) {
			return out
		}
		out = append([]string{d}, out...)
	}
}

// sudoCaller returns the uid and gid of the user who ran sudo. ok is false
// unless up runs as root with SUDO_UID and SUDO_GID set to integers (a real
// root login or a root container keeps root ownership).
func sudoCaller(env upEnv) (uid, gid int, ok bool) {
	if env.chown == nil || env.getenv == nil || env.probe().euid != 0 {
		return 0, 0, false
	}
	uid, uerr := strconv.Atoi(env.getenv("SUDO_UID"))
	gid, gerr := strconv.Atoi(env.getenv("SUDO_GID"))
	if uerr != nil || gerr != nil || uid < 0 || gid < 0 {
		return 0, 0, false
	}
	return uid, gid, true
}

// handFile gives one path to the user who ran sudo. A missing path is fine:
// after a failed up there is no state.json to hand over.
func handFile(path string, env upEnv) error {
	uid, gid, ok := sudoCaller(env)
	if !ok {
		return nil
	}
	if err := env.chown(path, uid, gid); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hand %s to %d:%d (the sudo caller): %w", path, uid, gid, err)
	}
	return nil
}

// handState gives the state directory and nl6.log to the user who ran sudo, so
// run and check work without root. hand are the directories that change hands:
// the ones this up created, parents included, or the state directory an
// earlier run left. A missing parent would stay with root otherwise. Without
// them the directory existed and is not nl6-ci's own, so it keeps its owner
// and only the files change hands. state.json follows at the end of up,
// through handFile.
func handState(dir string, hand []string, env upEnv) error {
	if _, _, ok := sudoCaller(env); !ok {
		return nil
	}
	if len(hand) == 0 {
		_, _ = fmt.Fprintf(env.out, "up: %s was not made by nl6-ci and keeps its owner\n", dir)
	}
	paths := append([]string{}, hand...)
	for _, p := range append(paths, filepath.Join(dir, "nl6.log")) {
		if err := handFile(p, env); err != nil {
			return err
		}
	}
	return nil
}

func down(dir string, env upEnv) error {
	s, err := loadState(dir)
	if errors.Is(err, os.ErrNotExist) {
		_, _ = fmt.Fprintln(env.out, "down: nothing running")
		return nil
	}
	if err != nil {
		return err
	}
	gone := func() error {
		if err := removeState(dir); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(env.out, "down: nl6 (pid %d) was not running, removed stale state\n", s.PID)
		return nil
	}
	comm := procComm(s.NL6)
	switch env.inspect(s.PID, comm, s.StartTicks) {
	case procForeign:
		if err := removeState(dir); err != nil {
			return err
		}
		_, _ = fmt.Fprintf(env.out, "down: pid %d is not nl6 any more, removed stale state\n", s.PID)
		return nil
	case procGone:
		return gone()
	}
	if err := stop(s.PID, comm, s.StartTicks, env); err != nil {
		if errors.Is(err, syscall.ESRCH) { // nl6 exited between the check and the signal
			return gone()
		}
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("no permission to stop nl6 (pid %d), call it with sudo: sudo nl6-ci down. state.json is kept", s.PID)
		}
		if errors.Is(err, errKilled) {
			if rerr := removeState(dir); rerr != nil {
				return rerr
			}
			return fmt.Errorf("nl6 (pid %d) %w. %s", s.PID, err, clearNS(env))
		}
		return fmt.Errorf("stop nl6 (pid %d): %w. state.json is kept", s.PID, err)
	}
	if err := removeState(dir); err != nil {
		return err
	}
	_, _ = fmt.Fprintf(env.out, "down: stopped pid %d\n", s.PID)
	return nil
}

// stopChild sends SIGTERM to the nl6 that up started and waits for its exit.
// An nl6 that outlives the stop budget is killed, and the error is errKilled.
func stopChild(c child, env upEnv) error {
	if err := c.term(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	select {
	case <-c.done:
		return nil
	case <-time.After(env.limit(stopBudget)):
	}
	if err := c.kill(); errors.Is(err, os.ErrProcessDone) {
		return nil // nl6 exited on SIGTERM just before the kill
	} else if err != nil {
		return err
	}
	select {
	case <-c.done:
		return errKilled
	case <-time.After(env.limit(killBudget)):
		return errors.New("still runs after SIGKILL")
	}
}

// stop sends SIGTERM to pid and waits until the recorded process is gone. An
// nl6 that outlives the stop budget is killed, and the error is errKilled.
func stop(pid int, comm string, start uint64, env upEnv) error {
	if err := env.kill(pid, syscall.SIGTERM); err != nil {
		return err
	}
	gone := func() (bool, error) { return env.inspect(pid, comm, start) != procOurs, nil }
	if waitFor(env.limit(stopBudget), env.interval(), nil, gone) == nil {
		return nil
	}
	if err := env.kill(pid, syscall.SIGKILL); errors.Is(err, syscall.ESRCH) {
		return nil // nl6 exited on SIGTERM just before the kill
	} else if err != nil {
		return err
	}
	if err := waitFor(env.limit(killBudget), env.interval(), nil, gone); err != nil {
		return fmt.Errorf("still runs after SIGKILL: %w", err)
	}
	return errKilled
}

// waitFor polls f until it reports done, returns an error, or the budget ends.
// A timeout names the last poll error f stored in *last, when there is one.
func waitFor(budget, every time.Duration, last *error, f func() (bool, error)) error {
	return waitUntil(time.Now().Add(budget), budget, every, last, f)
}

// waitUntil is waitFor with a deadline the caller shares with other steps.
// budget is the whole of it, for the message.
func waitUntil(deadline time.Time, budget, every time.Duration, last *error, f func() (bool, error)) error {
	for {
		done, err := f()
		if err != nil {
			return err
		}
		if done {
			return nil
		}
		if time.Now().After(deadline) {
			if last != nil && *last != nil {
				return fmt.Errorf("not ready after %s: %w", budget, *last)
			}
			return fmt.Errorf("not ready after %s", budget)
		}
		time.Sleep(every)
	}
}

// tailFile returns the last n lines of a file, each newline terminated.
func tailFile(path string, n int) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Sprintf("(cannot read %s: %v)\n", path, err)
	}
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return string(bytes.Join(lines, []byte("\n"))) + "\n"
}
