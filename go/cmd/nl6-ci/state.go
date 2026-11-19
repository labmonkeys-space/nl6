/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

const stateFile = "state.json"

// state is what `up` leaves behind for the other verbs.
type state struct {
	PID int `json:"pid"`
	// StartTicks is the start time of the pid: field 22 of /proc/<pid>/stat,
	// in clock ticks since boot. With the pid it names one process, because a
	// process that gets the pid later starts later. 0 means unknown (no procfs).
	StartTicks uint64 `json:"start_ticks,omitempty"`
	API        string `json:"api"`     // e.g. http://127.0.0.1:18080
	Log        string `json:"log"`     // <dir>/nl6.log
	Devices    int    `json:"devices"` // created device count
	NL6        string `json:"nl6"`
	// Started is when up started nl6. check refuses a report from before it.
	Started time.Time `json:"started"`
}

// loadState reads <dir>/state.json. The error wraps os.ErrNotExist when the
// file is absent. The state directory may be shared and world-writable
// (-state /tmp under sudo), and root signals the pid and prints the log that
// the file names. So the open never follows a symlink, and root refuses a file
// that another user planted.
func loadState(dir string) (state, error) {
	var s state
	path := filepath.Join(dir, stateFile)
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return s, fmt.Errorf("load state: %w", err)
	}
	defer func() { _ = f.Close() }() // read-only, nothing to lose
	fi, err := f.Stat()
	if err != nil {
		return s, fmt.Errorf("load state: %w", err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && !trustedOwner(st.Uid, os.Geteuid(), os.Getenv("SUDO_UID")) {
		return s, fmt.Errorf("load state %s: the file belongs to uid %d, not to root or the sudo caller. Remove it if no nl6-ci up wrote it", path, st.Uid)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return s, fmt.Errorf("load state: %w", err)
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("load state %s: %w", path, err)
	}
	return s, nil
}

// trustedOwner reports whether a state.json of this owner may steer the
// caller. Without root the caller gains nothing from the file. Root trusts
// its own file and the file of the user who ran sudo: up hands state.json to
// that user.
func trustedOwner(owner uint32, euid int, sudoUID string) bool {
	if euid != 0 || owner == 0 {
		return true
	}
	uid, err := strconv.ParseUint(sudoUID, 10, 32)
	return err == nil && uid == uint64(owner)
}

func saveState(dir string, s state) error {
	if err := os.MkdirAll(dir, 0o755); err != nil { // #nosec G301 -- state dir is 0755 on purpose: an unprivileged step must read what a root step wrote
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(dir, stateFile), b)
}

// stateFileFlags opens nl6.log. The state directory may be shared and
// world-writable (-state /tmp under sudo), so the open never follows a symlink
// planted under the fixed file name. spawnNL6 removes the earlier log first,
// so O_EXCL refuses a file that another user planted after the removal.
const stateFileFlags = os.O_CREATE | os.O_WRONLY | os.O_EXCL | syscall.O_NOFOLLOW

// writeFile writes a file nl6-ci keeps: state.json or the report. The data
// goes to a temporary file that is renamed into place, so a writer that is
// killed leaves the old file or the new one, never a cut one. The rename
// replaces a symlink planted under the name instead of following it.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Chmod(0o644) // #nosec G302 -- world-readable on purpose: an unprivileged step must read what a root step wrote
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		_ = os.Remove(f.Name()) // best-effort, the write error is returned
	}
	return err
}

func removeState(dir string) error {
	err := os.Remove(filepath.Join(dir, stateFile))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
