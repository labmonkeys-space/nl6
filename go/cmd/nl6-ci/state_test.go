/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestStateRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sub")
	want := state{PID: 42, API: "http://127.0.0.1:18080", Log: dir + "/nl6.log", Devices: 7}
	if err := saveState(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := loadState(dir)
	if err != nil || got != want {
		t.Fatalf("got %+v, %v", got, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, stateFile))
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("file mode %v", fi.Mode().Perm())
	}
}

func TestLoadStateAbsent(t *testing.T) {
	_, err := loadState(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestLoadStateCorrupt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, stateFile), []byte("{"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadState(dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}

func TestResolveStateDir(t *testing.T) {
	t.Setenv("NL6_CI_STATE", "/env")
	if got := resolveStateDir("/flag"); got != "/flag" {
		t.Error(got)
	}
	if got := resolveStateDir(""); got != "/env" {
		t.Error(got)
	}
	t.Setenv("NL6_CI_STATE", "")
	if got := resolveStateDir(""); got != ".nl6-ci" {
		t.Error(got)
	}
}

func TestSaveStateNeverFollowsASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	// The rename replaces the link itself.
	if err := saveState(dir, state{PID: 42}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the symlink target was overwritten: %q", b)
	}
	if fi, err := os.Lstat(filepath.Join(dir, stateFile)); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("state.json is not a regular file: %v, %v", fi, err)
	}
}

// A failed write leaves the earlier file and no temporary file. A directory
// under the target name makes the rename fail.
func TestWriteFileLeavesNothingBehindWhenItFails(t *testing.T) {
	dir := t.TempDir()
	if err := saveState(dir, state{PID: 42}); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "blocked")
	if err := os.Mkdir(blocked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(blocked, []byte("x")); err == nil {
		t.Fatal("writeFile replaced a directory")
	}
	if s, err := loadState(dir); err != nil || s.PID != 42 {
		t.Fatalf("state %+v, %v", s, err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("entries %v: a temporary file was left behind", entries)
	}
}

// Root signals the pid and prints the log that state.json names, so under
// root only root's own file and the sudo caller's file count.
func TestTrustedOwner(t *testing.T) {
	for _, tc := range []struct {
		name    string
		owner   uint32
		euid    int
		sudoUID string
		want    bool
	}{
		{"no root, any owner", 1001, 1000, "", true},
		{"root, root's file", 0, 0, "", true},
		{"root, the sudo caller's file", 1000, 0, "1000", true},
		{"root, another user's file", 1001, 0, "1000", false},
		{"root login, another user's file", 1001, 0, "", false},
		{"root, SUDO_UID is no number", 1001, 0, "x", false},
	} {
		if got := trustedOwner(tc.owner, tc.euid, tc.sudoUID); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A symlink planted under the state name is not followed, whatever it names.
func TestLoadStateRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte(`{"pid":42}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, stateFile)); err != nil {
		t.Fatal(err)
	}
	if s, err := loadState(dir); err == nil || errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %+v, %v", s, err)
	}
}
