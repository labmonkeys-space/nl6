/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestVersionFlagPrintsInjectedVersion builds the simulator with a
// known -ldflags injection and asserts that `./nl6 -version`
// prints exactly that string + newline and exits 0. Covers spec
// Requirement 1 (build-time injection) and Requirement 2 (-version
// flag behaviour) in a single round-trip.
func TestVersionFlagPrintsInjectedVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping: builds a binary and execs it")
	}

	const injected = "v99.99.99-test"
	dir := t.TempDir()
	binPath := filepath.Join(dir, "simulator-version-test")

	build := exec.Command("go", "build",
		"-ldflags", "-X main.Version="+injected,
		"-o", binPath,
		".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, out)
	}

	out, err := exec.Command(binPath, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("running -version failed: %v\n%s", err, out)
	}

	got := strings.TrimRight(string(out), "\n")
	if got != injected {
		t.Fatalf("-version stdout = %q, want %q", got, injected)
	}

	// Trailing newline check: spec requires exactly `<version>\n`.
	if !strings.HasSuffix(string(out), "\n") {
		t.Fatalf("-version output missing trailing newline: %q", string(out))
	}
}
