/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestGnmiCatalogNotDrifted regenerates the committed MX10004 catalogue
// from its bindings and diffs. Skips when the YANG cache is absent so CI
// without network still passes; `make gen-gnmi-catalog` populates it.
func TestGnmiCatalogNotDrifted(t *testing.T) {
	cache := os.Getenv("YANG_CACHE")
	if cache == "" {
		home, _ := os.UserHomeDir()
		cache = filepath.Join(home, ".cache", "nl6-yang")
	}
	rel := filepath.Join(cache, "juniper", "24.2", "24.2R1.17")
	if _, err := os.Stat(rel); err != nil {
		t.Skipf("YANG cache %s missing; run make gen-gnmi-catalog", rel)
	}
	out := filepath.Join(t.TempDir(), "gnmi.json")
	cmd := exec.Command("go", "run", "../cmd/gnmi-catalog",
		"-yang", filepath.Join(rel, "openconfig", "models")+","+filepath.Join(rel, "ietf"),
		"-path", filepath.Join(rel, "native", "jti", "models"),
		"-bindings", "resources/juniper_mx10004/gnmi-bindings.json", "-out", out)
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("generator: %v\n%s", err, b)
	}
	got, _ := os.ReadFile(out)
	want, _ := os.ReadFile("resources/juniper_mx10004/gnmi.json")
	if !bytes.Equal(got, want) {
		t.Fatal("resources/juniper_mx10004/gnmi.json differs from generator output; run make gen-gnmi-catalog and commit")
	}
}
