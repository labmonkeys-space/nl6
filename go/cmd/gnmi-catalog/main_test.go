/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateMatchesGolden(t *testing.T) {
	out := filepath.Join(t.TempDir(), "out.json")
	if err := run([]string{"-yang", "testdata", "-bindings", "testdata/bindings.json", "-out", out}); err != nil {
		t.Fatalf("run: %v", err)
	}
	got, _ := os.ReadFile(out)
	want, err := os.ReadFile("testdata/golden.json")
	if err != nil {
		t.Fatalf("golden missing; run the tool once and review its output: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("output differs from golden:\n%s", got)
	}
}

func TestGenerateRejectsUnknownLeaf(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	bad := strings.Replace(string(b), `"state/mtu": "const:1514"`, `"state/mtuu": "const:1514"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(bad), 0o644)
	err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), "state/mtuu") {
		t.Fatalf("unknown leaf accepted: %v", err)
	}
}

func TestGenerateRejectsDeviatedLeaf(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	bad := strings.Replace(string(b), `"state/mtu": "const:1514"`, `"state/removed-by-deviation": "const:x"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(bad), 0o644)
	if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")}); err == nil {
		t.Fatal("deviated leaf accepted")
	}
}
