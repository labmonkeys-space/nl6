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
	err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), "removed-by-deviation") {
		t.Fatalf("deviated leaf accepted: %v", err)
	}
}

func TestGenerateRejectsUnresolvableDeviation(t *testing.T) {
	dir := t.TempDir()
	// test-dev-bogus is stored as .yang.in so the golden run, which
	// walks all of testdata, does not load it.
	for src, dst := range map[string]string{
		"test-a.yang": "test-a.yang", "test-dev.yang": "test-dev.yang", "test-dev-bogus.yang.in": "test-dev-bogus.yang",
	} {
		b, err := os.ReadFile(filepath.Join("testdata", src))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, dst), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	err := run([]string{"-yang", dir, "-bindings", "testdata/bindings.json", "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), "/ta:interfaces/ta:interface/ta:state/ta:no-such-leaf") {
		t.Fatalf("unresolvable deviation accepted: %v", err)
	}
}

func TestGenerateCopiesAliases(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	withAlias := strings.Replace(string(b), `"module"`, `"aliases": ["/vendor/native/sensor/"], "module"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(withAlias), 0o644)
	out := filepath.Join(t.TempDir(), "o.json")
	if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	if !strings.Contains(string(got), `"aliases": [
        "/vendor/native/sensor/"
      ],`) {
		t.Fatalf("aliases not copied verbatim:\n%s", got)
	}
}

func TestGenerateRejectsUnknownBindingsField(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	bad := strings.Replace(string(b), `"module"`, `"modul": "x", "module"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(bad), 0o644)
	err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), `unknown field "modul"`) {
		t.Fatalf("misspelt bindings field accepted: %v", err)
	}
}
