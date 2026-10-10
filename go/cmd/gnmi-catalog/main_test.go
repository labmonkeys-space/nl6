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

func TestGenerateCopiesLeafFilter(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	withFilter := strings.Replace(strings.Replace(strings.Replace(string(b), `"components": []`, `"components": [{"name": "FPC0", "type": "LINECARD", "parent": "", "part_no": "L", "description": "l", "serial_no": "1", "temperature": true}]`, 1),
		`"keys": [{"source": "interfaces"}], "module"`, `"keys": [{"source": "components"}], "module"`, 1),
		`"module"`, `"filters": {"state/mtu": "LINECARD"}, "module"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(withFilter), 0o644)
	out := filepath.Join(t.TempDir(), "o.json")
	if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	flat := strings.Join(strings.Fields(string(got)), " ")
	if !strings.Contains(flat, `"name": "state/mtu", "type": "uint32", "gen": "const:1514", "filter": "LINECARD"`) {
		t.Fatalf("filter not copied onto its leaf:\n%s", got)
	}
	if n := strings.Count(string(got), `"filter"`); n != 1 {
		t.Fatalf("%d leaves carry a filter, want exactly the one named", n)
	}
}

func TestGenerateRejectsFilterOnUnknownLeaf(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	bad := strings.Replace(string(b), `"module"`, `"filters": {"state/nope": "LINECARD"}, "module"`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(bad), 0o644)
	err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), "state/nope") {
		t.Fatalf("filter on unknown leaf accepted: %v", err)
	}
}

func TestGenerateRejectsFilterWithoutComponentsKeyOrVocabulary(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	for _, tc := range []struct{ name, mutate, wantErr string }{
		{"no components key", strings.Replace(string(b), `"module"`, `"filters": {"state/mtu": "LINECARD"}, "module"`, 1), "needs a components key source"},
		{"filter outside the vocabulary", strings.Replace(strings.Replace(strings.Replace(string(b), `"components": []`, `"components": [{"name": "FPC0", "type": "LINECARD", "parent": "", "part_no": "L", "description": "l", "serial_no": "1", "temperature": true}]`, 1),
			`"keys": [{"source": "interfaces"}], "module"`, `"keys": [{"source": "components"}], "module"`, 1),
			`"module"`, `"filters": {"state/mtu": "FAN"}, "module"`, 1), `filter "FAN" on leaf state/mtu matches no component`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.json")
			_ = os.WriteFile(p, []byte(tc.mutate), 0o644)
			err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestGenerateLooksLeavesUpAtYangPath covers nl6#767: the rendered
// prefix is kept as the subtree path while the leaf types come from
// `yang_path`, which never reaches the output.
func TestGenerateLooksLeavesUpAtYangPath(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	moved := strings.Replace(string(b), `"path": "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]", "origin": "openconfig",`,
		`"path": "/rendered/queues[queue-number=*]", "yang_path": "/interfaces/interface/state/counters/out-queue", "origin": "openconfig",`, 1)
	moved = strings.Replace(moved, `"keys": [{"source": "interfaces"}, {"source": "static", "names": ["0", "1"]}], "module": "test-a",`,
		`"keys": [{"source": "static", "names": ["0", "1"]}], "module": "test-a",`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(moved), 0o644)
	out := filepath.Join(t.TempDir(), "o.json")
	if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(out)
	flat := strings.Join(strings.Fields(string(got)), " ")
	if !strings.Contains(flat, `"path": "/rendered/queues[queue-number=*]"`) || !strings.Contains(flat, `"name": "pkts", "type": "uint64"`) {
		t.Fatalf("rendered path or model type lost:\n%s", got)
	}
	if strings.Contains(flat, "yang_path") {
		t.Fatalf("yang_path leaked into the catalogue:\n%s", got)
	}
}

func TestGenerateRejectsYangPathOutsideModel(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	bad := strings.Replace(string(b), `"path": "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]", "origin": "openconfig",`,
		`"path": "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]", "yang_path": "/interfaces/interface/state/no-such-container", "origin": "openconfig",`, 1)
	p := filepath.Join(t.TempDir(), "b.json")
	_ = os.WriteFile(p, []byte(bad), 0o644)
	err := run([]string{"-yang", "testdata", "-bindings", p, "-out", filepath.Join(t.TempDir(), "o.json")})
	if err == nil || !strings.Contains(err.Error(), "out-queue") || !strings.Contains(err.Error(), "no-such-container") {
		t.Fatalf("bad yang_path accepted: %v", err)
	}
}

// TestGenerateMapsNativeModuleToNativeOrigin: a module used only by
// native-origin subtrees becomes an alias of native_origin (nl6#767),
// so a native sensor needs no hand-written origin alias.
func TestGenerateMapsNativeModuleToNativeOrigin(t *testing.T) {
	b, _ := os.ReadFile("testdata/bindings.json")
	native := strings.Replace(string(b), `"path": "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]", "origin": "openconfig",
      "keys": [{"source": "interfaces"}, {"source": "static", "names": ["0", "1"]}], "module": "test-a",`,
		`"path": "/interfaces/interface[name=*]/state/counters/out-queue[queue-number=*]", "origin": "testvendor",
      "keys": [{"source": "interfaces"}, {"source": "static", "names": ["0", "1"]}], "module": "test-a",`, 1)
	if native == string(b) {
		t.Fatal("fixture mutation did not apply")
	}
	for _, tc := range []struct{ name, data, want string }{
		{"shared by both origins", string(b), `"test-a": "openconfig"`},
		{"module under the native origin only", strings.Replace(strings.Replace(native, `"module": "test-a",
      "leaves": {"state/oper-status"`, `"module": "test-a",
      "leaves": {"state/oper-status"`, 1), `"origin": "openconfig", "keys": [{"source": "interfaces"}], "module": "test-a"`, `"origin": "testvendor", "keys": [{"source": "interfaces"}], "module": "test-a"`, 1), `"test-a": "testvendor"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "b.json")
			_ = os.WriteFile(p, []byte(tc.data), 0o644)
			out := filepath.Join(t.TempDir(), "o.json")
			if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
				t.Fatal(err)
			}
			got, _ := os.ReadFile(out)
			if !strings.Contains(string(got), tc.want) {
				t.Fatalf("want %s in:\n%s", tc.want, got)
			}
		})
	}
}
