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

// TestGenerateAliasLeaves covers nl6#787: alias_leaves is copied
// through, and the loader's refusals fire here, where the bindings are
// edited.
func TestGenerateAliasLeaves(t *testing.T) {
	b, err := os.ReadFile("testdata/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	// inject puts fields before the first subtree's "module" and fails
	// when nothing was replaced, so a fixture edit cannot make a row
	// pass for the wrong reason.
	inject := func(t *testing.T, fields string) string {
		t.Helper()
		out := strings.Replace(string(b), `"module"`, fields+`, "module"`, 1)
		if out == string(b) {
			t.Fatal(`fixture has no "module" to inject before`)
		}
		return out
	}
	gen := func(t *testing.T, bindings string) (string, error) {
		t.Helper()
		p := filepath.Join(t.TempDir(), "b.json")
		if err := os.WriteFile(p, []byte(bindings), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "o.json")
		if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
			return "", err
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(got)), " "), nil
	}
	got, err := gen(t, inject(t, `"aliases": ["/vendor/native/sensor/"], "alias_leaves": ["state"]`))
	if err != nil || !strings.Contains(got, `"alias_leaves": [ "state" ]`) {
		t.Fatalf("alias_leaves not copied (%v):\n%s", err, got)
	}
	for _, tc := range []struct{ name, fields, wantErr string }{
		{"without aliases", `"alias_leaves": ["state"]`, "alias_leaves without aliases"},
		{"covering no leaf", `"aliases": ["/vendor/native/sensor/"], "alias_leaves": ["state/nope"]`, `alias_leaves "state/nope" covers no leaf`},
		{"root entry", `"aliases": ["/vendor/native/sensor/"], "alias_leaves": ["/"]`, "must be a non-empty leaf path without keys"},
		{"always outside the scope", `"aliases": ["/vendor/native/sensor/"], "alias_leaves": ["state/counters"], "always": ["state/mtu"]`, "always leaf state/mtu is outside alias_leaves"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gen(t, inject(t, tc.fields)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestGenerateAliasOnlyAndDecimalEncodings covers nl6#790: alias_only
// and per-leaf decimal_encodings are copied through, and the loader's
// refusals fire here, where the bindings are edited.
func TestGenerateAliasOnlyAndDecimalEncodings(t *testing.T) {
	b, err := os.ReadFile("testdata/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	const extra = `"extra": {"properties/property[name=x]/state/value": {"type": "uint64", "gen": "counter:10"}}`
	if !strings.Contains(string(b), extra) {
		t.Fatal("fixture extra block changed; update this test")
	}
	withPower := strings.Replace(string(b), extra, `"extra": {"properties/property[name=x]/state/value": {"type": "uint64", "gen": "counter:10"}, "state/power": {"type": "decimal64", "gen": "const:1.5", "digits": 2}}`, 1)
	gen := func(t *testing.T, fields string) (string, error) {
		t.Helper()
		in := strings.Replace(withPower, `"module"`, fields+`, "module"`, 1)
		p := filepath.Join(t.TempDir(), "b.json")
		if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "o.json")
		if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
			return "", err
		}
		got, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(string(got)), " "), nil
	}
	got, err := gen(t, `"aliases": ["/vendor/native/sensor/"], "alias_only": true, "decimal_encodings": {"state/power": "double"}`)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, `"alias_only": true`) || !strings.Contains(got, `"name": "state/power", "type": "decimal64", "gen": "const:1.5", "digits": 2, "decimal_encoding": "double"`) {
		t.Fatalf("alias_only or decimal_encoding not copied:\n%s", got)
	}
	for _, tc := range []struct{ name, fields, wantErr string }{
		{"alias_only without aliases", `"alias_only": true`, "alias_only without aliases"},
		{"decimal_encoding on a non-decimal leaf", `"decimal_encodings": {"state/mtu": "double"}`, "which is uint32, not decimal64"},
		{"unknown decimal_encoding", `"decimal_encodings": {"state/power": "float"}`, `decimal_encoding "float"`},
		{"decimal_encoding on an unknown leaf", `"decimal_encodings": {"state/nope": "double"}`, "in neither leaves nor extra"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := gen(t, tc.fields); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// TestGenerateCopiesPrefixOriginFields covers nl6#788: the notification's
// aliased_origin_prefix and a subtree's echo_origin reach the catalogue.
func TestGenerateCopiesPrefixOriginFields(t *testing.T) {
	b, err := os.ReadFile("testdata/bindings.json")
	if err != nil {
		t.Fatal(err)
	}
	in := strings.Replace(string(b), `"prefix": "list-entry"`, `"aliased_origin_prefix": "empty", "prefix": "list-entry"`, 1)
	in = strings.Replace(in, `"module"`, `"echo_origin": true, "module"`, 1)
	if strings.Count(in, "aliased_origin_prefix")+strings.Count(in, "echo_origin") != 2 {
		t.Fatal("fixture changed; the injections did not land")
	}
	p := filepath.Join(t.TempDir(), "b.json")
	if err := os.WriteFile(p, []byte(in), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "o.json")
	if err := run([]string{"-yang", "testdata", "-bindings", p, "-out", out}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	flat := strings.Join(strings.Fields(string(got)), " ")
	if !strings.Contains(flat, `"aliased_origin_prefix": "empty"`) || strings.Count(flat, `"echo_origin": true`) != 1 {
		t.Fatalf("prefix origin fields not copied:\n%s", got)
	}
}
