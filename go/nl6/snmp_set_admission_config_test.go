/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The CONFIG half of nl6#690: how the two knobs reach a device, and what must
// never come back out.

// ── REST ───────────────────────────────────────────────────────────────────

// An unrecognised minimum security level is a 400, not a silent default. A
// security knob that is accepted and ignored leaves an operator believing their
// fleet is restricted when it is not, which is strictly worse than the
// nl6#445 family's usual consequence.
func TestCreateDevicesRejectsAnUnknownSetMinSecurityLevel(t *testing.T) {
	body := []byte(`{"start_ip":"10.0.0.1","device_count":1,"netmask":"24",
		"snmpv3":{"enabled":true,"engine_id":"800000090300AABBCCDD","set_min_security_level":"loose"}}`)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
	w := httptest.NewRecorder()

	createDevicesHandler(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 for an unrecognised set_min_security_level", w.Code)
	}
	if !strings.Contains(w.Body.String(), "security level") {
		t.Errorf("the 400 body does not name the field: %s", w.Body.String())
	}
}

// The three spellings the flag takes are the three the REST field takes. One
// constructor serves both, so they cannot drift.
func TestCreateDevicesAcceptsEverySetMinSecurityLevelSpelling(t *testing.T) {
	for _, level := range []string{"none", "auth", "priv", "noAuthNoPriv", "authNoPriv", "authPriv", ""} {
		cfg := &SNMPv3Config{SetMinSecurityLevel: level}
		if _, err := newSetAdmission("secret", cfg); err != nil {
			t.Errorf("newSetAdmission with set_min_security_level %q: %v", level, err)
		}
	}
}

// The write community is WRITE-ONLY. This repo has echoed a credential before
// — GET /api/v1/devices returns the gnmi_dialout block unredacted, which is why
// ca_pem had to be scrubbed of private-key blocks at both entry points — so the
// property is pinned rather than assumed.
//
// It is pinned STRUCTURALLY, by scanning every struct a handler serialises for
// a field that could carry it, because a round-trip test can only prove the
// absence of the value it happened to send.
func TestWriteCommunityIsNeverEchoed(t *testing.T) {
	// Glob + ParseFile rather than parser.ParseDir, which is deprecated as of
	// Go 1.25 for a reason that does not apply here (build tags) but which the
	// linter enforces anyway.
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob the package: %v", err)
	}
	fset := token.NewFileSet()
	var pkg []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		pkg = append(pkg, f)
	}
	if len(pkg) == 0 {
		t.Fatal("no non-test sources parsed; this guard is scanning nothing")
	}

	// CreateDevicesRequest is the one struct allowed to carry it: it is a
	// REQUEST body and is never written to a response (nothing in the package
	// marshals it). Every other struct with a JSON tag is fair game for a
	// response, so none of them may have the field.
	const requestStruct = "CreateDevicesRequest"
	found := map[string]bool{}
	for _, f := range pkg {
		ast.Inspect(f, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, name := range fld.Names {
					if name.Name != "WriteCommunity" {
						continue
					}
					found[ts.Name.Name] = true
					if ts.Name.Name == requestStruct {
						continue
					}
					if fld.Tag != nil && strings.Contains(fld.Tag.Value, "json:") {
						t.Errorf("%s.WriteCommunity carries a json tag (%s); a write community must never "+
							"be serialisable into a response", ts.Name.Name, fld.Tag.Value)
					}
				}
			}
			return true
		})
	}
	if !found[requestStruct] {
		t.Fatalf("no %s.WriteCommunity found; this guard is scanning the wrong thing and would pass "+
			"on a package that had lost the field entirely", requestStruct)
	}

	// Positive control for the same reason: a struct that DID echo it must be
	// caught. Scanning source means the only honest control is a synthetic
	// parse, so parse one.
	ctl, err := parser.ParseFile(token.NewFileSet(), "control.go",
		"package main\ntype LeakyView struct {\n\tWriteCommunity string `json:\"write_community\"`\n}\n", 0)
	if err != nil {
		t.Fatalf("parse the control: %v", err)
	}
	leaked := false
	ast.Inspect(ctl, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			for _, name := range fld.Names {
				if name.Name == "WriteCommunity" && fld.Tag != nil && strings.Contains(fld.Tag.Value, "json:") {
					leaked = true
				}
			}
		}
		return true
	})
	if !leaked {
		t.Fatal("the positive control was not detected; the scan above cannot see a leak either")
	}
}

// ── both creation paths ────────────────────────────────────────────────────

// The two device-creation paths have diverged before, and a device built by the
// parallel path without the admission policy would admit EVERY SET while its
// sequential sibling refused them — a difference visible only at N >= 10, on a
// Linux host, as root.
//
// That is why this is a SOURCE SCAN and not a behavioural test: a batch driven
// to completion needs root and a TUN device, so CI cannot run one. The same
// reasoning and the same shape as the nl6#684-era guard on
// degradeNbar2IfIncapable.
func TestBothDeviceCreationPathsCarryTheSetAdmissionPolicy(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "device.go", nil, 0)
	if err != nil {
		t.Fatalf("parse device.go: %v", err)
	}

	var total, withAdmission int
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		// &SNMPServer{...}
		id, ok := lit.Type.(*ast.Ident)
		if !ok || id.Name != "SNMPServer" {
			return true
		}
		total++
		for _, el := range lit.Elts {
			kv, ok := el.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "setAdmission" {
				withAdmission++
			}
		}
		return true
	})

	if total < 2 {
		t.Fatalf("found %d SNMPServer constructions in device.go, want the 2 creation paths; "+
			"this guard is looking at the wrong thing", total)
	}
	if withAdmission != total {
		t.Errorf("%d of %d SNMPServer constructions in device.go set setAdmission; a path that omits it "+
			"builds a device that admits every SET", withAdmission, total)
	}
}

// The seed is the channel both paths read, and a nil seed must REFUSE rather
// than admit: every caller that passes nil today is a test, and a future one
// that forgets must get the safe answer.
func TestNilExportSeedRefusesEverySet(t *testing.T) {
	got := setAdmissionOf(nil)
	if got.WriteCommunity != "" {
		t.Errorf("a nil seed yielded write community %q, want none", got.WriteCommunity)
	}
	if got.effectiveMinSecurityLevel() != securityLevelAuthNoPriv {
		t.Errorf("a nil seed yielded minimum %v, want authNoPriv", got.effectiveMinSecurityLevel())
	}

	seed := &ExportSeed{SetAdmission: setAdmissionConfig{WriteCommunity: "x", MinSecurityLevel: securityLevelAuthPriv}}
	if setAdmissionOf(seed) != seed.SetAdmission {
		t.Error("setAdmissionOf did not return the seed's policy unchanged")
	}
}

// ── the startup announcement ───────────────────────────────────────────────

// A refused SET is a timeout at the manager, so the log line is the only thing
// that names the cause. It states BOTH halves on every boot.
func TestDescribeStatesBothHalvesAndWarnsWhenTheMinimumIsUnreachable(t *testing.T) {
	rows := []struct {
		name    string
		cfg     setAdmissionConfig
		v3      *SNMPv3Config
		want    []string
		notWant []string
	}{
		{
			name: "shipped default, v3 off",
			cfg:  setAdmissionConfig{},
			v3:   nil,
			want: []string{"refused", "no write community", "authNoPriv", "SNMPv3 disabled"},
		},
		{
			name: "write community set, v3 at md5",
			cfg:  setAdmissionConfig{WriteCommunity: "secret"},
			v3:   &SNMPv3Config{Enabled: true, AuthProtocol: SNMPV3_AUTH_MD5},
			want: []string{"admitted", "authNoPriv"},
			// The community itself is never printed: this line goes to a log
			// an operator may paste into an issue.
			notWant: []string{"secret", "UNREACHABLE"},
		},
		{
			name: "minimum the fleet cannot reach: no auth",
			cfg:  setAdmissionConfig{},
			v3:   &SNMPv3Config{Enabled: true, AuthProtocol: SNMPV3_AUTH_NONE},
			want: []string{"UNREACHABLE", "no authentication protocol"},
		},
		{
			name: "minimum the fleet cannot reach: authPriv without privacy",
			cfg:  setAdmissionConfig{MinSecurityLevel: securityLevelAuthPriv},
			v3:   &SNMPv3Config{Enabled: true, AuthProtocol: SNMPV3_AUTH_MD5, PrivProtocol: SNMPV3_PRIV_NONE},
			want: []string{"UNREACHABLE", "no privacy protocol"},
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := r.cfg.describe(r.v3)
			for _, w := range r.want {
				if !strings.Contains(got, w) {
					t.Errorf("describe() = %q, missing %q", got, w)
				}
			}
			for _, nw := range r.notWant {
				if strings.Contains(got, nw) {
					t.Errorf("describe() = %q, must not contain %q", got, nw)
				}
			}
		})
	}
}
