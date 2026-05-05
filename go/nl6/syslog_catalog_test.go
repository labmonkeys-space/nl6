/*
 * © 2025 Labmonkeys Space
 * Apache-2.0 — see LICENSE.
 */

package main

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmbeddedSyslogCatalogParses is the primary smoke test: the default
// catalog shipped via //go:embed must load with no errors and contain exactly
// the six universal entries listed in design.md §D10.
func TestEmbeddedSyslogCatalogParses(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedSyslogCatalog: %v", err)
	}
	wantNames := []string{
		"interface-up", "interface-down",
		"auth-success", "auth-failure",
		"config-change", "system-restart",
	}
	if got, want := len(cat.Entries), len(wantNames); got != want {
		t.Fatalf("entry count: got %d, want %d", got, want)
	}
	for _, n := range wantNames {
		if _, ok := cat.ByName[n]; !ok {
			t.Errorf("entry %q missing from embedded catalog", n)
		}
	}
	// Total weight per design.md §D10 = 40 + 40 + 20 + 20 + 10 + 5 = 135.
	if got := cat.totalWeight; got != 135 {
		t.Errorf("totalWeight: got %d, want 135", got)
	}
}

// TestSyslogCatalogInvalidJSON ensures malformed JSON gives a clear error.
func TestSyslogCatalogInvalidJSON(t *testing.T) {
	_, err := parseSyslogCatalog([]byte(`{"entries": [`), "<test>")
	if err == nil {
		t.Fatal("parseSyslogCatalog: expected error on malformed JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing") {
		t.Errorf("error text: got %q, want mention of parsing", err.Error())
	}
}

// TestSyslogCatalogOutOfRangeSeverity exercises both the integer-range
// check and the unknown-name check on severity.
func TestSyslogCatalogOutOfRangeSeverity(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{
			name: "int too high",
			body: `{"entries":[{"name":"x","facility":"user","severity":8,"appName":"a","template":"m"}]}`,
			want: "out of range",
		},
		{
			name: "unknown string",
			body: `{"entries":[{"name":"x","facility":"user","severity":"notASeverity","appName":"a","template":"m"}]}`,
			want: "unknown severity name",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseSyslogCatalog([]byte(tc.body), "<test>")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q: want substring %q", err.Error(), tc.want)
			}
		})
	}
}

// TestSyslogCatalogUnknownFacility covers the facility side of the enum check.
func TestSyslogCatalogUnknownFacility(t *testing.T) {
	body := `{"entries":[{"name":"x","facility":"notAFacility","severity":"info","appName":"a","template":"m"}]}`
	_, err := parseSyslogCatalog([]byte(body), "<test>")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown facility name") {
		t.Errorf("error %q: want 'unknown facility name'", err.Error())
	}
}

// TestSyslogCatalogUnknownTemplateField rejects {{.NotAField}} at load.
func TestSyslogCatalogUnknownTemplateField(t *testing.T) {
	body := `{"entries":[{"name":"x","facility":"user","severity":"info","appName":"a","template":"hi {{.NotAField}}"}]}`
	_, err := parseSyslogCatalog([]byte(body), "<test>")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unknown template field") || !strings.Contains(err.Error(), "NotAField") {
		t.Errorf("error %q: want mention of unknown template field and field name", err.Error())
	}
}

// TestSyslogCatalogOversizeRejected exercises the §D12 MTU-safety guard. A
// template that renders beyond maxSyslogMessageBytes must be rejected at
// load time rather than producing truncated wire output at fire time.
func TestSyslogCatalogOversizeRejected(t *testing.T) {
	big := strings.Repeat("A", maxSyslogMessageBytes+100)
	body := `{"entries":[{"name":"x","facility":"user","severity":"info","appName":"a","template":"` + big + `"}]}`
	_, err := parseSyslogCatalog([]byte(body), "<test>")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "MTU-safety") {
		t.Errorf("error %q: want mention of MTU-safety", err.Error())
	}
}

// TestSyslogCatalogPickDistribution verifies that Pick honours weights
// within a reasonable tolerance. 10000 draws over a 40/10 split should
// see the heavier entry ~8000 times (+/- a few %).
func TestSyslogCatalogPickDistribution(t *testing.T) {
	body := `{"entries":[
		{"name":"heavy","facility":"user","severity":"info","appName":"a","template":"h","weight":40},
		{"name":"light","facility":"user","severity":"info","appName":"a","template":"l","weight":10}
	]}`
	cat, err := parseSyslogCatalog([]byte(body), "<test>")
	if err != nil {
		t.Fatal(err)
	}
	rnd := rand.New(rand.NewSource(0xC0FFEE))
	counts := map[string]int{}
	const draws = 10000
	for i := 0; i < draws; i++ {
		e := cat.Pick(rnd)
		counts[e.Name]++
	}
	// Expected ratio: heavy:light = 40:10 = 4:1 → heavy ≈ 8000, light ≈ 2000.
	// Tolerance: ±5% of draws = ±500 in absolute count.
	const tol = 500
	if got := counts["heavy"]; got < 8000-tol || got > 8000+tol {
		t.Errorf("heavy count %d outside 8000±%d", got, tol)
	}
	if got := counts["light"]; got < 2000-tol || got > 2000+tol {
		t.Errorf("light count %d outside 2000±%d", got, tol)
	}
}

// TestSyslogCatalogResolveNoOverrides renders a template with IfIndex/IfName.
func TestSyslogCatalogResolveNoOverrides(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	if e == nil {
		t.Fatal("interface-down missing from embedded catalog")
	}
	ctx := SyslogTemplateCtx{
		DeviceIP: "10.42.0.1",
		IfIndex:  3,
		IfName:   "GigabitEthernet0/3",
		Now:      1700000000,
		Uptime:   123456,
	}
	msg, err := e.Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Message, "GigabitEthernet0/3") {
		t.Errorf("resolved message %q missing IfName", msg.Message)
	}
	if !strings.Contains(msg.Message, "ifIndex=3") {
		t.Errorf("resolved message %q missing IfIndex", msg.Message)
	}
	// Structured data should be populated with the same two fields.
	if len(msg.StructuredData) != 2 {
		t.Fatalf("structuredData pairs: got %d, want 2", len(msg.StructuredData))
	}
	gotSD := map[string]string{}
	for _, kv := range msg.StructuredData {
		gotSD[kv.Key] = kv.Value
	}
	if gotSD["ifIndex"] != "3" || gotSD["ifName"] != "GigabitEthernet0/3" {
		t.Errorf("structuredData resolved wrong: %v", gotSD)
	}
}

// TestSyslogCatalogResolveOverrides shows that templateOverrides from the
// HTTP endpoint pin template fields deterministically.
func TestSyslogCatalogResolveOverrides(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	ctx := SyslogTemplateCtx{IfIndex: 1, IfName: "lo"}
	msg, err := e.Resolve(ctx, map[string]string{
		"IfIndex": "7",
		"IfName":  "GigabitEthernet0/7",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg.Message, "ifIndex=7") {
		t.Errorf("override did not apply: %q", msg.Message)
	}
	if !strings.Contains(msg.Message, "GigabitEthernet0/7") {
		t.Errorf("IfName override did not apply: %q", msg.Message)
	}
}

// TestSyslogCatalogResolveUnknownOverride rejects unknown override keys.
func TestSyslogCatalogResolveUnknownOverride(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	_, err = e.Resolve(SyslogTemplateCtx{}, map[string]string{"NotAField": "v"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "NotAField") {
		t.Errorf("error %q: want mention of NotAField", err.Error())
	}
}

// TestSyslogCatalogDuplicateName rejects two entries with the same name.
func TestSyslogCatalogDuplicateName(t *testing.T) {
	body := `{"entries":[
		{"name":"dup","facility":"user","severity":"info","appName":"a","template":"a"},
		{"name":"dup","facility":"user","severity":"info","appName":"a","template":"b"}
	]}`
	_, err := parseSyslogCatalog([]byte(body), "<test>")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "duplicate name") {
		t.Errorf("error %q: want 'duplicate name'", err.Error())
	}
}

// TestSyslogCatalogFacilityIntegerAccepted verifies both string name and
// integer syntax parse for facility (same for severity, implicitly covered
// by the out-of-range tests above).
func TestSyslogCatalogFacilityIntegerAccepted(t *testing.T) {
	body := `{"entries":[{"name":"x","facility":23,"severity":3,"appName":"a","template":"m"}]}`
	cat, err := parseSyslogCatalog([]byte(body), "<test>")
	if err != nil {
		t.Fatal(err)
	}
	if cat.Entries[0].Facility != 23 {
		t.Errorf("facility: got %d, want 23", cat.Entries[0].Facility)
	}
	if cat.Entries[0].Severity != 3 {
		t.Errorf("severity: got %d, want 3", cat.Entries[0].Severity)
	}
}

// TestSyslogCatalogEmptyAppNameRejected — empty `appName` is a catalog
// error because RFC 3164 has no NILVALUE for the TAG field.
func TestSyslogCatalogEmptyAppNameRejected(t *testing.T) {
	body := `{"entries":[{"name":"x","facility":"user","severity":"info","template":"m"}]}`
	_, err := parseSyslogCatalog([]byte(body), "<test>")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "appName is required") {
		t.Errorf("error %q: want mention of appName required", err.Error())
	}
}

// TestSyslogCatalogSDNameInvalid covers the RFC 5424 §6.3.3 SD-NAME
// grammar rejection: keys containing SP, =, ], ", or non-printable ASCII.
func TestSyslogCatalogSDNameInvalid(t *testing.T) {
	cases := []struct {
		name string
		key  string
	}{
		{"space in key", "has space"},
		{"equals in key", "a=b"},
		{"quote in key", `bad"`},
		{"bracket in key", "bad]"},
		{"empty key", ""},
		{"too long", strings.Repeat("x", 33)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"entries":[{"name":"x","facility":"user","severity":"info","appName":"a","structuredData":{"` +
				strings.ReplaceAll(strings.ReplaceAll(tc.key, `\`, `\\`), `"`, `\"`) +
				`":"v"},"template":"m"}]}`
			_, err := parseSyslogCatalog([]byte(body), "<test>")
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), "SD-NAME") {
				t.Errorf("error %q: want SD-NAME mention", err.Error())
			}
		})
	}
}

// TestSyslogCatalogParseIntStrict covers the strconv.Atoi tightening —
// `fmt.Sscanf` previously accepted `"3abc"` as 3 silently.
func TestSyslogCatalogParseIntStrict(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	for _, bad := range []string{"3abc", "", " 3", "3 ", "12.5"} {
		if _, err := e.Resolve(SyslogTemplateCtx{}, map[string]string{"IfIndex": bad}); err == nil {
			t.Errorf("expected error on IfIndex=%q, got nil", bad)
		}
	}
	// Negative numbers are still accepted (they parse as valid integers).
	// If the app wants to reject negatives it must do so at a higher layer.
	if _, err := e.Resolve(SyslogTemplateCtx{}, map[string]string{"IfIndex": "-1"}); err != nil {
		t.Errorf("negative IfIndex should parse: %v", err)
	}
}

// TestSyslogCatalogSDTemplatesPreCompiled verifies that SD templates are
// parsed at catalog load — the pre-compiled `*template.Template` is stored
// on the entry, not re-parsed at every Resolve call.
func TestSyslogCatalogSDTemplatesPreCompiled(t *testing.T) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	if len(e.StructuredData) == 0 {
		t.Fatal("interface-down has no structured data")
	}
	// At least one SD entry has a templated value (ifIndex -> "{{.IfIndex}}");
	// assert it has a non-nil pre-compiled template.
	foundTmpl := false
	for _, sd := range e.StructuredData {
		if sd.Tmpl != nil {
			foundTmpl = true
		}
	}
	if !foundTmpl {
		t.Error("expected at least one pre-compiled SD template on interface-down")
	}
}

// TestSyslogCatalogFileOverrideReplaces covers the spec scenario
// "File override replaces embedded catalog" (Requirement "Syslog catalog
// structure and loading"). Writes a minimal catalog file with three
// custom entries and asserts the six universal entries are absent.
func TestSyslogCatalogFileOverrideReplaces(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "custom.json")
	body := `{"entries":[
		{"name":"alpha","facility":"user","severity":"info","appName":"a","template":"A"},
		{"name":"beta","facility":"user","severity":"info","appName":"a","template":"B"},
		{"name":"gamma","facility":"user","severity":"info","appName":"a","template":"C"}
	]}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadSyslogCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := len(cat.Entries), 3; got != want {
		t.Fatalf("entry count: got %d, want %d", got, want)
	}
	for _, name := range []string{"interface-up", "interface-down", "auth-success", "auth-failure", "config-change", "system-restart"} {
		if _, ok := cat.ByName[name]; ok {
			t.Errorf("universal entry %q unexpectedly present in file-override catalog", name)
		}
	}
	for _, name := range []string{"alpha", "beta", "gamma"} {
		if _, ok := cat.ByName[name]; !ok {
			t.Errorf("custom entry %q missing from file-override catalog", name)
		}
	}
}

// BenchmarkSyslogResolve covers the spec scenario "Template evaluation
// is not N² at scale" — mean per-fire Resolve SHALL be < 50 µs.
func BenchmarkSyslogResolve(b *testing.B) {
	cat, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		b.Fatal(err)
	}
	e := cat.ByName["interface-down"]
	ctx := SyslogTemplateCtx{
		DeviceIP: "10.42.0.1",
		SysName:  "rtr-edge-01",
		IfIndex:  3,
		IfName:   "GigabitEthernet0/3",
		Now:      1700000000,
		Uptime:   123456,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := e.Resolve(ctx, nil); err != nil {
			b.Fatal(err)
		}
	}
}
