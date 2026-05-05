/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTrapCatalog_ExtendedVocabularyAccepted confirms all five Class 1
// fields (SysName, Model, Serial, ChassisID, IfName) are accepted by
// the trap catalog loader as valid template references. Each appears
// in a separate catalog entry so one field's validation logic can't
// accidentally pass another.
func TestTrapCatalog_ExtendedVocabularyAccepted(t *testing.T) {
	body := `{"traps":[
		{"name":"useSysName","snmpTrapOID":"1.2.3.1","varbinds":[{"oid":"1.2.3.100","type":"octet-string","value":"host={{.SysName}}"}]},
		{"name":"useModel","snmpTrapOID":"1.2.3.2","varbinds":[{"oid":"1.2.3.101","type":"octet-string","value":"model={{.Model}}"}]},
		{"name":"useSerial","snmpTrapOID":"1.2.3.3","varbinds":[{"oid":"1.2.3.102","type":"octet-string","value":"sn={{.Serial}}"}]},
		{"name":"useChassisID","snmpTrapOID":"1.2.3.4","varbinds":[{"oid":"1.2.3.103","type":"octet-string","value":"cid={{.ChassisID}}"}]},
		{"name":"useIfName","snmpTrapOID":"1.2.3.5","varbinds":[{"oid":"1.2.3.104","type":"octet-string","value":"ifn={{.IfName}}"}]}
	]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatalf("catalog load: %v", err)
	}
	if len(cat.Entries) != 5 {
		t.Errorf("entries: got %d, want 5", len(cat.Entries))
	}
}

// TestTrapCatalog_ClassTwoFieldsRejected pins that Class 2 random-
// per-fire fields (deferred to a future change) produce a clear error
// at catalog load — this prevents a vendor catalog from silently using
// an unimplemented field name.
func TestTrapCatalog_ClassTwoFieldsRejected(t *testing.T) {
	cases := []string{"PeerIP", "PeerAS", "User", "SourceIP", "RuleName", "SrcZone", "DstZone", "NotAField"}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			body := `{"traps":[{"name":"x","snmpTrapOID":"1.2.3","varbinds":[` +
				`{"oid":"1.2.3.{{.` + field + `}}","type":"integer","value":"1"}]}]}`
			path := filepath.Join(t.TempDir(), "c.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadCatalogFromFile(path)
			if err == nil {
				t.Fatalf("%s should be rejected", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error should name the offending field; got %v", err)
			}
		})
	}
}

// TestSyslogCatalog_ExtendedVocabularyAccepted is the syslog mirror —
// Model, Serial, ChassisID are new to the syslog vocabulary (SysName
// and IfName already existed).
func TestSyslogCatalog_ExtendedVocabularyAccepted(t *testing.T) {
	body := `{"entries":[
		{"name":"m","facility":"local7","severity":"notice","appName":"T","template":"model={{.Model}}"},
		{"name":"s","facility":"local7","severity":"notice","appName":"T","template":"sn={{.Serial}}"},
		{"name":"c","facility":"local7","severity":"notice","appName":"T","template":"cid={{.ChassisID}}"}
	]}`
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadSyslogCatalogFromFile(path)
	if err != nil {
		t.Fatalf("catalog load: %v", err)
	}
	if len(cat.Entries) != 3 {
		t.Errorf("entries: got %d, want 3", len(cat.Entries))
	}
}

// TestSyslogCatalog_ClassTwoFieldsRejected — symmetric with trap.
func TestSyslogCatalog_ClassTwoFieldsRejected(t *testing.T) {
	cases := []string{"PeerIP", "User", "SourceIP", "RuleName"}
	for _, field := range cases {
		t.Run(field, func(t *testing.T) {
			body := `{"entries":[{"name":"x","facility":"local7","severity":"notice","appName":"T","template":"foo={{.` + field + `}}"}]}`
			path := filepath.Join(t.TempDir(), "s.json")
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := LoadSyslogCatalogFromFile(path)
			if err == nil {
				t.Fatalf("%s should be rejected", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error should name the offending field; got %v", err)
			}
		})
	}
}

// TestCatalogEntry_Resolve_NewFieldsFromCtx confirms end-to-end that
// the Class 1 fields set on TemplateCtx make it into the resolved
// varbind output. Covers the full per-fire path from ctx → template
// evaluation.
func TestCatalogEntry_Resolve_NewFieldsFromCtx(t *testing.T) {
	body := `{"traps":[{"name":"all","snmpTrapOID":"1.2.3",
		"varbinds":[{"oid":"1.2.3.100","type":"octet-string","value":"sys={{.SysName}} mod={{.Model}} sn={{.Serial}} cid={{.ChassisID}} ifn={{.IfName}}"}]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := TemplateCtx{
		IfIndex:   3,
		IfName:    "GigabitEthernet0/3",
		Uptime:    100,
		Now:       1700000000,
		DeviceIP:  "10.42.0.1",
		SysName:   "rtr-dc-01",
		Model:     "Cisco IOS",
		Serial:    "SN0A2A0001",
		ChassisID: "02:42:0a:2a:00:01",
	}
	vbs, err := cat.Entries[0].Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "sys=rtr-dc-01 mod=Cisco IOS sn=SN0A2A0001 cid=02:42:0a:2a:00:01 ifn=GigabitEthernet0/3"
	if vbs[0].Value != want {
		t.Errorf("resolved value:\n got %q\nwant %q", vbs[0].Value, want)
	}
}

// TestCatalogEntry_Resolve_NewFieldOverrides confirms the POST-trap
// override path now accepts overrides for each Class 1 field.
func TestCatalogEntry_Resolve_NewFieldOverrides(t *testing.T) {
	body := `{"traps":[{"name":"all","snmpTrapOID":"1.2.3",
		"varbinds":[{"oid":"1.2.3.100","type":"octet-string","value":"{{.SysName}}|{{.Model}}|{{.Serial}}|{{.ChassisID}}|{{.IfName}}"}]}]}`
	path := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := TemplateCtx{SysName: "base-sys", Model: "base-mod", Serial: "base-sn", ChassisID: "base-cid", IfName: "base-ifn"}
	overrides := map[string]string{
		"SysName":   "override-sys",
		"Model":     "override-mod",
		"Serial":    "override-sn",
		"ChassisID": "override-cid",
		"IfName":    "override-ifn",
	}
	vbs, err := cat.Entries[0].Resolve(ctx, overrides)
	if err != nil {
		t.Fatal(err)
	}
	want := "override-sys|override-mod|override-sn|override-cid|override-ifn"
	if vbs[0].Value != want {
		t.Errorf("override resolve:\n got %q\nwant %q", vbs[0].Value, want)
	}
}

// TestSyslogCatalogEntry_Resolve_NewFieldsFromCtx is the symmetric
// syslog end-to-end test for the trap-side `TestCatalogEntry_Resolve_NewFieldsFromCtx`.
// Covers Class 1 field resolution through the full syslog load →
// Resolve → rendered message path so future regressions in either
// vocabulary surface equally on both sides.
func TestSyslogCatalogEntry_Resolve_NewFieldsFromCtx(t *testing.T) {
	body := `{"entries":[{"name":"all","facility":"local7","severity":"notice","appName":"T",
		"template":"model={{.Model}} sn={{.Serial}} cid={{.ChassisID}} host={{.SysName}} ifn={{.IfName}}"}]}`
	path := filepath.Join(t.TempDir(), "s.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cat, err := LoadSyslogCatalogFromFile(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := SyslogTemplateCtx{
		DeviceIP:  "10.42.0.1",
		SysName:   "rtr-dc-01",
		IfIndex:   3,
		IfName:    "TenGigE0/0/0/3",
		Now:       1700000000,
		Uptime:    100,
		Model:     "Cisco IOS",
		Serial:    "SN0A2A0001",
		ChassisID: "02:42:0a:2a:00:01",
	}
	resolved, err := cat.Entries[0].Resolve(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := "model=Cisco IOS sn=SN0A2A0001 cid=02:42:0a:2a:00:01 host=rtr-dc-01 ifn=TenGigE0/0/0/3"
	if resolved.Message != want {
		t.Errorf("resolved message:\n got %q\nwant %q", resolved.Message, want)
	}
}

// BenchmarkTemplateResolve_NineFieldVocab exercises the per-fire
// Resolve path with the full nine-field vocabulary so a regression
// inflating the render cost (e.g., dynamic reflection, string
// allocation on every field) would surface. Target: <50µs per fire
// per the design spec (§D3 / tasks 2.12).
func BenchmarkTemplateResolve_NineFieldVocab(b *testing.B) {
	body := `{"traps":[{"name":"all","snmpTrapOID":"1.2.3",
		"varbinds":[{"oid":"1.2.3.{{.IfIndex}}","type":"octet-string","value":"t={{.Uptime}} n={{.Now}} ip={{.DeviceIP}} sys={{.SysName}} mod={{.Model}} sn={{.Serial}} cid={{.ChassisID}} ifn={{.IfName}}"}]}]}`
	tmp := b.TempDir()
	path := filepath.Join(tmp, "c.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		b.Fatal(err)
	}
	cat, err := LoadCatalogFromFile(path)
	if err != nil {
		b.Fatal(err)
	}
	ctx := TemplateCtx{
		IfIndex: 3, IfName: "GigabitEthernet0/3",
		Uptime: 100, Now: time.Now().Unix(), DeviceIP: "10.42.0.1",
		SysName: "rtr-dc-01", Model: "Cisco IOS",
		Serial: "SN0A2A0001", ChassisID: "02:42:0a:2a:00:01",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cat.Entries[0].Resolve(ctx, nil)
		if err != nil {
			b.Fatal(err)
		}
	}
}
