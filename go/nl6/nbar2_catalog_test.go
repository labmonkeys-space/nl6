/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nbar2JSON builds a catalog document from entry fragments so each rule test
// plants exactly one violation in an otherwise valid file.
func nbar2JSON(extends string, entries ...string) []byte {
	head := "{"
	if extends != "" {
		head += `"extends": ` + extends + ", "
	}
	return []byte(head + `"entries": [` + strings.Join(entries, ",") + "]}")
}

const nbar2GoodHTTP = `{"name":"http","description":"HTTP","engine":3,"selector":80,"proto":"tcp","dst_port":80,"weight":30,
  "hosts":[{"value":"www.example.com","weight":2},{"value":"cdn.example.net"}],"uris":[{"value":"/"},{"value":"/index.html"}]}`
const nbar2GoodDNS = `{"name":"dns","description":"DNS","engine":3,"selector":53,"proto":"udp","dst_port":53,"weight":10}`

func TestNbar2CatalogPacksApplicationID(t *testing.T) {
	cat, err := parseNbar2Catalog(nbar2JSON("",
		`{"name":"l7","description":"x","engine":13,"selector":80,"proto":"tcp","dst_port":80}`), "t")
	if err != nil {
		t.Fatal(err)
	}
	e := cat.ByName["l7"]
	if e.ID != 0x0D000050 {
		t.Fatalf("ID = %#x, want 0x0D000050", e.ID)
	}
	if e.Proto != 6 || e.Weight != 1 {
		t.Fatalf("proto=%d weight=%d, want tcp=6 and default weight 1", e.Proto, e.Weight)
	}
	if !cat.Extends {
		t.Fatal("extends must default to true")
	}
}

// Every load rule, each with a positive control that plants the violation
// and requires the rule to fire naming file and entry (nl6#571's rule: a
// guard asserting zero of something cannot fail on its own).
func TestNbar2CatalogRulesReject(t *testing.T) {
	cases := []struct {
		name string
		doc  []byte
		want string
	}{
		{"no entries", []byte(`{"entries":[]}`), "has no entries"},
		{"unknown field", []byte(`{"entries":[],"catalog":"x"}`), "unknown field"},
		{"unknown engine", nbar2JSON("", `{"name":"a","engine":7,"selector":1,"proto":"tcp","dst_port":1}`), "engine 7 is not one of"},
		{"selector too wide", nbar2JSON("", `{"name":"a","engine":3,"selector":16777216,"proto":"tcp","dst_port":1}`), "selector 16777216 out of range"},
		{"bad proto", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"sctp","dst_port":1}`), "proto must be tcp, udp, icmp"},
		{"port too wide", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"tcp","dst_port":70000}`), "dst_port 70000 out of range"},
		{"icmp with port", nbar2JSON("", `{"name":"a","engine":6,"selector":1,"proto":"icmp","dst_port":443}`), "icmp carries no port"},
		// Absent keys are not zero values: an entry without proto used to
		// load as IP protocol 0 and go on the wire that way (PR #673 review).
		{"missing proto", nbar2JSON("", `{"name":"a","engine":6,"selector":1,"dst_port":443}`), "proto is required"},
		{"missing dst_port on tcp", nbar2JSON("", `{"name":"a","engine":6,"selector":1,"proto":"tcp"}`), "dst_port is required"},
		{"name too long", nbar2JSON("", `{"name":"`+strings.Repeat("n", 25)+`","engine":3,"selector":1,"proto":"tcp","dst_port":1}`), "name is 25 bytes, over the 24-byte"},
		{"description too long", nbar2JSON("", `{"name":"a","description":"`+strings.Repeat("d", 56)+`","engine":3,"selector":1,"proto":"tcp","dst_port":1}`), "description is 56 bytes, over the 55-byte"},
		{"negative weight", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"tcp","dst_port":1,"weight":-1}`), "weight must be positive"},
		{"empty host value", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"tcp","dst_port":1,"hosts":[{"value":""}]}`), "hosts[0]: value is required"},
		{"uri too long", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"tcp","dst_port":1,"uris":[{"value":"`+strings.Repeat("u", 65536)+`"}]}`), "uris[0]: value is 65536 bytes, over the RFC 7011"},
		{"negative host weight", nbar2JSON("", `{"name":"a","engine":3,"selector":1,"proto":"tcp","dst_port":1,"hosts":[{"value":"h","weight":-2}]}`), "hosts[0]: weight must be positive"},
		{"duplicate name", nbar2JSON("", nbar2GoodHTTP, nbar2GoodHTTP), `duplicate name "http"`},
		{"duplicate id", nbar2JSON("", nbar2GoodHTTP, `{"name":"http2","engine":3,"selector":80,"proto":"tcp","dst_port":8080}`), `applicationId 0x3000050 (engine 3, selector 80) is already used by "http"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNbar2Catalog(tc.doc, "planted.json")
			if err == nil {
				t.Fatalf("loaded; the %s rule did not fire", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %q, want it to contain %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), "planted.json") {
				t.Fatalf("error = %q does not name the file", err)
			}
		})
	}
	// Control: the good fragments load.
	if _, err := parseNbar2Catalog(nbar2JSON("", nbar2GoodHTTP, nbar2GoodDNS), "good.json"); err != nil {
		t.Fatalf("control failed: %v", err)
	}
}

func TestNbar2CatalogMergeOverlay(t *testing.T) {
	universal, err := parseNbar2Catalog(nbar2JSON("", nbar2GoodHTTP, nbar2GoodDNS), "u")
	if err != nil {
		t.Fatal(err)
	}
	overlay, err := parseNbar2Catalog(nbar2JSON("true",
		`{"name":"http","description":"HTTP edge","engine":3,"selector":80,"proto":"tcp","dst_port":80,"weight":50}`,
		`{"name":"ldap","engine":3,"selector":389,"proto":"tcp","dst_port":389}`), "o")
	if err != nil {
		t.Fatal(err)
	}
	merged, err := universal.MergeOverlay(overlay, "o")
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(merged.Entries))
	for _, e := range merged.Entries {
		names = append(names, e.Name)
	}
	if got := strings.Join(names, ","); got != "http,dns,ldap" {
		t.Fatalf("merged order = %s, want http,dns,ldap (override in place, append new, carry through)", got)
	}
	if merged.ByName["http"].Description != "HTTP edge" || merged.ByName["http"].Weight != 50 {
		t.Fatalf("http was not replaced by the overlay: %+v", merged.ByName["http"])
	}
	if len(universal.ByName["http"].Hosts) != 2 || universal.ByName["http"].Weight != 30 {
		t.Fatal("MergeOverlay mutated the universal")
	}

	// extends:false is the whole catalog for the type.
	replace, err := parseNbar2Catalog(nbar2JSON("false", nbar2GoodDNS), "r")
	if err != nil {
		t.Fatal(err)
	}
	if replace.Extends {
		t.Fatal("extends:false was not honoured")
	}

	// An id collision that only exists after the merge is refused.
	collide, err := parseNbar2Catalog(nbar2JSON("true",
		`{"name":"dns-alt","engine":3,"selector":53,"proto":"udp","dst_port":5353}`), "c")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := universal.MergeOverlay(collide, "c"); err == nil || !strings.Contains(err.Error(), `used by both "dns" and "dns-alt"`) {
		t.Fatalf("post-merge id collision not refused: %v", err)
	}
}

// The scan reads <slug>/nbar2.json, skips `_` dirs and files that are
// directories, merges under extends:true and replaces under extends:false.
func TestNbar2ScanPerTypeCatalogs(t *testing.T) {
	universal, err := parseNbar2Catalog(nbar2JSON("", nbar2GoodHTTP, nbar2GoodDNS), "u")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(slug, body string) {
		if err := os.MkdirAll(filepath.Join(dir, slug), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, slug, nbar2CatalogFileName), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("Cisco_IOS", string(nbar2JSON("true", `{"name":"ldap","engine":3,"selector":389,"proto":"tcp","dst_port":389}`)))
	write("juniper_mx240", string(nbar2JSON("false", nbar2GoodDNS)))
	write("_common", string(nbar2JSON("", `{"name":"x","engine":3,"selector":1,"proto":"tcp","dst_port":1}`)))
	if err := os.MkdirAll(filepath.Join(dir, "asr9k", nbar2CatalogFileName), 0o755); err != nil {
		t.Fatal(err)
	}
	got, err := ScanPerTypeNbar2Catalogs(universal, dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("scanned %d slugs, want 2 (cisco_ios, juniper_mx240): %v", len(got), got)
	}
	if c := got["cisco_ios"]; c == nil || len(c.Entries) != 3 || c.ByName["ldap"] == nil {
		t.Fatalf("cisco_ios overlay not merged (lower-cased key, 3 entries): %+v", c)
	}
	if c := got["juniper_mx240"]; c == nil || len(c.Entries) != 1 || c.ByName["http"] != nil {
		t.Fatalf("juniper_mx240 extends:false not a replacement: %+v", c)
	}
	if _, err := ScanPerTypeNbar2Catalogs(universal, filepath.Join(dir, "missing")); err != nil {
		t.Fatalf("missing resource dir must be a no-op, got %v", err)
	}
	write("bad", `{"entries":[{"name":"a","engine":9}]}`)
	if _, err := ScanPerTypeNbar2Catalogs(universal, dir); err == nil || !strings.Contains(err.Error(), `per-type nbar2 catalog "bad"`) {
		t.Fatalf("a malformed overlay must fail the scan naming the slug, got %v", err)
	}
}

// The shipped tree: the embedded universal loads, both overlays merge on top
// of it, and every other type falls through to the universal.
func TestNbar2ShippedCatalogsLoad(t *testing.T) {
	sm := &SimulatorManager{}
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: maxFlowPayloadIPv4}); err != nil {
		t.Fatal(err)
	}
	u := sm.Nbar2CatalogFor("juniper_mx240.json")
	if u == nil || u != sm.nbar2CatalogsByType[universalCatalogKey] {
		t.Fatal("a type without an overlay must resolve to the universal")
	}
	if u.Usable() != len(u.Entries) || len(u.Oversized) != 0 {
		t.Fatalf("shipped universal has oversized entries at the default MTU: %v", u.Oversized)
	}
	ios := sm.Nbar2CatalogFor("cisco_ios.json")
	if ios == u || ios.ByName["http-alt"] == nil || ios.ByName["dns"] == nil || ios.ByName["http"].Weight != 35 {
		t.Fatalf("cisco_ios overlay not applied: %+v", ios)
	}
	cat := sm.Nbar2CatalogFor("cisco_catalyst_9500.json")
	if cat == u || cat.ByName["ldap"] == nil || cat.ByName["kerberos"] == nil || cat.ByName["http"] == nil {
		t.Fatalf("cisco_catalyst_9500 overlay not applied: %+v", cat)
	}
	if ios.Encoder() == nil || ios.Encoder() == cat.Encoder() {
		t.Fatal("each catalog carries its own encoder, built once")
	}
	if got := len(ios.Encoder().Applications()); got != ios.Usable() {
		t.Fatalf("application table advertises %d apps, catalog can emit %d", got, ios.Usable())
	}
	for _, e := range u.Entries {
		if e.Engine != avcEngineIANAL4 || uint32(e.DstPort) != e.Selector {
			t.Errorf("shipped entry %s: engine %d selector %d port %d; shipped entries are engine 3 with the port as selector, which RFC 6759 defines and needs no protocol-pack number", e.Name, e.Engine, e.Selector, e.DstPort)
		}
	}
}

// -nbar2-catalog replaces the universal AND suppresses every overlay; a
// missing file is an error.
func TestNbar2OverrideFlagSuppressesOverlays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "op.json")
	if err := os.WriteFile(path, nbar2JSON("", nbar2GoodDNS), 0o644); err != nil {
		t.Fatal(err)
	}
	sm := &SimulatorManager{}
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{CatalogPath: path, PayloadBudget: maxFlowPayloadIPv4}); err != nil {
		t.Fatal(err)
	}
	if len(sm.nbar2CatalogsByType) != 1 {
		t.Fatalf("override loaded %d catalogs, want only _universal", len(sm.nbar2CatalogsByType))
	}
	ios := sm.Nbar2CatalogFor("cisco_ios.json")
	if ios.ByName["http-alt"] != nil || ios.ByName["dns"] == nil {
		t.Fatal("resources/cisco_ios/nbar2.json was read under the override")
	}
	if got := nbar2CatalogSource("cisco_ios", path); got != "override:"+path {
		t.Fatalf("source = %s", got)
	}
	if err := (&SimulatorManager{}).StartNbar2Catalogs(Nbar2CatalogConfig{CatalogPath: filepath.Join(t.TempDir(), "none.json"), PayloadBudget: 1472}); err == nil {
		t.Fatal("a missing override file must fail the load")
	}
	if err := (&SimulatorManager{}).StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: 0}); err == nil {
		t.Fatal("a non-positive budget must be refused, never defaulted")
	}
}

// The dry render: an entry whose worst-case record cannot fit an empty
// datagram is disabled and named with size, gap and admitting MTU; the load
// succeeds; the entry is absent from the draw, from the avcCatalog and from
// the application-table datagram.
func TestNbar2DryRenderDisablesOversized(t *testing.T) {
	cat, err := parseNbar2Catalog(nbar2JSON("",
		`{"name":"big","engine":6,"selector":1,"proto":"tcp","dst_port":80,"uris":[{"value":"/x"},{"value":"/`+strings.Repeat("u", 1400)+`"}]}`,
		nbar2GoodHTTP), "d")
	if err != nil {
		t.Fatal(err)
	}
	disabled := cat.ApplySizeBudget(maxFlowPayloadIPv4, "d")
	if len(disabled) != 1 || !strings.Contains(disabled[0], "d/big (") || !strings.Contains(disabled[0], "needs -datagram-mtu >=") {
		t.Fatalf("disabled = %v, want exactly the 1400-byte URI entry with its size and admitting MTU", disabled)
	}
	if !cat.ByName["big"].oversized || cat.ByName["http"].oversized {
		t.Fatal("wrong entry marked")
	}
	cat.finalize()
	if cat.Usable() != 1 || cat.avc.Len() != 1 {
		t.Fatalf("usable = %d, avc = %d, want 1 and 1", cat.Usable(), cat.avc.Len())
	}
	apps := cat.Encoder().Applications()
	if len(apps) != 1 || apps[0].Name != "http" {
		t.Fatalf("Applications() = %+v, want only http", apps)
	}
	buf := make([]byte, maxFlowPayloadIPv4)
	n, consumed, err := cat.Encoder().EncodeAppTableDatagram(1, 0, apps, buf)
	if err != nil || consumed != 1 {
		t.Fatalf("app table: n=%d consumed=%d err=%v", n, consumed, err)
	}
	bigID := cat.ByName["big"].ID
	var idBytes [4]byte
	binary.BigEndian.PutUint32(idBytes[:], bigID)
	if strings.Contains(string(buf[:n]), string(idBytes[:])) {
		t.Fatal("the application-table datagram carries the oversized entry's id")
	}
	// A control at a budget that admits it: nothing disabled.
	cat2, _ := parseNbar2Catalog(nbar2JSON("", nbar2GoodHTTP), "d2")
	if got := cat2.ApplySizeBudget(maxFlowPayloadIPv4, "d2"); len(got) != 0 {
		t.Fatalf("a fitting entry was disabled: %v", got)
	}
}

// Every entry oversized: the catalog still loads (attach refuses later), and
// draw tables are empty.
func TestNbar2AllOversizedStillLoads(t *testing.T) {
	sm := &SimulatorManager{}
	// 576 is the smallest MTU SetLinkMTU accepts; 576-28 = 548 bytes of
	// payload, which the shipped http entry's worst case (host + URI) still
	// fits, so plant a catalog that cannot.
	path := filepath.Join(t.TempDir(), "big.json")
	doc := nbar2JSON("", `{"name":"big","engine":6,"selector":1,"proto":"tcp","dst_port":80,"hosts":[{"value":"`+strings.Repeat("h", 600)+`"}]}`)
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{CatalogPath: path, PayloadBudget: 548}); err != nil {
		t.Fatalf("an all-oversized catalog must load, got %v", err)
	}
	c := sm.Nbar2CatalogFor("cisco_ios.json")
	if c.Usable() != 0 || len(c.Oversized) != 1 {
		t.Fatalf("usable=%d oversized=%v", c.Usable(), c.Oversized)
	}
}

func TestNbar2CatalogForBeforeLoadIsNil(t *testing.T) {
	sm := &SimulatorManager{}
	if sm.Nbar2CatalogFor("cisco_ios.json") != nil {
		t.Fatal("a manager whose loader never ran must resolve nil, not panic")
	}
	if nbar2CatalogSource(universalCatalogKey, "") != "embedded" || nbar2CatalogSource("cisco_ios", "") != "file:resources/cisco_ios/nbar2.json" {
		t.Fatal("source labels")
	}
}

// shippedNbar2Encoder loads the shipped catalogs at the default MTU and
// returns the encoder a device of resourceFile would share.
func shippedNbar2Encoder(t *testing.T, resourceFile string) *IPFIXAVCEncoder {
	t.Helper()
	sm := &SimulatorManager{}
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: maxFlowPayloadIPv4}); err != nil {
		t.Fatal(err)
	}
	return sm.Nbar2CatalogFor(resourceFile).Encoder()
}

// The corpus walker sees resources/<slug>/nbar2.json as a part of that
// profile, exactly as it sees traps.json and syslog.json: the resource
// decoder is non-strict, so a catalog file's keys are inert to the SNMP,
// SSH and REST loaders. That holds only while a catalog part carries NO
// profile key, which this pins for every shipped nbar2.json.
func TestNbar2CatalogPartsAreInertToProfileLoaders(t *testing.T) {
	seen := 0
	for _, p := range shippedResourceParts(t) {
		if filepath.Base(p) != nbar2CatalogFileName {
			continue
		}
		seen++
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		var top map[string]json.RawMessage
		if err := json.Unmarshal(data, &top); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		for _, k := range []string{"snmp", "ssh", "rest", "optical", "_comment"} {
			if _, has := top[k]; has {
				t.Errorf("%s carries a %q key; a catalog part must carry only comment, extends and entries, or the profile loaders read it", p, k)
			}
		}
		if _, err := parseNbar2Catalog(data, p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if seen != 2 {
		t.Fatalf("saw %d shipped per-type nbar2.json parts, want 2 (cisco_ios, cisco_catalyst_9500); the walk is blind to a layout or an overlay moved", seen)
	}
}

// The name-agreement rule is WIRED into StartNbar2Catalogs, so an operator
// overlay that renames a wire id the universal (or another overlay) also
// carries is refused at load, naming both, rather than surfacing as
// whichever name the lowest participant IP happened to carry in a report.
func TestNbar2StartRefusesDisagreeingOverlay(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "cisco_ios"), 0o755); err != nil {
		t.Fatal(err)
	}
	// engine 3 / selector 80 is "http" in the embedded universal.
	doc := `{"extends": false, "entries":[{"name":"web","description":"x","engine":3,"selector":80,"proto":"tcp","dst_port":80}]}`
	if err := os.WriteFile(filepath.Join(dir, "cisco_ios", "nbar2.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	err := (&SimulatorManager{}).StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: maxFlowPayloadIPv4, ResourceDir: dir})
	if err == nil || !strings.Contains(err.Error(), "disagree") || !strings.Contains(err.Error(), `"http"`) || !strings.Contains(err.Error(), `"web"`) {
		t.Fatalf("a renaming overlay must be refused at load naming both names, got %v", err)
	}
	// Control: an overlay that agrees loads.
	doc = `{"extends": false, "entries":[{"name":"http","description":"x","engine":3,"selector":80,"proto":"tcp","dst_port":80}]}`
	if err := os.WriteFile(filepath.Join(dir, "cisco_ios", "nbar2.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := (&SimulatorManager{}).StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: maxFlowPayloadIPv4, ResourceDir: dir}); err != nil {
		t.Fatalf("an agreeing overlay must load: %v", err)
	}
}
