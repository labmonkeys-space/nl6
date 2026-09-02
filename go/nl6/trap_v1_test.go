/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// nl6#97. SNMPv1 Trap-PDU, and the RFC 3584 §3.2 mapping onto it.
//
// These tests DECODE the emitted bytes rather than comparing against a second
// encoding: an encoder test whose expectation is built by the same author from
// the same misunderstanding agrees with itself. The decoder here walks the PDU
// field by field against RFC 1157 §4.1.6.
//
// THE MAPPING IS DERIVED, NOT DECLARED, and that is the surprising part. RFC
// 3584 §3.2 honours a declared snmpTrapEnterprise only for a STANDARD trap; for
// anything else the enterprise comes from snmpTrapOID. An earlier draft of this
// change had it backwards and would have put an enterprise on the wire that no
// conforming proxy produces.

// v1PDU is a decoded SNMPv1 message, for assertions that name fields rather
// than byte offsets.
type v1PDU struct {
	Version     int
	Community   string
	PDUTag      byte
	Enterprise  string
	AgentAddr   string
	Generic     int
	Specific    int
	TimeStamp   uint32
	VarbindOIDs []string
}

// decodeV1Trap walks an SNMPv1 trap message. Deliberately a separate, simple
// reader rather than a call into nl6's own parser: sharing a parser with the
// encoder would let one misreading satisfy both sides.
func decodeV1Trap(t *testing.T, pkt []byte) v1PDU {
	t.Helper()

	var out v1PDU
	seq, rest := v1TLV(t, pkt, ASN1_SEQUENCE, "outer message")
	if len(rest) != 0 {
		t.Fatalf("trailing bytes after the outer SEQUENCE: % x", rest)
	}
	ver, seq := v1Int(t, seq, "version")
	out.Version = ver
	comm, seq := v1OctetString(t, seq, "community")
	out.Community = comm

	if len(seq) == 0 {
		t.Fatal("message carries no PDU")
	}
	out.PDUTag = seq[0]
	body, after := v1TLV(t, seq, out.PDUTag, "PDU")
	if len(after) != 0 {
		t.Fatalf("trailing bytes after the PDU: % x", after)
	}

	ent, body := v1OIDField(t, body, "enterprise")
	out.Enterprise = ent
	addr, body := v1IPField(t, body, "agent-addr")
	out.AgentAddr = addr
	gen, body := v1Int(t, body, "generic-trap")
	out.Generic = gen
	spec, body := v1Int(t, body, "specific-trap")
	out.Specific = spec
	ts, body := v1Uint32(t, body, ASN1_TIMETICKS, "time-stamp")
	out.TimeStamp = ts

	vbList, after := v1TLV(t, body, ASN1_SEQUENCE, "variable-bindings")
	if len(after) != 0 {
		t.Fatalf("trailing bytes after variable-bindings: % x", after)
	}
	for len(vbList) > 0 {
		var vb []byte
		vb, vbList = v1TLV(t, vbList, ASN1_SEQUENCE, "varbind")
		oid, _ := v1OIDField(t, vb, "varbind name")
		out.VarbindOIDs = append(out.VarbindOIDs, oid)
	}
	return out
}

func encodeOneV1Trap(t *testing.T, enc SNMPv1Encoder, trapOID, enterprise string, vbs []Varbind) v1PDU {
	t.Helper()
	buf := make([]byte, 4096)
	n, err := enc.EncodeTrap("public", 1, trapOID, enterprise, 12345, vbs, buf)
	if err != nil {
		t.Fatalf("EncodeTrap(%q, %q): %v", trapOID, enterprise, err)
	}
	return decodeV1Trap(t, buf[:n])
}

// TestSnmpTrapsOIDIsTheStandardTrapPrefix re-derives snmpTraps from the shipped
// corpus instead of trusting the constant. RFC 3584 §3.2 assigns it as the
// enterprise for a standard trap that declares none, so a wrong value here would
// ride on every coldStart the simulator sends.
func TestSnmpTrapsOIDIsTheStandardTrapPrefix(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("resources", "_common", "traps.json"))
	if err != nil {
		t.Fatalf("read the universal catalog: %v", err)
	}
	var doc struct {
		Traps []struct {
			Name        string `json:"name"`
			SnmpTrapOID string `json:"snmpTrapOID"`
		} `json:"traps"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse: %v", err)
	}

	prefixes := map[string][]string{}
	for _, e := range doc.Traps {
		oid := strings.TrimPrefix(e.SnmpTrapOID, ".")
		parts := strings.Split(oid, ".")
		if len(parts) < 2 {
			continue
		}
		p := strings.Join(parts[:len(parts)-1], ".")
		prefixes[p] = append(prefixes[p], e.Name)
	}
	if got := prefixes[snmpTrapsOID]; len(got) != 5 {
		t.Errorf("the universal catalog has %d entries under snmpTrapsOID (%s), want the 5 standard "+
			"traps; prefixes seen: %v.\nIf this constant is wrong, every standard trap goes out with "+
			"the wrong enterprise", len(got), snmpTrapsOID, prefixes)
	}
}

// TestV1MappingStandardTraps covers the matrix's standard-trap row. The five
// universal entries declare no snmpTrapEnterprise, so they take the RFC's
// snmpTraps default.
func TestV1MappingStandardTraps(t *testing.T) {
	for _, tc := range []struct {
		oid     string
		generic int
		name    string
	}{
		{snmpTrapsOID + ".1", v1GenericColdStart, "coldStart"},
		{snmpTrapsOID + ".2", v1GenericWarmStart, "warmStart"},
		{snmpTrapsOID + ".3", v1GenericLinkDown, "linkDown"},
		{snmpTrapsOID + ".4", v1GenericLinkUp, "linkUp"},
		{snmpTrapsOID + ".5", v1GenericAuthFailure, "authenticationFailure"},
	} {
		id, err := mapV2cToV1Identity(tc.oid, "")
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if id.Generic != tc.generic {
			t.Errorf("%s: generic-trap = %d, want %d", tc.name, id.Generic, tc.generic)
		}
		if id.Specific != 0 {
			t.Errorf("%s: specific-trap = %d, want 0 for a standard trap", tc.name, id.Specific)
		}
		if id.Enterprise != snmpTrapsOID {
			t.Errorf("%s: enterprise = %q, want %q. RFC 3584 §3.2 assigns snmpTraps when a standard "+
				"trap declares none", tc.name, id.Enterprise, snmpTrapsOID)
		}
	}

	// A standard trap that DOES declare one uses it: the only case where the
	// declared value is honoured.
	id, err := mapV2cToV1Identity(snmpTrapsOID+".1", "1.3.6.1.4.1.9")
	if err != nil {
		t.Fatal(err)
	}
	if id.Enterprise != "1.3.6.1.4.1.9" {
		t.Errorf("a standard trap declaring snmpTrapEnterprise got enterprise %q, want the declared "+
			"value; RFC 3584 §3.2 honours it in this case and only this case", id.Enterprise)
	}
}

// TestV1MappingEnterpriseSpecificIgnoresTheDeclaredEnterprise is the row the
// spec had backwards. For a non-standard trap the enterprise is ALWAYS derived.
func TestV1MappingEnterpriseSpecificIgnoresTheDeclaredEnterprise(t *testing.T) {
	for _, tc := range []struct {
		oid, declared, wantEnt string
		wantSpecific           int
		why                    string
	}{
		{"1.3.6.1.4.1.9.9.43.2.0.1", "1.3.6.1.4.1.9.9.43", "1.3.6.1.4.1.9.9.43.2", 1,
			"next-to-last sub-identifier is 0, so RFC 3584 removes the last TWO"},
		{"1.3.6.1.4.1.1271.3.2.12", "1.3.6.1.4.1.1271", "1.3.6.1.4.1.1271.3.2", 12,
			"next-to-last is non-zero, so RFC 3584 removes the last ONE"},
	} {
		id, err := mapV2cToV1Identity(tc.oid, tc.declared)
		if err != nil {
			t.Fatalf("%s: %v", tc.oid, err)
		}
		if id.Generic != v1GenericEnterpriseSpecific {
			t.Errorf("%s: generic-trap = %d, want 6", tc.oid, id.Generic)
		}
		if id.Specific != tc.wantSpecific {
			t.Errorf("%s: specific-trap = %d, want %d (the last sub-identifier)", tc.oid, id.Specific, tc.wantSpecific)
		}
		if id.Enterprise != tc.wantEnt {
			t.Errorf("%s: enterprise = %q, want %q (%s).\nThe DECLARED snmpTrapEnterprise (%q) must "+
				"NOT win here: RFC 3584 §3.2 honours it only for a standard trap, and emitting it "+
				"would put an enterprise on the wire no conforming proxy produces",
				tc.oid, id.Enterprise, tc.wantEnt, tc.why, tc.declared)
		}
	}
}

// TestV1TrapPDUShape decodes a real emitted PDU field by field.
func TestV1TrapPDUShape(t *testing.T) {
	enc := SNMPv1Encoder{AgentAddr: "10.42.0.7"}
	got := encodeOneV1Trap(t, enc, "1.3.6.1.4.1.9.9.43.2.0.1", "1.3.6.1.4.1.9.9.43",
		[]Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "device-1"}})

	if got.Version != 0 {
		t.Errorf("version = %d, want 0 (SNMPv1)", got.Version)
	}
	if got.Community != "public" {
		t.Errorf("community = %q, want %q", got.Community, "public")
	}
	if got.PDUTag != v1TrapPDUTag {
		t.Errorf("PDU tag = 0x%02X, want 0x%02X (Trap-PDU)", got.PDUTag, v1TrapPDUTag)
	}
	if got.Enterprise != "1.3.6.1.4.1.9.9.43.2" {
		t.Errorf("enterprise = %q, want the derived value", got.Enterprise)
	}
	if got.AgentAddr != "10.42.0.7" {
		t.Errorf("agent-addr = %q, want the device's own IPv4", got.AgentAddr)
	}
	if got.Generic != v1GenericEnterpriseSpecific || got.Specific != 1 {
		t.Errorf("generic/specific = %d/%d, want 6/1", got.Generic, got.Specific)
	}
	if got.TimeStamp != 12345 {
		t.Errorf("time-stamp = %d, want the uptime passed in", got.TimeStamp)
	}
}

// TestV1DropsTheV2cPrependedVarbinds is the matrix row nl6#97 does not mention.
// sysUpTime.0, snmpTrapOID.0 and snmpTrapEnterprise.0 became PDU fields; a v1
// trap carrying them as varbinds is malformed in a way no agent produces.
func TestV1DropsTheV2cPrependedVarbinds(t *testing.T) {
	enc := SNMPv1Encoder{AgentAddr: "10.42.0.7"}
	got := encodeOneV1Trap(t, enc, "1.3.6.1.4.1.9.9.43.2.0.1", "1.3.6.1.4.1.9.9.43",
		[]Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "device-1"}})

	if len(got.VarbindOIDs) != 1 || got.VarbindOIDs[0] != "1.3.6.1.2.1.1.5.0" {
		t.Fatalf("varbinds = %v, want exactly the one body varbind", got.VarbindOIDs)
	}
	for _, banned := range []string{
		strings.TrimPrefix(oidSysUpTime0, "."),
		strings.TrimPrefix(oidSnmpTrapOID0, "."),
		strings.TrimPrefix(oidSnmpTrapEnterprise0, "."),
	} {
		for _, got := range got.VarbindOIDs {
			if got == banned {
				t.Errorf("the v1 PDU carries %s as a varbind. It is a v2c construct that became a PDU "+
					"field; emitting it produces a trap no real agent sends", banned)
			}
		}
	}
}

// TestV1RefusesInformAndAck pins that the unsatisfiable half of the interface
// fails loudly. Startup refuses the flag pair; these are the backstop.
func TestV1RefusesInformAndAck(t *testing.T) {
	enc := SNMPv1Encoder{AgentAddr: "10.42.0.7"}
	if _, err := enc.EncodeInform("public", 1, snmpTrapsOID+".1", "", 1, nil, make([]byte, 512)); err == nil {
		t.Error("EncodeInform returned no error. RFC 1157 defines no acknowledged notification, so " +
			"there is nothing to encode")
	}
	if _, _, err := enc.ParseAck([]byte{0x30, 0x00}); err == nil {
		t.Error("ParseAck returned no error; nothing ever acknowledges an SNMPv1 trap")
	}
}

// TestParseTrapSNMPVersion pins the flag's accept-set, including that the empty
// value stays v2c so an existing deployment is unchanged.
func TestParseTrapSNMPVersion(t *testing.T) {
	for in, want := range map[string]TrapSNMPVersion{
		"": TrapSNMPv2c, "v2c": TrapSNMPv2c, "2c": TrapSNMPv2c, "V2C": TrapSNMPv2c,
		"v1": TrapSNMPv1, "1": TrapSNMPv1, " V1 ": TrapSNMPv1,
	} {
		got, err := ParseTrapSNMPVersion(in)
		if err != nil {
			t.Errorf("ParseTrapSNMPVersion(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTrapSNMPVersion(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseTrapSNMPVersion("v3"); err == nil {
		t.Error("ParseTrapSNMPVersion accepted v3; SNMPv3 trap support is nl6#98, not this change")
	}
}

// ── an independent BER reader ───────────────────────────────────────────────
//
// Deliberately NOT nl6's own parser. A decoder that shares code with the
// encoder lets a single misreading of RFC 1157 satisfy both sides and look like
// agreement. This one is written straight from the tag/length/value rules.

func v1Len(t *testing.T, b []byte, what string) (length, headerLen int) {
	t.Helper()
	if len(b) < 2 {
		t.Fatalf("%s: truncated TLV: % x", what, b)
	}
	n := int(b[1])
	if n < 0x80 {
		return n, 2
	}
	count := n & 0x7f
	if count == 0 || count > 4 || len(b) < 2+count {
		t.Fatalf("%s: unreadable long-form length: % x", what, b)
	}
	v := 0
	for _, c := range b[2 : 2+count] {
		v = v<<8 | int(c)
	}
	return v, 2 + count
}

func v1TLV(t *testing.T, b []byte, tag byte, what string) (contents, rest []byte) {
	t.Helper()
	if len(b) == 0 {
		t.Fatalf("%s: no bytes", what)
	}
	if b[0] != tag {
		t.Fatalf("%s: tag = 0x%02X, want 0x%02X", what, b[0], tag)
	}
	n, hdr := v1Len(t, b, what)
	if len(b) < hdr+n {
		t.Fatalf("%s: length %d overruns %d remaining bytes", what, n, len(b)-hdr)
	}
	return b[hdr : hdr+n], b[hdr+n:]
}

func v1Int(t *testing.T, b []byte, what string) (int, []byte) {
	t.Helper()
	c, rest := v1TLV(t, b, ASN1_INTEGER, what)
	v := 0
	for _, x := range c {
		v = v<<8 | int(x)
	}
	return v, rest
}

func v1OctetString(t *testing.T, b []byte, what string) (string, []byte) {
	t.Helper()
	c, rest := v1TLV(t, b, ASN1_OCTET_STRING, what)
	return string(c), rest
}

func v1Uint32(t *testing.T, b []byte, tag byte, what string) (uint32, []byte) {
	t.Helper()
	c, rest := v1TLV(t, b, tag, what)
	var v uint32
	for _, x := range c {
		v = v<<8 | uint32(x)
	}
	return v, rest
}

func v1IPField(t *testing.T, b []byte, what string) (string, []byte) {
	t.Helper()
	c, rest := v1TLV(t, b, ASN1_IPADDRESS, what)
	if len(c) != 4 {
		t.Fatalf("%s: IpAddress is %d bytes, want 4", what, len(c))
	}
	return fmt.Sprintf("%d.%d.%d.%d", c[0], c[1], c[2], c[3]), rest
}

func v1OIDField(t *testing.T, b []byte, what string) (string, []byte) {
	t.Helper()
	c, rest := v1TLV(t, b, ASN1_OBJECT_ID, what)
	if len(c) == 0 {
		t.Fatalf("%s: empty OID", what)
	}
	// First byte packs the first two arcs as 40*a+b.
	parts := []string{strconv.Itoa(int(c[0]) / 40), strconv.Itoa(int(c[0]) % 40)}
	v := 0
	for _, x := range c[1:] {
		v = v<<7 | int(x&0x7f)
		if x&0x80 == 0 {
			parts = append(parts, strconv.Itoa(v))
			v = 0
		}
	}
	return strings.Join(parts, "."), rest
}

// TestV2cOutputUnchangedByV1Encoder is the whole risk of adding a second
// encoder: silently perturbing the first. It digests the v2c encoding of every
// shipped catalog entry, so a change to the shared primitives or to
// encodeV2cNotification moves the digest even when the v1 tests stay green.
//
// The digest is over the SHIPPED entries rather than a synthetic set, because
// the shared surface is encodeVarbindTyped and the OID encoder, which only the
// real corpus exercises across all its types.
func TestV2cOutputUnchangedByV1Encoder(t *testing.T) {
	universal, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("load the universal catalog: %v", err)
	}
	perType, err := ScanPerTypeTrapCatalogs(universal, "resources")
	if err != nil {
		t.Fatalf("scan per-type catalogs: %v", err)
	}

	cats := map[string]*Catalog{"_universal": universal}
	for slug, c := range perType {
		cats[slug] = c
	}
	names := make([]string, 0, len(cats))
	for n := range cats {
		names = append(names, n)
	}
	sort.Strings(names)

	enc := SNMPv2cEncoder{}
	h := sha256.New()
	encoded := 0
	buf := make([]byte, 8192)
	for _, name := range names {
		entries := append([]*CatalogEntry(nil), cats[name].Entries...)
		sort.Slice(entries, func(a, b int) bool { return entries[a].Name < entries[b].Name })
		for _, e := range entries {
			vbs := make([]Varbind, 0, len(e.Varbinds))
			for _, vb := range e.Varbinds {
				// Templated OIDs and values cannot be encoded literally; the
				// probe keeps the corpus coverage without inventing a fire.
				oid := vb.rawOID
				if strings.Contains(oid, "{{") {
					continue
				}
				val := vb.rawValue
				if strings.Contains(val, "{{") {
					val = trapTypeProbeValue[vb.Type]
				}
				vbs = append(vbs, Varbind{OID: oid, Type: vb.Type, Value: val})
			}
			n, err := enc.EncodeTrap("public", 7, e.SnmpTrapOID, e.SnmpTrapEnterprise, 4242, vbs, buf)
			if err != nil {
				continue // an entry the v2c encoder already refuses; not this test's subject
			}
			h.Write([]byte(name + "/" + e.Name + ":"))
			h.Write(buf[:n])
			encoded++
		}
	}

	// Floored so a collapse of the walk cannot pass by encoding nothing.
	if encoded < 20 {
		t.Fatalf("only %d shipped entries encoded; the walk collapsed and the digest below would "+
			"pin nothing", encoded)
	}
	const want = "a414471f8d5045f5fc35c523f97845a628f4ec9aff18c6ef0a2ec4ef24b53cb6"
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		t.Errorf("v2c encoding of %d shipped entries digests to %s, recorded as %s.\nAdding the v1 "+
			"encoder must not perturb v2c output by one byte. If this moved deliberately, say which "+
			"v2c behaviour changed and why", encoded, got, want)
	}
}

// TestTrapVersionModeConflict pins the startup refusal. It is a function rather
// than an inline check in main() precisely so it can be tested: the startup path
// exits on the root check long before the guard, so running the binary as an
// unprivileged user verifies nothing about it.
func TestTrapVersionModeConflict(t *testing.T) {
	if err := trapVersionModeConflict(TrapSNMPv1, "inform"); err == nil {
		t.Error("v1 + inform was accepted. RFC 1157 defines no acknowledged notification, so the " +
			"pair is unsatisfiable and must fail at startup rather than per fire")
	} else {
		for _, want := range []string{"-trap-snmp-version=v1", "-trap-mode=inform"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not name %s; an operator needs both flags to know what to "+
					"change.\ngot: %v", want, err)
			}
		}
	}
	for _, ok := range []struct {
		v    TrapSNMPVersion
		mode string
	}{
		{TrapSNMPv1, "trap"}, {TrapSNMPv1, ""}, {TrapSNMPv2c, "inform"}, {TrapSNMPv2c, "trap"},
	} {
		if err := trapVersionModeConflict(ok.v, ok.mode); err != nil {
			t.Errorf("trapVersionModeConflict(%v, %q) refused a legal combination: %v", ok.v, ok.mode, err)
		}
	}
}
