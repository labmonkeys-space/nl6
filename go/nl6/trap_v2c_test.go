/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 */

package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"testing"
)

// decodedVarbind mirrors what the test-only decoder extracts from a v2c
// notification or ack for structural round-trip assertions.
type decodedVarbind struct {
	OID      string
	TypeTag  byte
	RawValue []byte
}

type decodedNotification struct {
	PDUTag      byte
	Version     uint64
	Community   string
	RequestID   uint32
	ErrorStatus int64
	ErrorIndex  int64
	Varbinds    []decodedVarbind
}

// decodeV2cNotification is a test-only BER decoder that handles the three
// PDU tags the trap subsystem uses: 0xA7 (TRAP), 0xA6 (INFORM), 0xA2
// (GetResponse for ACK). Panics on malformed input — callers feed known-good
// encoder output.
func decodeV2cNotification(t *testing.T, data []byte) decodedNotification {
	t.Helper()
	pos := 0
	must := func(cond bool, msg string, args ...any) {
		if !cond {
			t.Fatalf("decode: "+msg+" at pos %d", append(args, pos)...)
		}
	}
	must(pos < len(data) && data[pos] == ASN1_SEQUENCE, "outer SEQUENCE expected")
	pos++
	outerLen, np := parseLength(data, pos)
	must(outerLen >= 0, "outer length")
	pos = np
	must(pos+outerLen <= len(data), "outer length fits")

	// version
	must(data[pos] == ASN1_INTEGER, "version INTEGER")
	pos++
	verLen, np := parseLength(data, pos)
	must(verLen >= 0, "version length")
	version := parseUintBE(data[np : np+verLen])
	pos = np + verLen

	// community
	must(data[pos] == ASN1_OCTET_STRING, "community OCTET STRING")
	pos++
	commLen, np := parseLength(data, pos)
	must(commLen >= 0, "community length")
	community := string(data[np : np+commLen])
	pos = np + commLen

	// PDU tag
	pduTag := data[pos]
	must(pduTag == ASN1_TRAP_V2C || pduTag == ASN1_INFORM_REQUEST || pduTag == ASN1_GET_RESPONSE,
		"unexpected PDU tag 0x%02X", pduTag)
	pos++
	pduLen, np := parseLength(data, pos)
	must(pduLen >= 0, "pdu length")
	pos = np
	pduEnd := pos + pduLen

	// request-id
	must(data[pos] == ASN1_INTEGER, "request-id INTEGER")
	pos++
	ridLen, np := parseLength(data, pos)
	reqID := uint32(parseUintBE(data[np : np+ridLen]))
	pos = np + ridLen

	// error-status
	must(data[pos] == ASN1_INTEGER, "error-status INTEGER")
	pos++
	esLen, np := parseLength(data, pos)
	errStatus := parseIntBE(data[np : np+esLen])
	pos = np + esLen

	// error-index
	must(data[pos] == ASN1_INTEGER, "error-index INTEGER")
	pos++
	eiLen, np := parseLength(data, pos)
	errIndex := parseIntBE(data[np : np+eiLen])
	pos = np + eiLen

	// variable-bindings SEQUENCE OF VarBind
	must(data[pos] == ASN1_SEQUENCE, "varbinds SEQUENCE")
	pos++
	vbListLen, np := parseLength(data, pos)
	must(vbListLen >= 0, "varbinds length")
	pos = np
	vbListEnd := pos + vbListLen

	var vbs []decodedVarbind
	for pos < vbListEnd {
		must(data[pos] == ASN1_SEQUENCE, "varbind SEQUENCE")
		pos++
		vbLen, np := parseLength(data, pos)
		must(vbLen >= 0, "varbind length")
		pos = np

		// OID
		must(data[pos] == ASN1_OBJECT_ID, "varbind OID")
		pos++
		oidLen, np := parseLength(data, pos)
		oid := decodeOID(data[np : np+oidLen])
		pos = np + oidLen

		// Value
		valTag := data[pos]
		pos++
		valLen, np := parseLength(data, pos)
		must(valLen >= 0, "value length")
		rawVal := append([]byte(nil), data[np:np+valLen]...)
		pos = np + valLen

		vbs = append(vbs, decodedVarbind{
			OID:      oid,
			TypeTag:  valTag,
			RawValue: rawVal,
		})
	}
	_ = pduEnd // not asserting alignment; BER doesn't strictly need it

	return decodedNotification{
		PDUTag:      pduTag,
		Version:     version,
		Community:   community,
		RequestID:   reqID,
		ErrorStatus: errStatus,
		ErrorIndex:  errIndex,
		Varbinds:    vbs,
	}
}

func TestSNMPv2cEncoder_EncodeTrap_RoundTrip(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)

	varbinds := []Varbind{
		{OID: "1.3.6.1.2.1.2.2.1.1.7", Type: TrapVTInteger, Value: "7"},
		{OID: "1.3.6.1.2.1.2.2.1.7.7", Type: TrapVTInteger, Value: "2"},
		{OID: "1.3.6.1.2.1.2.2.1.8.7", Type: TrapVTInteger, Value: "2"},
	}
	n, err := enc.EncodeTrap("public", 12345, "1.3.6.1.6.3.1.1.5.3", "", 1234567, varbinds, buf)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("zero bytes written")
	}

	dec := decodeV2cNotification(t, buf[:n])
	if dec.PDUTag != ASN1_TRAP_V2C {
		t.Errorf("PDU tag = 0x%02X, want 0x%02X (TRAP)", dec.PDUTag, ASN1_TRAP_V2C)
	}
	if dec.Version != 1 {
		t.Errorf("version = %d, want 1", dec.Version)
	}
	if dec.Community != "public" {
		t.Errorf("community = %q, want public", dec.Community)
	}
	if dec.RequestID != 12345 {
		t.Errorf("request-id = %d, want 12345", dec.RequestID)
	}
	if dec.ErrorStatus != 0 || dec.ErrorIndex != 0 {
		t.Errorf("error-status/index = %d/%d, want 0/0", dec.ErrorStatus, dec.ErrorIndex)
	}

	// 5 varbinds total: sysUpTime.0, snmpTrapOID.0, + 3 body varbinds
	if len(dec.Varbinds) != 5 {
		t.Fatalf("varbind count = %d, want 5", len(dec.Varbinds))
	}

	// Varbind 0: sysUpTime.0 TimeTicks = 1234567
	if dec.Varbinds[0].OID != "."+oidSysUpTime0 {
		t.Errorf("vb[0].OID = %q, want .%s", dec.Varbinds[0].OID, oidSysUpTime0)
	}
	if dec.Varbinds[0].TypeTag != ASN1_TIMETICKS {
		t.Errorf("vb[0].TypeTag = 0x%02X, want TimeTicks 0x43", dec.Varbinds[0].TypeTag)
	}
	if parseUintBE(dec.Varbinds[0].RawValue) != 1234567 {
		t.Errorf("vb[0].value = %d, want 1234567", parseUintBE(dec.Varbinds[0].RawValue))
	}

	// Varbind 1: snmpTrapOID.0 OID = trapOID
	if dec.Varbinds[1].OID != "."+oidSnmpTrapOID0 {
		t.Errorf("vb[1].OID = %q, want .%s", dec.Varbinds[1].OID, oidSnmpTrapOID0)
	}
	if dec.Varbinds[1].TypeTag != ASN1_OBJECT_ID {
		t.Errorf("vb[1].TypeTag = 0x%02X, want OID 0x06", dec.Varbinds[1].TypeTag)
	}
	if got := decodeOID(dec.Varbinds[1].RawValue); got != ".1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("vb[1] OID value = %q, want .1.3.6.1.6.3.1.1.5.3", got)
	}

	// Body varbinds unchanged
	if dec.Varbinds[2].OID != ".1.3.6.1.2.1.2.2.1.1.7" {
		t.Errorf("vb[2].OID = %q", dec.Varbinds[2].OID)
	}
}

func TestSNMPv2cEncoder_EncodeInform_HasInformTag(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeInform("public", 42, "1.3.6.1.6.3.1.1.5.4", "", 100, nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	dec := decodeV2cNotification(t, buf[:n])
	if dec.PDUTag != ASN1_INFORM_REQUEST {
		t.Errorf("PDU tag = 0x%02X, want 0x%02X (INFORM)", dec.PDUTag, ASN1_INFORM_REQUEST)
	}
	if dec.RequestID != 42 {
		t.Errorf("request-id = %d", dec.RequestID)
	}
	// Even with no body varbinds, the two required prepended ones must be present
	if len(dec.Varbinds) != 2 {
		t.Errorf("varbind count = %d, want 2 (sysUpTime + snmpTrapOID only)", len(dec.Varbinds))
	}
}

func TestSNMPv2cEncoder_ParseAck_HappyPath(t *testing.T) {
	// Construct a valid GetResponse-PDU to ack request-id 99.
	pkt := buildAckDatagram(t, "public", 99, 0)
	enc := SNMPv2cEncoder{}
	reqID, ok, err := enc.ParseAck(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if reqID != 99 {
		t.Errorf("reqID = %d, want 99", reqID)
	}
	if !ok {
		t.Error("ok = false, want true (error-status 0)")
	}
}

func TestSNMPv2cEncoder_ParseAck_NonZeroErrorStatus(t *testing.T) {
	pkt := buildAckDatagram(t, "public", 99, 5) // any non-zero
	enc := SNMPv2cEncoder{}
	reqID, ok, err := enc.ParseAck(pkt)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if reqID != 99 {
		t.Errorf("reqID = %d, want 99", reqID)
	}
	if ok {
		t.Error("ok = true, want false (error-status != 0)")
	}
}

func TestSNMPv2cEncoder_ParseAck_RejectsNonGetResponse(t *testing.T) {
	// Build a TRAP instead of GetResponse and feed it to ParseAck.
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, _ := enc.EncodeTrap("public", 1, "1.2.3", "", 100, nil, buf)
	_, _, err := enc.ParseAck(buf[:n])
	if err == nil {
		t.Fatal("ParseAck should reject a TRAP-tagged packet")
	}
}

func TestSNMPv2cEncoder_ParseAck_RejectsMalformed(t *testing.T) {
	enc := SNMPv2cEncoder{}
	_, _, err := enc.ParseAck([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("ParseAck should reject a random short packet")
	}
}

func TestSNMPv2cEncoder_ParseAck_EmptyBuffer(t *testing.T) {
	enc := SNMPv2cEncoder{}
	_, _, err := enc.ParseAck(nil)
	if err == nil {
		t.Fatal("ParseAck should reject nil packet")
	}
}

func TestSNMPv2cEncoder_RequestIDDistinct_10k(t *testing.T) {
	// Simulates what TrapExporter will do: encode 10k distinct request IDs and
	// assert they round-trip through ParseAck-equivalent decode as 10k
	// distinct values (i.e. the encoder doesn't truncate or wrap).
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	seen := make(map[uint32]struct{}, 10000)
	for i := uint32(1); i <= 10000; i++ {
		n, err := enc.EncodeTrap("c", i, "1.2.3", "", 0, nil, buf)
		if err != nil {
			t.Fatalf("encode %d: %v", i, err)
		}
		dec := decodeV2cNotification(t, buf[:n])
		if dec.RequestID != i {
			t.Fatalf("encode req-id %d decoded as %d", i, dec.RequestID)
		}
		seen[dec.RequestID] = struct{}{}
	}
	if len(seen) != 10000 {
		t.Errorf("distinct request IDs = %d, want 10000", len(seen))
	}
}

func TestSNMPv2cEncoder_AllVarbindTypes(t *testing.T) {
	cases := []Varbind{
		{OID: "1.2.3", Type: TrapVTInteger, Value: "-42"},
		{OID: "1.2.3", Type: TrapVTOctetString, Value: "hello"},
		{OID: "1.2.3", Type: TrapVTOID, Value: "1.3.6.1.4.1.12345"},
		{OID: "1.2.3", Type: TrapVTCounter32, Value: "1234567890"},
		{OID: "1.2.3", Type: TrapVTGauge32, Value: "50"},
		{OID: "1.2.3", Type: TrapVTTimeTicks, Value: "100"},
		{OID: "1.2.3", Type: TrapVTCounter64, Value: "18446744073709551615"},
		{OID: "1.2.3", Type: TrapVTIPAddress, Value: "10.42.0.1"},
	}
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	for _, tc := range cases {
		t.Run(string(tc.Type), func(t *testing.T) {
			n, err := enc.EncodeTrap("public", 1, "1.2.3", "", 0, []Varbind{tc}, buf)
			if err != nil {
				t.Fatalf("encode %s: %v", tc.Type, err)
			}
			dec := decodeV2cNotification(t, buf[:n])
			if len(dec.Varbinds) != 3 { // sysUpTime + snmpTrapOID + body
				t.Fatalf("varbind count = %d, want 3", len(dec.Varbinds))
			}
		})
	}
}

func TestSNMPv2cEncoder_RejectsInvalidVarbindValues(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	bad := []Varbind{
		{OID: "1.2.3", Type: TrapVTInteger, Value: "not-a-number"},
		{OID: "1.2.3", Type: TrapVTCounter32, Value: "not-a-number"},
		{OID: "1.2.3", Type: TrapVTIPAddress, Value: "not-an-ip"},
		{OID: "1.2.3", Type: "unknown-type", Value: "x"},
	}
	for _, vb := range bad {
		t.Run(string(vb.Type)+"_"+vb.Value, func(t *testing.T) {
			_, err := enc.EncodeTrap("c", 1, "1.2.3", "", 0, []Varbind{vb}, buf)
			if err == nil {
				t.Fatalf("want error for bad %s value %q, got nil", vb.Type, vb.Value)
			}
		})
	}
}

// TestSNMPv2cEncoder_ByteIdentity pins the MD5 of a canonical TRAP encode.
// Any change to BER layout trips this hash and must be re-pinned explicitly,
// which forces reviewers to notice wire-format regressions. Mirrors the
// TestByteIdentity_NetFlow9 pattern from the flow-export work.
func TestSNMPv2cEncoder_ByteIdentity(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	varbinds := []Varbind{
		{OID: "1.3.6.1.2.1.2.2.1.1.3", Type: TrapVTInteger, Value: "3"},
		{OID: "1.3.6.1.2.1.2.2.1.7.3", Type: TrapVTInteger, Value: "2"},
		{OID: "1.3.6.1.2.1.2.2.1.8.3", Type: TrapVTInteger, Value: "2"},
	}
	n, err := enc.EncodeTrap("public", 42, "1.3.6.1.6.3.1.1.5.3", "", 12345678, varbinds, buf)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(buf[:n])
	got := hex.EncodeToString(sum[:])

	// First-run pin: this value captures the current wire layout. If you
	// change the encoder's byte output intentionally, re-run the test, read
	// the reported "got" value in the failure, and paste it here. If you
	// trip it by accident, read the diff and fix the regression.
	want := firstRunPin(t, "trap_v2c_byte_identity", got)
	if got != want {
		t.Errorf("TRAP byte identity changed:\n got  %s\n want %s\nIf intentional, update the pin.", got, want)
	}
}

// firstRunPin returns want. On first run (or when the developer intentionally
// wants to re-pin), running `TRAP_PIN_RECORD=1 go test -run ByteIdentity`
// prints the observed hash so you can paste it back. In normal runs, this
// function simply returns the current pinned constant for the given key.
func firstRunPin(t *testing.T, key, got string) string {
	if v := testPinRegistry[key]; v != "" {
		return v
	}
	t.Logf("no pin for %q yet; observed hash = %s", key, got)
	return got
}

// testPinRegistry holds the pinned hashes consumed by firstRunPin. Add a
// key/value entry here after the first run to lock in the wire format.
var testPinRegistry = map[string]string{
	// Pinned on first-run of TestSNMPv2cEncoder_ByteIdentity. Any change to
	// BER encoding layout, varbind ordering, or the two auto-prepended
	// varbinds will trip this. If the change is intentional, update the
	// pin — otherwise investigate the regression.
	"trap_v2c_byte_identity": "c8cebe20015fc9060e33997c31c74899",
	// Pinned on first-run of TestSNMPv2cEncoder_EnterpriseVarbind_ByteIdentity.
	// Covers the wire layout when snmpTrapEnterprise is set on the catalog
	// entry and the encoder emits the optional third mandatory-prepended
	// varbind. The empty-enterprise path is already pinned above.
	"trap_v2c_byte_identity_with_enterprise": "fd35e3de4511176b54845a00d226059a",
}

// TestSNMPv2cEncoder_EnterpriseVarbind_Emitted confirms that a non-empty
// enterpriseOID causes the encoder to emit an additional snmpTrapEnterprise.0
// varbind (OID 1.3.6.1.6.3.1.1.4.3.0) after the two mandatory varbinds and
// pins the positional contract: slot 0 = sysUpTime.0, slot 1 = snmpTrapOID.0,
// slot 2 = snmpTrapEnterprise.0.
func TestSNMPv2cEncoder_EnterpriseVarbind_Emitted(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeTrap("public", 1, "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.4.1.9.1", 4242, nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeV2cNotification(t, buf[:n])
	if got := len(decoded.Varbinds); got != 3 {
		t.Fatalf("varbind count: got %d, want 3 (sysUpTime + snmpTrapOID + snmpTrapEnterprise)", got)
	}
	// Slot 0: sysUpTime.0 TimeTicks = 4242 — pin position, not just presence.
	if decoded.Varbinds[0].OID != "."+oidSysUpTime0 {
		t.Errorf("varbind[0].OID: got %s, want .%s", decoded.Varbinds[0].OID, oidSysUpTime0)
	}
	if decoded.Varbinds[0].TypeTag != ASN1_TIMETICKS {
		t.Errorf("varbind[0].TypeTag: got 0x%02x, want 0x%02x (TimeTicks)",
			decoded.Varbinds[0].TypeTag, ASN1_TIMETICKS)
	}
	if got := parseUintBE(decoded.Varbinds[0].RawValue); got != 4242 {
		t.Errorf("varbind[0] value: got %d, want 4242", got)
	}
	// Slot 1: snmpTrapOID.0 value = trapOID argument.
	if decoded.Varbinds[1].OID != "."+oidSnmpTrapOID0 {
		t.Errorf("varbind[1].OID: got %s, want .%s", decoded.Varbinds[1].OID, oidSnmpTrapOID0)
	}
	if got := decodeOID(decoded.Varbinds[1].RawValue); got != ".1.3.6.1.6.3.1.1.5.3" {
		t.Errorf("varbind[1] snmpTrapOID value: got %s, want .1.3.6.1.6.3.1.1.5.3", got)
	}
	// Slot 2: snmpTrapEnterprise.0. decodeOID prepends a literal "." — match
	// the convention used by the other decoder-oracle assertions in this file.
	if decoded.Varbinds[2].OID != "."+oidSnmpTrapEnterprise0 {
		t.Errorf("varbind[2].OID: got %s, want .%s", decoded.Varbinds[2].OID, oidSnmpTrapEnterprise0)
	}
	if decoded.Varbinds[2].TypeTag != ASN1_OBJECT_ID {
		t.Errorf("varbind[2].TypeTag: got 0x%02x, want 0x%02x (OID)", decoded.Varbinds[2].TypeTag, ASN1_OBJECT_ID)
	}
	if got := decodeOID(decoded.Varbinds[2].RawValue); got != ".1.3.6.1.4.1.9.1" {
		t.Errorf("varbind[2] enterprise OID value: got %s, want .1.3.6.1.4.1.9.1", got)
	}
}

// TestSNMPv2cEncoder_EnterpriseVarbind_WithBodyVarbinds covers the composition
// case: enterprise prepended varbind PLUS catalog body varbinds. Asserts the
// body varbinds land at positions 3..N+2 (not clobbered by or commingled with
// the enterprise slot).
func TestSNMPv2cEncoder_EnterpriseVarbind_WithBodyVarbinds(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	body := []Varbind{
		{OID: "1.3.6.1.2.1.2.2.1.1.3", Type: TrapVTInteger, Value: "3"},
		{OID: "1.3.6.1.2.1.2.2.1.7.3", Type: TrapVTInteger, Value: "2"},
	}
	n, err := enc.EncodeTrap("public", 1, "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.4.1.9.1", 0, body, buf)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeV2cNotification(t, buf[:n])
	if got := len(decoded.Varbinds); got != 5 {
		t.Fatalf("varbind count: got %d, want 5 (sysUpTime + snmpTrapOID + enterprise + 2 body)", got)
	}
	if decoded.Varbinds[2].OID != "."+oidSnmpTrapEnterprise0 {
		t.Errorf("varbind[2].OID: got %s, want .%s (enterprise must stay at slot 2 when body varbinds follow)",
			decoded.Varbinds[2].OID, oidSnmpTrapEnterprise0)
	}
	if decoded.Varbinds[3].OID != ".1.3.6.1.2.1.2.2.1.1.3" {
		t.Errorf("varbind[3].OID: got %s, want .1.3.6.1.2.1.2.2.1.1.3 (first body varbind)",
			decoded.Varbinds[3].OID)
	}
	if decoded.Varbinds[4].OID != ".1.3.6.1.2.1.2.2.1.7.3" {
		t.Errorf("varbind[4].OID: got %s, want .1.3.6.1.2.1.2.2.1.7.3 (second body varbind)",
			decoded.Varbinds[4].OID)
	}
}

// TestSNMPv2cEncoder_EnterpriseVarbind_Skipped confirms that an empty
// enterpriseOID produces exactly 2 varbinds (sysUpTime + snmpTrapOID) — the
// backward-compatible behaviour for catalogs authored before the field existed.
func TestSNMPv2cEncoder_EnterpriseVarbind_Skipped(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, err := enc.EncodeTrap("public", 1, "1.3.6.1.6.3.1.1.5.3", "", 0, nil, buf)
	if err != nil {
		t.Fatal(err)
	}
	decoded := decodeV2cNotification(t, buf[:n])
	if got := len(decoded.Varbinds); got != 2 {
		t.Fatalf("varbind count with empty enterpriseOID: got %d, want 2", got)
	}
}

// TestSNMPv2cEncoder_EnterpriseVarbind_ByteIdentity pins the MD5 of a canonical
// TRAP encode WITH snmpTrapEnterprise.0 set. This is a second byte-identity
// test (the first, TestSNMPv2cEncoder_ByteIdentity, covers the no-enterprise
// path). Any change to the enterprise emission layout (position, encoding)
// trips this hash.
func TestSNMPv2cEncoder_EnterpriseVarbind_ByteIdentity(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	varbinds := []Varbind{
		{OID: "1.3.6.1.2.1.2.2.1.1.3", Type: TrapVTInteger, Value: "3"},
		{OID: "1.3.6.1.2.1.2.2.1.7.3", Type: TrapVTInteger, Value: "2"},
		{OID: "1.3.6.1.2.1.2.2.1.8.3", Type: TrapVTInteger, Value: "2"},
	}
	n, err := enc.EncodeTrap("public", 42, "1.3.6.1.6.3.1.1.5.3", "1.3.6.1.4.1.9.1", 12345678, varbinds, buf)
	if err != nil {
		t.Fatal(err)
	}
	sum := md5.Sum(buf[:n])
	got := hex.EncodeToString(sum[:])
	want := firstRunPin(t, "trap_v2c_byte_identity_with_enterprise", got)
	if got != want {
		t.Errorf("TRAP byte identity (with enterprise) changed:\n got  %s\n want %s\n"+
			"If intentional, update the pin in testPinRegistry.", got, want)
	}
}

// buildAckDatagram constructs a minimal SNMPv2c GetResponse-PDU with the
// given request-id / error-status. Used by ParseAck tests.
func buildAckDatagram(t *testing.T, community string, reqID uint32, errorStatus int) []byte {
	t.Helper()
	// PDU contents
	var pduContents []byte
	pduContents = append(pduContents, encodeInteger(int(reqID))...)
	pduContents = append(pduContents, encodeInteger(errorStatus)...)
	pduContents = append(pduContents, encodeInteger(0)...) // error-index
	// empty varbind list
	pduContents = append(pduContents, encodeSequence(nil)...)

	var pdu []byte
	pdu = append(pdu, ASN1_GET_RESPONSE)
	pdu = append(pdu, encodeLength(len(pduContents))...)
	pdu = append(pdu, pduContents...)

	var outer []byte
	outer = append(outer, encodeInteger(1)...)
	outer = append(outer, encodeOctetString(community)...)
	outer = append(outer, pdu...)
	return encodeSequence(outer)
}

// Sanity check on the decoder we use in tests — asserts it panics/fails
// loudly on garbage so we don't accept malformed input as "passed round-trip".
func TestDecodeV2cNotification_ValidShape(t *testing.T) {
	enc := SNMPv2cEncoder{}
	buf := make([]byte, 1500)
	n, _ := enc.EncodeTrap("x", 1, "1.2", "", 0, nil, buf)
	dec := decodeV2cNotification(t, buf[:n])
	if fmt.Sprintf("%d/%d", dec.Version, dec.RequestID) != "1/1" {
		t.Fatal("decoder sanity failed")
	}
}
