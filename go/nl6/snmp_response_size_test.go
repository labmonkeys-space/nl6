//go:build linux

/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

// Note: the //go:build linux constraint above matches snmp_getbulk_test.go,
// whose buildGetBulkPDU these tests reuse; the package's Linux-only paths are
// the TUN/netns runtime, not these encoders. The shared server constructor
// lives in the untagged snmp_testutil_test.go.

package main

import (
	"fmt"
	"testing"
)

// nl6#489: GETBULK responses were never truncated. `handleGetBulk` built
// `maxRepetitions × repeaterCols` variable bindings with no size check, and
// there is no `tooBig` anywhere in the SNMP path. RFC 3416 §4.2.3 requires an
// agent to return "as many variable bindings as fit"; nl6 built the whole
// response and handed it to the kernel, which fragmented it.
//
// Fragmentation is the visible symptom, but not the defect. The defect is that
// a collector tuning `max-repetitions` against nl6 can never find the
// truncation knee real hardware would give it — so the tuning experiment
// measures a regime that cannot occur in production.

// sizeTestColumns are the ifTable/ifXTable columns an OpenNMS SNMP collector
// actually walks. Response size scales as columns × repetitions, so this is the
// shape the numbers below describe.
var sizeTestColumns = []string{
	"1.3.6.1.2.1.2.2.1.2",     // ifDescr        (string)
	"1.3.6.1.2.1.2.2.1.5",     // ifSpeed
	"1.3.6.1.2.1.2.2.1.7",     // ifAdminStatus
	"1.3.6.1.2.1.2.2.1.8",     // ifOperStatus
	"1.3.6.1.2.1.2.2.1.10",    // ifInOctets
	"1.3.6.1.2.1.2.2.1.16",    // ifOutOctets
	"1.3.6.1.2.1.31.1.1.1.1",  // ifName
	"1.3.6.1.2.1.31.1.1.1.6",  // ifHCInOctets
	"1.3.6.1.2.1.31.1.1.1.10", // ifHCOutOctets
	"1.3.6.1.2.1.31.1.1.1.18", // ifAlias
}

// newSizeTestServer builds a device with `ifaces` interfaces populated across
// every column in sizeTestColumns.
func newSizeTestServer(ifaces int) *SNMPServer {
	vals := map[string]string{}
	for i := 1; i <= ifaces; i++ {
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.2.%d", i)] = fmt.Sprintf("GigabitEthernet0/%d", i)
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.5.%d", i)] = "1000000000"
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.7.%d", i)] = "1"
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.8.%d", i)] = "1"
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.10.%d", i)] = "4294967290"
		vals[fmt.Sprintf("1.3.6.1.2.1.2.2.1.16.%d", i)] = "4294967290"
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.1.%d", i)] = fmt.Sprintf("Gi0/%d", i)
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.6.%d", i)] = "18446744073709551000"
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.10.%d", i)] = "18446744073709551000"
		vals[fmt.Sprintf("1.3.6.1.2.1.31.1.1.1.18.%d", i)] = fmt.Sprintf("uplink-to-spine-%d", i)
	}
	return newTestServer(vals)
}

// columnsFor repeats the walked columns until it has n of them.
func columnsFor(n int) []string {
	var out []string
	for len(out) < n {
		out = append(out, sizeTestColumns...)
	}
	return out[:n]
}

// countResponseVarbinds parses a GetResponse and returns how many variable
// bindings it carries, plus the error-status.
//
// Deliberately parses the real bytes rather than trusting a returned count:
// every bug in this family has been a mismatch between what a component
// reported and what it actually emitted.
func countResponseVarbinds(t *testing.T, msg []byte) (n int, errStatus int) {
	t.Helper()
	oids, _, err := parseGetBulkResponse(msg)
	if err != nil {
		t.Fatalf("parse response (%d bytes): %v", len(msg), err)
	}
	return len(oids), responseErrorStatus(t, msg)
}

// responseErrorStatus extracts error-status from a GetResponse PDU.
func responseErrorStatus(t *testing.T, msg []byte) int {
	t.Helper()
	pos := 0
	if pos >= len(msg) || msg[pos] != ASN1_SEQUENCE {
		t.Fatalf("expected outer SEQUENCE")
	}
	pos++
	_, pos = parseLength(msg, pos)
	// version
	pos++
	vLen, p2 := parseLength(msg, pos)
	pos = p2 + vLen
	// community
	pos++
	cLen, p3 := parseLength(msg, pos)
	pos = p3 + cLen
	// PDU
	if pos >= len(msg) || msg[pos] != SNMP_GET_RESPONSE {
		t.Fatalf("expected GetResponse PDU, got %#x", safeAt(msg, pos))
	}
	pos++
	_, pos = parseLength(msg, pos)
	// request-id
	pos++
	rLen, p4 := parseLength(msg, pos)
	pos = p4 + rLen
	// error-status
	if pos >= len(msg) || msg[pos] != ASN1_INTEGER {
		t.Fatalf("expected error-status INTEGER")
	}
	pos++
	eLen, p5 := parseLength(msg, pos)
	pos = p5
	status := 0
	for i := 0; i < eLen && pos+i < len(msg); i++ {
		status = status<<8 | int(msg[pos+i])
	}
	return status
}

// buildBulkPDU is buildGetBulkPDU with an explicit column list.
func buildBulkPDU(nonRep, maxRep int, oids []string) []byte {
	return buildGetBulkPDU(nonRep, maxRep, oids)
}

// TestGetBulkSizeCurve records how response size scales with columns ×
// repetitions, so the fragmentation onset is a pinned fact rather than
// something rediscovered.
//
// These were the numbers that motivated nl6#489. The OpenNMS collector default
// (30 columns × max-repetitions 2) lands at a 1464 B frame against a 1500 B
// MTU — 36 bytes of headroom, which is why nothing fragments out of the box and
// why anything above it does.
func TestGetBulkSizeCurve(t *testing.T) {
	s := newSizeTestServer(64)
	t.Logf("%5s %8s %10s %10s %8s", "cols", "maxRep", "varbinds", "respBytes", "frame")
	for _, c := range []struct{ cols, rep int }{
		{10, 2}, {30, 2}, {10, 10}, {10, 25}, {10, 50}, {10, 127},
	} {
		cols := columnsFor(c.cols)
		resp := s.handleGetBulk(cols[0], buildBulkPDU(0, c.rep, cols))
		n, _ := countResponseVarbinds(t, resp)
		t.Logf("%5d %8d %10d %10d %8d", c.cols, c.rep, n, len(resp),
			len(resp)+ipv4HeaderBytes+udpHeaderBytes)
	}
}

// TestGetBulkDefaultCollectorResponseIsNotTruncated is the regression bar this
// change must not move.
//
// OpenNMS's SNMP collector uses max-vars-per-pdu 30 and max-repetitions 2
// (SnmpConfiguration.java, AbstractSnmpCollector.java). That returns 60
// variable bindings today and MUST keep returning 60. An off-by-a-little budget
// would silently halve collector throughput in the most common configuration —
// a worse bug than either of the ones being fixed.
func TestGetBulkDefaultCollectorResponseIsNotTruncated(t *testing.T) {
	s := newSizeTestServer(64)
	cols := columnsFor(30)
	resp := s.handleGetBulk(cols[0], buildBulkPDU(0, 2, cols))

	n, status := countResponseVarbinds(t, resp)
	if status != 0 {
		t.Fatalf("error-status = %d, want noError for a response that fits", status)
	}
	if n != 60 {
		t.Errorf("OpenNMS default (30 cols × maxRep 2) returned %d variable bindings, want 60 — "+
			"truncation must not cut the most common collector configuration", n)
	}
	if frame := len(resp) + ipv4HeaderBytes + udpHeaderBytes; frame > linkMTU {
		t.Errorf("the default collector response is %d B (frame %d B), over the %d B MTU",
			len(resp), frame, linkMTU)
	}
}

// TestGetBulkParseMaxRepetitions pins the parser defect: BER encodes any
// INTEGER ≥ 128 in two bytes (the leading 0x00 keeps it positive), so a parser
// that accepts only single-byte content silently falls back to its default at
// 128 — not 255, and right in the middle of the range operators tune.
func TestGetBulkParseMaxRepetitions(t *testing.T) {
	s := &SNMPServer{}
	for _, want := range []int{1, 10, 25, 50, 100, 127, 128, 200, 255, 300, 1000} {
		pdu := buildBulkPDU(0, want, []string{"1.3.6.1.2.1.2.2.1.2"})
		_, got := s.parseGetBulkParams(pdu)
		if got != want {
			t.Errorf("max-repetitions %d parsed as %d (BER content is %d bytes) — a requested "+
				"value must never be silently replaced by a default",
				want, got, len(encodeInteger(want))-2)
		}
	}
}

// TestGetBulkResponsesFitTheBudget is the core assertion: no response, at any
// columns × repetitions, may exceed the datagram budget.
func TestGetBulkResponsesFitTheBudget(t *testing.T) {
	s := newSizeTestServer(64)
	for _, c := range []struct{ cols, rep int }{
		{1, 1}, {10, 2}, {30, 2}, {10, 10}, {10, 50}, {10, 127},
		{30, 127}, {10, 1000}, {30, 1000},
	} {
		name := fmt.Sprintf("cols%d_rep%d", c.cols, c.rep)
		t.Run(name, func(t *testing.T) {
			cols := columnsFor(c.cols)
			resp := s.handleGetBulk(cols[0], buildBulkPDU(0, c.rep, cols))
			if len(resp) > maxSNMPResponseSize {
				t.Errorf("response is %d B, over the %d B budget (frame %d B against a %d B MTU)",
					len(resp), maxSNMPResponseSize,
					len(resp)+ipv4HeaderBytes+udpHeaderBytes, linkMTU)
			}
			n, status := countResponseVarbinds(t, resp)
			if status != 0 {
				t.Errorf("error-status = %d; GETBULK truncates rather than erroring", status)
			}
			if n == 0 {
				t.Error("zero variable bindings returned; a walk would stall forever with no error")
			}
		})
	}
}

// TestGetBulkTruncatedWalkResumesWithoutGapOrRepeat checks the property that
// makes truncation safe at all: the collector continues from the last OID
// returned, and the union of the two responses is what one untruncated
// response would have held.
func TestGetBulkTruncatedWalkResumesWithoutGapOrRepeat(t *testing.T) {
	s := newSizeTestServer(64)
	cols := columnsFor(1) // single column keeps the walk order linear and checkable

	first := s.handleGetBulk(cols[0], buildBulkPDU(0, 1000, cols))
	oids1, _, err := parseGetBulkResponse(first)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	if len(oids1) == 0 {
		t.Fatal("first response empty")
	}
	if len(first) > maxSNMPResponseSize {
		t.Fatalf("first response %d B exceeds the %d B budget", len(first), maxSNMPResponseSize)
	}

	// Resume from the last OID returned, exactly as a collector does.
	last := oids1[len(oids1)-1]
	second := s.handleGetBulk(last, buildBulkPDU(0, 1000, []string{last}))
	oids2, _, err := parseGetBulkResponse(second)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}

	seen := map[string]bool{}
	for _, o := range oids1 {
		seen[o] = true
	}
	for _, o := range oids2 {
		if seen[o] {
			t.Errorf("OID %s returned in both responses — the resume point overlaps", o)
			break
		}
	}
	if len(oids2) > 0 && compareOIDs(oids2[0], last) <= 0 {
		t.Errorf("resume returned %s, which is not after the last OID of the first response (%s) "+
			"— the walk would loop or skip", oids2[0], last)
	}
}

// TestGetRequestTooBigRatherThanTruncated is the GET half (design D3).
//
// A multi-OID GET shares GETBULK's response encoder (snmp_server.go, deliberate
// since nl6#176 — Enlinkd bundles three lldp OIDs in one GET). RFC 3416 §4.2.1
// gives it the OPPOSITE rule: a response that will not fit must return tooBig
// with an EMPTY variable-binding list. A GET requester asked for specific
// bindings and has no resume point, so a partial answer is an unsignalled wrong
// answer.
func TestGetRequestTooBigRatherThanTruncated(t *testing.T) {
	// One interface, but a value long enough that a handful of bindings
	// overflow the budget.
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	vals := map[string]string{}
	var oids []string
	for i := 1; i <= 8; i++ {
		oid := fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.18.%d", i)
		vals[oid] = string(long)
		oids = append(oids, oid)
	}
	s := newTestServer(vals)

	resp := s.handleGetRequestVarbinds(oids, buildGetPDU(oids))
	if len(resp) > maxSNMPResponseSize {
		t.Errorf("GET response is %d B, over the %d B budget — it must be replaced by tooBig, "+
			"not emitted oversized", len(resp), maxSNMPResponseSize)
	}
	n, status := countResponseVarbinds(t, resp)
	if status != snmpErrTooBig {
		t.Errorf("error-status = %d, want tooBig(%d) — a GET has no resume point, so a "+
			"truncated response is a silent partial answer", status, snmpErrTooBig)
	}
	if n != 0 {
		t.Errorf("tooBig response carries %d variable bindings, want 0 (RFC 3416 §4.2.1)", n)
	}
}

// TestGetRequestThatFitsReturnsEveryBinding guards the nl6#176 behaviour that
// the shared encoder exists for.
func TestGetRequestThatFitsReturnsEveryBinding(t *testing.T) {
	// Dotted form: findResponse matches on it (see its sysLocation/sysName fast
	// paths) and the encoder emits it, so request and expectation agree.
	oids := []string{
		".1.0.8802.1.1.2.1.3.7.1.2.1", // lldpLocPortIdSubtype
		".1.0.8802.1.1.2.1.3.7.1.3.1", // lldpLocPortId
		".1.0.8802.1.1.2.1.3.7.1.4.1", // lldpLocPortDesc
	}
	s := newTestServer(map[string]string{
		oids[0]: "5",
		oids[1]: "Gi0/1",
		oids[2]: "uplink to spine 1",
	})

	resp := s.handleGetRequestVarbinds(oids, buildGetPDU(oids))
	got, _, err := parseGetBulkResponse(resp)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != len(oids) {
		t.Fatalf("GET returned %d variable bindings, want %d — nl6#176 regression "+
			"(Enlinkd bundles these three and a partial answer breaks topology discovery)",
			len(got), len(oids))
	}
	for i := range oids {
		if got[i] != oids[i] {
			t.Errorf("binding %d is %s, want %s — bindings must be returned in request order",
				i, got[i], oids[i])
		}
	}
}

// TestSameOversizedSetTruncatesUnderBulkAndFailsUnderGet is the assertion that
// catches the two rules getting crossed. It is the single most important test
// in this change: one encoder, two rules, and the only thing distinguishing
// them is which PDU asked.
func TestSameOversizedSetTruncatesUnderBulkAndFailsUnderGet(t *testing.T) {
	s := newSizeTestServer(64)
	cols := columnsFor(10)

	bulk := s.handleGetBulk(cols[0], buildBulkPDU(0, 127, cols))
	bulkN, bulkStatus := countResponseVarbinds(t, bulk)
	if bulkStatus != 0 {
		t.Errorf("GETBULK error-status = %d, want noError — GETBULK truncates", bulkStatus)
	}
	if bulkN == 0 {
		t.Error("GETBULK returned nothing; it must return as many bindings as fit")
	}
	if len(bulk) > maxSNMPResponseSize {
		t.Errorf("GETBULK response %d B over the %d B budget", len(bulk), maxSNMPResponseSize)
	}

	// The same overflowing quantity of data, asked for as a GET.
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'x'
	}
	vals := map[string]string{}
	var getOIDs []string
	for i := 1; i <= 8; i++ {
		oid := fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.18.%d", i)
		vals[oid] = string(long)
		getOIDs = append(getOIDs, oid)
	}
	gs := newTestServer(vals)
	get := gs.handleGetRequestVarbinds(getOIDs, buildGetPDU(getOIDs))
	getN, getStatus := countResponseVarbinds(t, get)
	if getStatus != snmpErrTooBig {
		t.Errorf("GET error-status = %d, want tooBig(%d) — GET must NOT truncate",
			getStatus, snmpErrTooBig)
	}
	if getN != 0 {
		t.Errorf("GET tooBig carries %d bindings, want 0", getN)
	}
}

// buildGetPDU already exists in snmp_getbulk_test.go and is reused here.

// TestGetBulkMalformedPDUDoesNotPanic is the regression test for a remotely
// triggerable crash introduced by this change and caught in review.
//
// Making parseBERInt sign-extend meant a non-repeaters field of INTEGER 0xFF
// parsed as -1. The negative clamp sat AFTER six early returns, so a PDU whose
// max-repetitions field is absent took one of them and carried -1 into
// handleGetBulk, where `allOIDs[cap:]` panicked with "slice bounds out of range
// [-1:]". There is no recover() on the SNMP serve path, so one malformed UDP
// packet took the whole simulator down. Before the change `int(data[pos])`
// yielded 255 and clamped harmlessly.
//
// Sweeps a range of malformed shapes rather than only the one found, because
// the class — a hostile value reaching a slice index — is what matters.
func TestGetBulkMalformedPDUDoesNotPanic(t *testing.T) {
	s := newSizeTestServer(4)
	vb := encodeSequence(encodeSequence(append(encodeOID("1.3.6.1.2.1.2.2.1.2"), encodeNull()...)))

	build := func(fields ...[]byte) []byte {
		body := encodeInteger(42)
		for _, f := range fields {
			body = append(body, f...)
		}
		body = append(body, vb...)
		pdu := []byte{ASN1_GET_BULK}
		pdu = append(pdu, encodeLength(len(body))...)
		pdu = append(pdu, body...)
		msg := encodeInteger(1)
		msg = append(msg, encodeOctetString("public")...)
		msg = append(msg, pdu...)
		return encodeSequence(msg)
	}

	neg1 := []byte{ASN1_INTEGER, 0x01, 0xFF}          // -1
	neg128 := []byte{ASN1_INTEGER, 0x01, 0x80}        // -128
	negWide := []byte{ASN1_INTEGER, 0x02, 0xFF, 0x00} // -256

	for _, tc := range []struct {
		name string
		pdu  []byte
	}{
		{"negative non-repeaters, max-repetitions absent", build(neg1)},
		{"negative non-repeaters and negative max-repetitions", build(neg1, neg1)},
		{"most-negative single octet", build(neg128, neg128)},
		{"negative multi-octet", build(negWide, negWide)},
		{"non-repeaters only, nothing after", build(neg1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			nr, mr := s.parseGetBulkParams(tc.pdu)
			if nr < 0 || mr < 0 {
				t.Errorf("parsed negative values (nonRepeaters=%d maxRepetitions=%d); they reach "+
					"a slice index and panic the serve path", nr, mr)
			}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("handleGetBulk panicked on a malformed PDU: %v — one packet would "+
						"take the simulator down, there is no recover() on the serve path", r)
				}
			}()
			s.handleGetBulk("1.3.6.1.2.1.2.2.1.2", tc.pdu)
		})
	}
}

// TestGetBulkWalkClampAppliesBelowTheGlobalCeiling guards the walk guard.
//
// The first version wrapped the per-column clamp in `maxRepetitions > maxFit`,
// which made it inert for everything below ~98 — so 30 columns x 98 repetitions
// still walked 2940 MIB steps to emit the ~60 bindings that fit, which is the
// amplification the guard exists to stop.
//
// Asserted through the parser+handler rather than by reading the clamp, so it
// measures the effect rather than restating the implementation.
func TestGetBulkWalkClampAppliesBelowTheGlobalCeiling(t *testing.T) {
	s := newSizeTestServer(64)
	cols := columnsFor(30)

	// 98 is under the global maxFit (budget/minVarbindSize) but far over what
	// 30 columns can fit, so the per-column clamp must engage.
	resp := s.handleGetBulk(cols[0], buildBulkPDU(0, 98, cols))
	n, status := countResponseVarbinds(t, resp)
	if status != snmpErrNoError {
		t.Fatalf("error-status = %d, want noError", status)
	}
	if len(resp) > maxSNMPResponseSize {
		t.Errorf("response %d B over the %d B budget", len(resp), maxSNMPResponseSize)
	}
	// The response must still be full: the clamp is a CPU guard and must never
	// cost datagram utilisation.
	full := s.handleGetBulk(cols[0], buildBulkPDU(0, 2, cols))
	fullN, _ := countResponseVarbinds(t, full)
	if n < fullN {
		t.Errorf("clamped walk returned %d bindings but maxRep 2 returned %d — the CPU guard "+
			"is under-filling the datagram", n, fullN)
	}
}

// TestGetOversizedSingleBindingStillReturnsTooBig guards the escape hatch.
//
// "Always emit at least one binding" is correct for GETBULK — an empty
// no-error response stalls a walk forever. Applying it to GET produced an
// oversized datagram carrying error-status noError: the fragmenting response
// this bound exists to prevent, and a violation of RFC 3416 §4.2.1 that the
// same function enforces elsewhere. Reachable at a low -datagram-mtu with an
// ordinary long value.
func TestGetOversizedSingleBindingStillReturnsTooBig(t *testing.T) {
	restoreLinkMTU(t)
	if err := SetLinkMTU(minLinkMTU); err != nil {
		t.Fatal(err)
	}

	long := make([]byte, 900)
	for i := range long {
		long[i] = 'x'
	}
	oid := ".1.3.6.1.2.1.1.1.0"
	s := newTestServer(map[string]string{oid: string(long)})

	resp := s.handleGetRequestVarbinds([]string{oid}, buildGetPDU([]string{oid}))
	n, status := countResponseVarbinds(t, resp)
	if status != snmpErrTooBig {
		t.Errorf("single oversized binding: error-status = %d, want tooBig(%d) — the "+
			"always-emit-one relaxation must not apply to GET", status, snmpErrTooBig)
	}
	if n != 0 {
		t.Errorf("tooBig response carries %d bindings, want 0", n)
	}
	if len(resp) > maxSNMPResponseSize {
		t.Errorf("GET emitted a %d B response against a %d B budget — the datagram this "+
			"bound exists to prevent", len(resp), maxSNMPResponseSize)
	}

	// GETBULK keeps the relaxation: a stalled walk is worse than one oversized
	// datagram, and it has no other way to make progress.
	bulk := s.handleGetBulk(oid, buildBulkPDU(0, 1, []string{oid}))
	bn, bstatus := countResponseVarbinds(t, bulk)
	if bstatus != snmpErrNoError || bn == 0 {
		t.Errorf("GETBULK returned status=%d bindings=%d; it must still emit one binding "+
			"rather than stall the walk", bstatus, bn)
	}
}

// TestParseBERIntAcceptsPaddedIntegers guards the padded-INTEGER path.
// Rejecting anything wider than 8 octets made the caller keep its default —
// the same "requested value silently replaced" failure the parser fix removes.
func TestParseBERIntAcceptsPaddedIntegers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content []byte
		want    int
	}{
		{"single octet", []byte{0x64}, 100},
		{"two octets, positive", []byte{0x00, 0xC8}, 200},
		{"padded to 4", []byte{0x00, 0x00, 0x00, 0xC8}, 200},
		{"padded to 12", []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xE8}, 1000},
		{"negative", []byte{0xFF}, -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := parseBERInt(tc.content, 0, len(tc.content))
			if !ok {
				t.Fatalf("rejected a legal INTEGER; the caller would silently keep its default")
			}
			if got != tc.want {
				t.Errorf("parsed %d, want %d", got, tc.want)
			}
		})
	}
}
