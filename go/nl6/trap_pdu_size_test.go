/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"log"
	"math"
	"math/rand"
	"net"
	"sort"
	"strings"
	"testing"
	"time"
)

// nl6#487: maxTrapPDU bounded an assembled notification at the Ethernet MTU but
// applied that bound to the UDP PAYLOAD, so a trap at the limit landed at 1528
// bytes on the wire and fragmented — the same buffer-versus-frame conflation
// fixed for flow export in nl6#485.
//
// The tests here pin the two facts the design rests on: what shipped content
// actually encodes to, and the MTU below which it stops fitting.

// worstCaseTrapCtx is the template context the size checks render with: every
// field at a plausible maximum, so an entry that fits here fits in production.
//
// Detail is deliberately EMPTY. It is per-fire free-form (the optical SD/SF
// alarms carry the triggering OSNR through it) and has no worst case; assuming
// one would disable valid entries to guard a case the fire-time encode check
// already covers. See design D2.
func worstCaseTrapCtx() TemplateCtx {
	return TemplateCtx{
		IfIndex:   2147483647,
		IfName:    "GigabitEthernet0/2147483647",
		Uptime:    4294967295,
		Now:       time.Now().Unix(),
		DeviceIP:  "255.255.255.255",
		SysName:   "device-with-a-fairly-long-system-name-0000",
		Model:     "Ciena Waveserver 5",
		Serial:    "SNffffffff",
		ChassisID: "02:42:ff:ff:ff:ff",
		NowLocal:  "2026-12-31 23:59:59",
		Detail:    "",
	}
}

// shippedTrapCatalogs returns every catalog that ships in the binary or the
// resource tree, labelled by source.
func shippedTrapCatalogs(t *testing.T) map[string]*Catalog {
	t.Helper()
	out := map[string]*Catalog{}
	uni, err := LoadEmbeddedCatalog()
	if err != nil {
		t.Fatalf("LoadEmbeddedCatalog: %v", err)
	}
	out["_universal"] = uni
	for _, slug := range []string{"ciena_waveserver5", "cisco_ios", "juniper_mx240"} {
		c, err := LoadCatalogFromFile("resources/" + slug + "/traps.json")
		if err != nil {
			t.Fatalf("load %s: %v", slug, err)
		}
		out[slug] = c
	}
	return out
}

// encodedTrapSize renders and encodes one entry exactly as the fire path would,
// returning the PDU byte count.
func encodedTrapSize(t *testing.T, e *CatalogEntry, ctx TemplateCtx) int {
	t.Helper()
	vbs, err := e.Resolve(ctx, nil)
	if err != nil {
		t.Fatalf("resolve %s: %v", e.Name, err)
	}
	pdu, err := encodeV2cNotificationFast(make([]byte, 0, 65535), 0xA7, "public", 1,
		nil, e.SnmpTrapOID, e.SnmpTrapEnterprise, 12345, vbs)
	if err != nil {
		t.Fatalf("encode %s: %v", e.Name, err)
	}
	return len(pdu)
}

// TestShippedTrapEntriesFitTheBudget is the evidence that correcting the bound
// costs nothing that ships, and it records the margin.
//
// The margin is the point. A glance at the catalogs suggests traps are ~200 B
// and the bound is unreachable; the Ciena optical alarms carry 39 varbinds and
// encode to ~1005 B, which is 67% of the old 1500 bound. Sizing OIDs as dotted
// strings rather than BER is what makes them look small.
func TestShippedTrapEntriesFitTheBudget(t *testing.T) {
	ctx := worstCaseTrapCtx()
	type row struct {
		size  int
		label string
	}
	var rows []row
	for src, c := range shippedTrapCatalogs(t) {
		for _, e := range c.Entries {
			rows = append(rows, row{encodedTrapSize(t, e, ctx), src + "/" + e.Name})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].size > rows[j].size })

	budget := maxTrapPDU
	for _, r := range rows {
		if r.size > budget {
			t.Errorf("%s encodes to %d B, over the %d B budget — correcting the bound "+
				"would silently disable shipped content", r.label, r.size, budget)
		}
	}

	largest := rows[0]
	t.Logf("largest shipped trap: %s at %d B (frame %d B), budget %d B, margin %d B",
		largest.label, largest.size, largest.size+ipv4HeaderBytes+udpHeaderBytes,
		budget, budget-largest.size)

	// Guard the assumption the design rests on: the largest entry is one of the
	// Ciena optical alarms and sits well under half the budget's headroom claim.
	// If a future catalog entry approaches the bound, this fails and the design
	// note about "467 B of margin" needs revisiting rather than silently rotting.
	if margin := budget - largest.size; margin < 300 {
		t.Errorf("largest shipped entry leaves only %d B of margin against the %d B budget; "+
			"design D2's reasoning assumes a comfortable gap", margin, budget)
	}
}

// TestShippedTrapEntriesMinimumMTU pins the MTU below which shipped content
// stops fitting. This figure is what design D2's warn-and-disable decision
// rests on: since `-datagram-mtu` accepts values down to minLinkMTU (576),
// rejecting oversized entries at load would make over half the accepted range
// refuse to boot on nl6's own embedded catalogs.
func TestShippedTrapEntriesMinimumMTU(t *testing.T) {
	ctx := worstCaseTrapCtx()
	largest := 0
	for _, c := range shippedTrapCatalogs(t) {
		for _, e := range c.Entries {
			if n := encodedTrapSize(t, e, ctx); n > largest {
				largest = n
			}
		}
	}

	// The smallest MTU at which the largest shipped entry still fits.
	minMTU := largest + ipv4HeaderBytes + udpHeaderBytes
	t.Logf("shipped traps need MTU >= %d; -datagram-mtu accepts down to %d, "+
		"so %d..%d disables shipped optical entries", minMTU, minLinkMTU, minLinkMTU, minMTU-1)

	if minMTU <= minLinkMTU {
		t.Errorf("largest shipped entry fits at every accepted MTU (need %d, floor %d) — "+
			"design D2's warn-and-disable rationale no longer applies and should be revisited",
			minMTU, minLinkMTU)
	}
	if minMTU > defaultLinkMTU {
		t.Errorf("largest shipped entry needs MTU %d, above the %d default — shipped content "+
			"would be disabled out of the box", minMTU, defaultLinkMTU)
	}
}

// TestMaxTrapPDUIsAFrameBound is the regression test for the bug itself: the
// bound must leave room for the IPv4 and UDP headers, not consume the whole
// MTU. A notification at the bound must produce a frame that fits the link.
func TestMaxTrapPDUIsAFrameBound(t *testing.T) {
	if got, want := maxTrapPDU, linkMTU-ipv4HeaderBytes-udpHeaderBytes; got != want {
		t.Fatalf("maxTrapPDU = %d, want %d (linkMTU %d - IPv4 %d - UDP %d) — a PDU at the "+
			"bound must fit the FRAME, not the MTU",
			got, want, linkMTU, ipv4HeaderBytes, udpHeaderBytes)
	}
	if frame := maxTrapPDU + ipv4HeaderBytes + udpHeaderBytes; frame != linkMTU {
		t.Errorf("a PDU at maxTrapPDU yields a %d B frame against a %d B link", frame, linkMTU)
	}
}

// TestMaxTrapPDUTracksDatagramMTU checks the bound is derived rather than
// literal. A hardcoded 1472 would silently ignore -datagram-mtu and re-break on
// exactly the lower-MTU paths that flag exists to serve.
func TestMaxTrapPDUTracksDatagramMTU(t *testing.T) {
	restoreLinkMTU(t)

	for _, mtu := range []int{1500, 1450, 1200, 9000} {
		if err := SetLinkMTU(mtu); err != nil {
			t.Fatalf("SetLinkMTU(%d): %v", mtu, err)
		}
		if got, want := maxTrapPDU, mtu-ipv4HeaderBytes-udpHeaderBytes; got != want {
			t.Errorf("at -datagram-mtu %d: maxTrapPDU = %d, want %d — the flag did not reach "+
				"the trap bound (is it registered in recomputeDatagramBudgets?)", mtu, got, want)
		}
	}
}

// TestTrapBufferPoolMatchesBound guards the three sites that must agree. The
// scratch clamp exists to stop the reference encoder overrunning a pooled
// buffer; if the pool and the bound drift apart, that protection silently
// inverts into a truncation or an overrun (design D1).
func TestTrapBufferPoolMatchesBound(t *testing.T) {
	buf := trapBufPool.Get().(*trapBuf)
	defer trapBufPool.Put(buf)
	if c := cap(buf.b); c < maxTrapPDU {
		t.Errorf("pooled trap buffer capacity %d is below maxTrapPDU %d — the reference "+
			"encoder's scratch clamp would slice past the allocation", c, maxTrapPDU)
	}
}

// TestTrapEncoderRejectsOverBound checks the fire-time backstop still fires at
// the corrected bound. It is the only defence against a runtime {{.Detail}} or
// a REST varbindOverrides, neither of which a load-time render can bound.
func TestTrapEncoderRejectsOverBound(t *testing.T) {
	// One octet-string varbind sized so the assembled PDU lands just past the
	// bound. The exact overshoot does not matter; crossing it does.
	oversize := maxTrapPDU + 64
	vbs := []Varbind{{
		OID:   "1.3.6.1.2.1.1.5.0",
		Type:  TrapVTOctetString,
		Value: fmt.Sprintf("%*s", oversize, ""),
	}}
	_, err := encodeV2cNotificationFast(make([]byte, 0, 65535), 0xA7, "public", 1,
		nil, "1.3.6.1.6.3.1.1.5.3", "", 12345, vbs)
	if err == nil {
		t.Fatalf("encoder accepted a PDU past maxTrapPDU (%d B) — the fire-time backstop "+
			"is the only guard against oversized runtime values", maxTrapPDU)
	}
}

// TestApplySizeBudget_DisablesRatherThanRejects is the core of design D2's
// reversal. An oversized entry must stay loadable and simply stop firing.
func TestApplySizeBudget_DisablesRatherThanRejects(t *testing.T) {
	c := mustLoadEmbeddedCatalog(t)
	before := len(c.Entries)

	// A budget below every entry disables all of them. The catalog must still
	// be usable — this mirrors the existing all-role-tagged case, where a zero
	// schedulable total is legal.
	disabled := c.ApplySizeBudget(1, "_test")
	if len(disabled) != before {
		t.Fatalf("disabled %d of %d entries at a 1-byte budget, want all", len(disabled), before)
	}
	if len(c.Entries) != before {
		t.Errorf("entries dropped from the catalog (%d -> %d); they should be disabled, not removed",
			before, len(c.Entries))
	}
	if got := c.Pick(rand.New(rand.NewSource(1))); got != nil {
		t.Errorf("Pick returned %q from an all-oversized catalog, want nil", got.Name)
	}
	for _, role := range []string{"link-down", "link-up"} {
		if got := c.EntriesByRole(role); len(got) != 0 {
			t.Errorf("EntriesByRole(%q) returned %d entries; an oversized entry must be "+
				"excluded here too, or it fires on every oper-status transition and fails "+
				"at encode", role, len(got))
		}
	}
}

// TestApplySizeBudget_LeavesFittingEntriesSchedulable checks the filter is
// selective: only entries over the budget stop firing.
//
// Uses the MERGED catalog a ciena device actually resolves to (universal +
// overlay), because the overlay file alone holds only the four optical alarms
// and they all land within ~30 B of each other — nothing to split.
func TestApplySizeBudget_LeavesFittingEntriesSchedulable(t *testing.T) {
	universal := mustLoadEmbeddedCatalog(t)
	overlay, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load ciena: %v", err)
	}
	c := universal.MergeOverlay(overlay)

	// Between the universal entries (~190 B) and the optical alarms (~976 B).
	const budget = 500
	disabled := c.ApplySizeBudget(budget, "ciena_waveserver5")
	if len(disabled) == 0 {
		t.Fatal("no entry disabled at a 500-byte budget; the optical alarms encode to ~976 B")
	}
	if len(disabled) == len(c.Entries) {
		t.Fatalf("every one of %d entries disabled at %d B; the universal entries are ~190 B "+
			"and should survive", len(c.Entries), budget)
	}

	for _, e := range c.Entries {
		size := encodedTrapSize(t, e, worstCaseTrapCtx())
		if e.oversized && size <= budget {
			t.Errorf("%s (%d B) disabled although it fits the %d B budget", e.Name, size, budget)
		}
		if !e.oversized && size > budget {
			t.Errorf("%s (%d B) left schedulable although it exceeds the %d B budget",
				e.Name, size, budget)
		}
	}
}

// TestApplySizeBudget_ShippedCatalogsSurviveDefaultMTU is task 4.8's positive
// half: nothing that ships is disabled out of the box.
func TestApplySizeBudget_ShippedCatalogsSurviveDefaultMTU(t *testing.T) {
	restoreLinkMTU(t)
	if err := SetLinkMTU(defaultLinkMTU); err != nil {
		t.Fatal(err)
	}
	for src, c := range shippedTrapCatalogs(t) {
		if d := c.ApplySizeBudget(maxTrapPDU, src); len(d) != 0 {
			t.Errorf("%s: %d entries disabled at the default MTU: %v", src, len(d), d)
		}
	}
}

// TestApplySizeBudget_LowMTUDisablesOpticalEntries is the negative half, and
// the concrete case design D2 refuses to turn into a startup abort.
func TestApplySizeBudget_LowMTUDisablesOpticalEntries(t *testing.T) {
	restoreLinkMTU(t)
	if err := SetLinkMTU(1000); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load ciena: %v", err)
	}
	disabled := c.ApplySizeBudget(maxTrapPDU, "ciena_waveserver5")
	if len(disabled) == 0 {
		t.Errorf("no entry disabled at -datagram-mtu 1000 (budget %d); the optical alarms "+
			"encode to ~976 B and should not fit", maxTrapPDU)
	}
	// The point of the whole decision: this is a warning, not a failed load.
	if len(c.Entries) == 0 {
		t.Error("catalog emptied; entries must remain loaded and merely unschedulable")
	}
}

// TestLogFirstEncodeErr_GatesAfterOne is task 2.3: the gate must suppress the
// LOG only, never the counter. Ungated, an oversized entry at 30k devices on a
// 30 s mean interval is ~1,000 lines/second indefinitely.
func TestLogFirstEncodeErr_GatesAfterOne(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	e := &TrapExporter{deviceIP: net.ParseIP("10.42.0.1"), collectorStr: "10.0.0.1:162"}
	const fires = 25
	for i := 0; i < fires; i++ {
		e.logFirstEncodeErr("encode", "bigTrap", fmt.Errorf("encoded PDU (%d bytes) exceeds buffer", 1500+i))
	}

	if n := strings.Count(buf.String(), "further encode errors suppressed"); n != 1 {
		t.Errorf("%d failed fires produced %d log lines, want exactly 1", fires, n)
	}
	// The first error must survive verbatim — the gate drops repeats, not the
	// diagnostic.
	if !strings.Contains(buf.String(), "1500 bytes") {
		t.Errorf("the one emitted line lost the encoder's own message: %q", buf.String())
	}
}

// TestLogFirstEncodeErr_IgnoresNil guards the nil-error path the write-error
// gate also has: a nil must not consume the one available log line.
func TestLogFirstEncodeErr_IgnoresNil(t *testing.T) {
	var buf bytes.Buffer
	orig := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(orig) })

	e := &TrapExporter{deviceIP: net.ParseIP("10.42.0.1"), collectorStr: "10.0.0.1:162"}
	e.logFirstEncodeErr("encode", "x", nil)
	if buf.Len() != 0 {
		t.Errorf("a nil error logged: %q", buf.String())
	}
	e.logFirstEncodeErr("encode", "x", fmt.Errorf("real failure"))
	if !strings.Contains(buf.String(), "real failure") {
		t.Errorf("the nil consumed the sync.Once; the real error was swallowed: %q", buf.String())
	}
}

// TestApplySizeBudget_ReportsRealSize guards the diagnostic that design D2
// relies on instead of failing the load.
//
// In production `budget == maxTrapPDU`, so the encoder's own guard fires before
// the budget comparison and returns a nil PDU. The first version reported
// len(pdu), i.e. "0 B > 972 B budget" — no size, no gap, no remedy. Since this
// log line is the ONLY signal an operator gets, an uninformative one makes
// warn-and-disable worse than the reject it replaced.
func TestApplySizeBudget_ReportsRealSize(t *testing.T) {
	restoreLinkMTU(t)
	if err := SetLinkMTU(1000); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load ciena: %v", err)
	}

	// The production wiring: budget IS maxTrapPDU.
	disabled := c.ApplySizeBudget(maxTrapPDU, "ciena_waveserver5")
	if len(disabled) == 0 {
		t.Fatal("no entry disabled at -datagram-mtu 1000")
	}
	for _, msg := range disabled {
		// Anchored on the opening paren: a bare "0 B" substring also matches
		// inside a legitimate "1000 B".
		if strings.Contains(msg, "(0 B") {
			t.Errorf("disable message reports a zero size, which tells an operator nothing: %q", msg)
		}
		if !strings.Contains(msg, "over the") || !strings.Contains(msg, "needs -datagram-mtu >=") {
			t.Errorf("disable message lacks the gap or the remedy: %q", msg)
		}
	}
}

// TestApplySizeBudget_AccountsForDetail is the regression test for the worst
// bug the review found: rendering {{.Detail}} empty let an entry pass the load
// check and fail at every fire.
//
// All four shipped Ciena optical alarms interpolate Detail, and the alarm
// manager fills it with " (OSNR %.2f dB)". With Detail empty, the two *Raise
// entries passed at ~985 B and then encoded to ~1011 B at fire time — and
// because the *Clear entries carry longer literal text, they were disabled
// while their Raise counterparts were not. A split Raise/Clear pair can leave a
// collector holding an alarm that never clears.
func TestApplySizeBudget_AccountsForDetail(t *testing.T) {
	restoreLinkMTU(t)
	if err := SetLinkMTU(1000); err != nil {
		t.Fatal(err)
	}
	c, err := LoadCatalogFromFile("resources/ciena_waveserver5/traps.json")
	if err != nil {
		t.Fatalf("load ciena: %v", err)
	}
	c.ApplySizeBudget(maxTrapPDU, "ciena_waveserver5")

	// No entry may survive the load check and then fail at fire time with a
	// Detail the simulator itself produces.
	ctx := worstCaseTrapCtx()
	ctx.Detail = " (OSNR -12.34 dB)"
	for _, e := range c.Entries {
		if e.oversized {
			continue
		}
		vbs, rerr := e.Resolve(ctx, nil)
		if rerr != nil {
			t.Fatalf("resolve %s: %v", e.Name, rerr)
		}
		if _, eerr := encodeV2cNotificationFast(make([]byte, 0, 65535), ASN1_TRAP_V2C,
			dryRenderCommunity, math.MaxUint32, e.pre, e.SnmpTrapOID, e.SnmpTrapEnterprise,
			ctx.Uptime, vbs); eerr != nil {
			t.Errorf("%s passed the load-time check but fails at fire time with a real "+
				"Detail: %v — the dry render must account for Detail", e.Name, eerr)
		}
	}

	// A Raise and its Clear must share a fate. Half a pair is worse than none.
	pairs := [][2]string{
		{"opticalPreFecSdRaise", "opticalPreFecSdClear"},
		{"opticalPreFecSfRaise", "opticalPreFecSfClear"},
	}
	for _, pr := range pairs {
		raise, ok1 := c.ByName[pr[0]]
		clear, ok2 := c.ByName[pr[1]]
		if !ok1 || !ok2 {
			t.Fatalf("missing %v in the ciena catalog", pr)
		}
		if raise.oversized != clear.oversized {
			t.Errorf("%s disabled=%v but %s disabled=%v — a split pair can leave a "+
				"collector holding an alarm that never clears",
				pr[0], raise.oversized, pr[1], clear.oversized)
		}
	}
}

// TestDryRenderUsesWorstCaseRequestID pins the request-ID half of the sizing.
// The fire path uses a monotonically growing counter and appendInteger spends 5
// content bytes past 0x7FFFFFFF against 1 for a small value, so rendering with
// reqID 1 understated every entry by 4 bytes.
func TestDryRenderUsesWorstCaseRequestID(t *testing.T) {
	vbs := []Varbind{{OID: "1.3.6.1.2.1.1.5.0", Type: TrapVTOctetString, Value: "x"}}
	small, err := encodeV2cNotificationFast(make([]byte, 0, 4096), ASN1_TRAP_V2C, "public", 1,
		nil, "1.3.6.1.6.3.1.1.5.3", "", 1, vbs)
	if err != nil {
		t.Fatal(err)
	}
	large, err := encodeV2cNotificationFast(make([]byte, 0, 4096), ASN1_TRAP_V2C, "public", math.MaxUint32,
		nil, "1.3.6.1.6.3.1.1.5.3", "", 1, vbs)
	if err != nil {
		t.Fatal(err)
	}
	if len(large) <= len(small) {
		t.Fatalf("a max request ID (%d B) is not larger than reqID 1 (%d B); the dry render's "+
			"choice of MaxUint32 would be pointless", len(large), len(small))
	}
	t.Logf("request-ID width costs %d B; the dry render must use the max or it understates "+
		"every entry by that much", len(large)-len(small))
}
