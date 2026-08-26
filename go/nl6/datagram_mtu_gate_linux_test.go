//go:build linux

/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

// The datagram-size gate for nl6#488.
//
// Every UDP-emitting subsystem must produce datagrams whose FRAME fits the
// egress path. Three of them got that wrong (nl6#485 flow, nl6#487 trap,
// nl6#489 getbulk) and the class kept recurring because nothing checked it
// automatically: the only evidence was a tcpdump run by hand, once, per change.
//
// This gate asks the KERNEL instead of watching the wire. With
// IP_MTU_DISCOVER=IP_PMTUDISC_DO the Don't-Fragment bit is set and the kernel
// REFUSES to fragment locally — an oversized datagram fails the send with
// EMSGSIZE rather than being silently split. getsockopt(IP_MTU) supplies the
// route's real MTU, so the assertion holds on an overlay or a tunnel too rather
// than assuming 1500.
//
// What it does NOT prove: this is a local send-time check, not an observation
// of what left the host. The manual capture procedure (recorded in nl6#492 and
// nl6#493) remains the ground truth; this is the per-PR regression gate. The
// cheap check must not be allowed to retire the expensive one.
//
// Linux-only: IP_MTU_DISCOVER and IP_MTU are Linux socket options, and nl6's
// network paths are Linux-only anyway.

// pmtuProbe is a UDP socket that refuses to fragment, plus the route MTU the
// kernel reports for it.
type pmtuProbe struct {
	conn *net.UDPConn
	addr *net.UDPAddr
	mtu  int
}

// newPMTUProbe connects to a discardable but routable destination and puts the
// socket in "never fragment" mode.
//
// TEST-NET-1 (RFC 5737) is reserved for documentation and is not expected to
// answer — which is fine, because nothing here needs a reply. What is needed is
// a route, so the kernel picks a real egress interface rather than loopback.
//
// Returns nil when the environment cannot answer the question, which the caller
// must treat as a SKIP rather than a pass (see the note on task 4.4): a green
// from an environment that could not have shown the failure is not a green.
func newPMTUProbe(t *testing.T) *pmtuProbe {
	t.Helper()

	c, err := net.Dial("udp4", "192.0.2.1:9999")
	if err != nil {
		t.Skipf("no IPv4 route to a test destination (%v); the gate cannot run here", err)
	}
	uc := c.(*net.UDPConn)
	t.Cleanup(func() { uc.Close() })

	raw, err := uc.SyscallConn()
	if err != nil {
		t.Skipf("SyscallConn: %v", err)
	}
	var mtu int
	var serr error
	if cerr := raw.Control(func(fd uintptr) {
		// IP_PMTUDISC_DO == 2: set DF, never fragment locally.
		if serr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, 2); serr != nil {
			return
		}
		mtu, serr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU)
	}); cerr != nil {
		t.Skipf("raw.Control: %v", cerr)
	}
	if serr != nil {
		t.Skipf("IP_MTU_DISCOVER/IP_MTU unavailable: %v", serr)
	}

	// An MTU this large means nothing nl6 emits could fragment, so the gate
	// would pass vacuously. Loopback (65536) lands here — which is exactly the
	// blindness that let nl6#485 ship through every in-process measurement.
	if mtu > 4096 {
		t.Skipf("route MTU is %d; nothing nl6 emits can fragment at that size, so a pass "+
			"here would carry no information (this is what loopback's 65536 does)", mtu)
	}

	return &pmtuProbe{conn: uc, addr: uc.RemoteAddr().(*net.UDPAddr), mtu: mtu}
}

// budget is the payload ceiling implied by the kernel-reported MTU.
func (p *pmtuProbe) budget() int { return p.mtu - ipv4HeaderBytes - udpHeaderBytes }

// wouldFragment reports whether a payload of n bytes would need fragmenting on
// this route, by attempting the send and inspecting the error.
func (p *pmtuProbe) wouldFragment(t *testing.T, payload []byte) bool {
	t.Helper()
	_, err := p.conn.Write(payload)
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EMSGSIZE) {
		return true
	}
	// Anything else (no route to host, network unreachable) is an environment
	// problem, not an answer about size.
	t.Skipf("send failed for a reason other than size (%v); the gate cannot run here", err)
	return false
}

// TestPMTUGate_DetectsAKnownBadSize is task 5: prove the gate can see the
// failure before trusting a pass from it. A payload one byte past the budget
// must be refused, and one at the budget must not be.
func TestPMTUGate_DetectsAKnownBadSize(t *testing.T) {
	p := newPMTUProbe(t)
	t.Logf("kernel-reported route MTU %d; payload budget %d", p.mtu, p.budget())

	if p.wouldFragment(t, make([]byte, p.budget())) {
		t.Errorf("a payload of exactly the budget (%d B, frame %d B) was refused; the gate's "+
			"boundary is wrong and it would fail correct builds", p.budget(), p.mtu)
	}
	if !p.wouldFragment(t, make([]byte, p.budget()+1)) {
		t.Fatalf("a payload one byte over the budget (%d B, frame %d B) was ACCEPTED; the gate "+
			"cannot detect oversized datagrams and every pass from it is meaningless",
			p.budget()+1, p.mtu+1)
	}
}

// TestPMTUGate_FlowDatagramsFitTheRoute takes the datagrams the real
// FlowExporter.Tick emits and replays each one through a never-fragment socket.
// This is the automated form of the manual capture that verified nl6#485 and
// nl6#490.
//
// Tick is driven against an ordinary loopback listener rather than the probe
// socket, because Tick SWALLOWS write errors: a failed WriteTo is logged once
// and still increments PacketsSent, so an EMSGSIZE would never surface through
// its return value. Collecting the bytes and sending them ourselves keeps the
// assertion on the datagrams Tick actually produces while making the failure
// observable.
func TestPMTUGate_FlowDatagramsFitTheRoute(t *testing.T) {
	restoreLinkMTU(t)
	p := newPMTUProbe(t)

	// Match the simulator's budget to the route, which is what an operator does
	// with -datagram-mtu on a lower-MTU path.
	if err := SetLinkMTU(p.mtu); err != nil {
		t.Fatalf("SetLinkMTU(%d): %v", p.mtu, err)
	}

	for _, tc := range []struct {
		protocol string
		encoder  FlowEncoder
	}{
		{"netflow9", NetFlow9Encoder{}},
		{"ipfix", IPFIXEncoder{}},
		{"netflow5", &NetFlow5Encoder{}},
		{"sflow", SFlowEncoder{}},
	} {
		t.Run(tc.protocol, func(t *testing.T) {
			ln, ch := testUDPListener(t)
			defer ln.Close()
			conn := testSender(t)
			defer conn.Close()

			fe := newTestFlowExporter(testDevice("10.1.2.7"), mtuTestProfile(),
				1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
			fe.protocol = tc.protocol
			if tc.protocol == "sflow" {
				fe.counterSources = []CounterSource{NewCPUCounterSource(nil)}
			}

			// Two ticks: the first carries a template (larger overhead), the
			// second is data-only. Both fill toward the same ceiling.
			var datagrams [][]byte
			for i := 0; i < 2; i++ {
				fillExpiredFlows(t, fe, 240)
				tickWithEncoder(fe, time.Now(), tc.encoder, conn,
					ln.LocalAddr().(*net.UDPAddr), testPool())
				datagrams = append(datagrams, drainPackets(ch)...)
			}
			if len(datagrams) == 0 {
				t.Fatal("Tick emitted nothing; the gate would pass vacuously")
			}

			largest := 0
			for i, d := range datagrams {
				if len(d) > largest {
					largest = len(d)
				}
				if p.wouldFragment(t, d) {
					t.Errorf("datagram %d of %d is %d B (frame %d B) and needs fragmenting on a "+
						"route with MTU %d — %s pagination is over budget",
						i, len(datagrams), len(d), len(d)+ipv4HeaderBytes+udpHeaderBytes,
						p.mtu, tc.protocol)
				}
			}
			t.Logf("%s: %d datagrams, largest %d B (frame %d B) against route MTU %d",
				tc.protocol, len(datagrams), largest,
				largest+ipv4HeaderBytes+udpHeaderBytes, p.mtu)
		})
	}
}

// TestPMTUGate_FlowRefusesWhenBudgetExceedsRoute is the negative control for
// the flow path, and it needs no code revert: raising -datagram-mtu above the
// route's real MTU reproduces exactly the pre-nl6#485 condition, where the
// budget was the full MTU rather than the MTU minus headers.
func TestPMTUGate_FlowRefusesWhenBudgetExceedsRoute(t *testing.T) {
	restoreLinkMTU(t)
	p := newPMTUProbe(t)

	// Budget = route MTU + headers, i.e. datagrams sized to the frame limit
	// with no room for the headers. This is the bug.
	if err := SetLinkMTU(p.mtu + ipv4HeaderBytes + udpHeaderBytes); err != nil {
		t.Fatalf("SetLinkMTU: %v", err)
	}
	if maxFlowPayloadIPv4 <= p.budget() {
		t.Fatalf("budget %d did not exceed the route budget %d; the control is not testing anything",
			maxFlowPayloadIPv4, p.budget())
	}

	fe := newTestFlowExporter(testDevice("10.1.2.7"), mtuTestProfile(),
		1*time.Millisecond, 1*time.Millisecond, 10*time.Minute)
	fe.seqNo = 1 // suppress the template so every datagram is a full data one
	fe.lastTempl = time.Now()
	fillExpiredFlows(t, fe, 240)

	// Send the largest payload this budget produces directly, so the assertion
	// is on the size rather than on Tick's error swallowing.
	oversized := make([]byte, maxFlowPayloadIPv4)
	if !p.wouldFragment(t, oversized) {
		t.Fatalf("a %d B payload (frame %d B) was accepted on a route with MTU %d — the gate "+
			"cannot detect the very condition nl6#485 was about",
			len(oversized), len(oversized)+28, p.mtu)
	}
}

// TestPMTUGate_TrapNotificationsFitTheRoute covers the trap path (nl6#487),
// closing that change's task 6.4 and its untested 6.3.
func TestPMTUGate_TrapNotificationsFitTheRoute(t *testing.T) {
	restoreLinkMTU(t)
	p := newPMTUProbe(t)
	if err := SetLinkMTU(p.mtu); err != nil {
		t.Fatalf("SetLinkMTU(%d): %v", p.mtu, err)
	}

	ctx := worstCaseTrapCtx()
	ctx.Detail = worstCaseDetail
	for src, c := range shippedTrapCatalogs(t) {
		if d := c.ApplySizeBudget(maxTrapPDU, src); len(d) > 0 {
			t.Logf("%s: %d entries disabled at route MTU %d: %v", src, len(d), p.mtu, d)
		}
		for _, e := range c.Entries {
			if e.oversized {
				continue // disabled entries never reach the wire, by design
			}
			vbs, err := e.Resolve(ctx, nil)
			if err != nil {
				t.Fatalf("resolve %s: %v", e.Name, err)
			}
			// Both PDU tags: TRAP and INFORM differ only in the tag and encode
			// to the same length, which nl6#487 task 6.3 asserted but never ran.
			for _, tag := range []byte{ASN1_TRAP_V2C, ASN1_INFORM_REQUEST} {
				pdu, err := encodeV2cNotificationFast(make([]byte, 0, 65535), tag,
					dryRenderCommunity, 1, e.pre, e.SnmpTrapOID, e.SnmpTrapEnterprise, ctx.Uptime, vbs)
				if err != nil {
					t.Errorf("%s/%s survived the size check but does not encode: %v", src, e.Name, err)
					continue
				}
				if p.wouldFragment(t, pdu) {
					t.Errorf("%s/%s (tag %#x) encodes to %d B, which needs fragmenting on a "+
						"route with MTU %d — a schedulable entry must always fit",
						src, e.Name, tag, len(pdu), p.mtu)
				}
			}
		}
	}
}

// TestPMTUGate_ReportsTheRouteMTU makes the environment visible in the test
// log. On an overlay a failure here is the -datagram-mtu decision (nl6#488),
// not a regression, and an operator reading CI output should not have to
// investigate twice to tell those apart.
func TestPMTUGate_ReportsTheRouteMTU(t *testing.T) {
	p := newPMTUProbe(t)
	t.Logf("route MTU %d, payload budget %d, simulator budget %d (-datagram-mtu %d)",
		p.mtu, p.budget(), maxFlowPayloadIPv4, linkMTU)
	if p.mtu < defaultLinkMTU {
		t.Logf("NOTE: this route is below the %d default. nl6 needs -datagram-mtu %d here, "+
			"or full-size datagrams fragment (nl6#488).", defaultLinkMTU, p.mtu)
	}
}
