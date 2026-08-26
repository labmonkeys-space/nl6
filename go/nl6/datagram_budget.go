/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "fmt"

// Egress-path constants shared by every subsystem that emits a UDP datagram.
//
// These describe the PATH, not any one subsystem, which is why they carry no
// subsystem prefix and do not live in flow_exporter.go where they started
// (nl6#488). Three subsystems derived this same arithmetic independently and
// two derived it wrong, so the inputs are defined once here and each subsystem
// computes its own ceiling from them.
//
// The distinction that matters: flow export is UDP, so the on-wire FRAME is
// the encoded payload plus the transport and network headers. What a subsystem
// fills is the payload, but what constrains it is the frame — the payload's
// ceiling is the MTU MINUS the IP and UDP headers, not the MTU. Budgeting the
// full MTU for the payload put a NetFlow v9 datagram at 1524 bytes on the wire
// and the kernel fragmented it (nl6#485); IPFIX landed at 1508.
//
// Fragmentation is invisible on LOOPBACK, whose MTU is 65536, which is where
// every Go test in this package sends. That is why the bug survived every
// in-process measurement.
//
// It is NOT invisible on veth. veth takes the kernel default of 1500 and
// fragments a 1524-byte frame like any other link — verified in an Ubuntu VM
// against nl6's own netns→veth path: emulating the pre-fix budget produced 85
// of 212 datagrams fragmented (40%), first fragments at exactly 1500 bytes,
// reproducing the original capture's signature. Current main over the same
// path fragments zero of 129. An earlier revision of this comment claimed veth
// could not fragment; that was wrong, and it made the verification look like it
// needed hardware it never needed.
//
// On a real network one lost fragment discards the entire datagram — 31 records
// under NetFlow v9, not one — and middleboxes and strict collectors drop
// fragments outright.
const (
	// defaultLinkMTU is the assumed path MTU when `-datagram-mtu` is not given.
	// Standard Ethernet; also what nl6's own TUN and veth devices take, since
	// nl6 sets no MTU on them.
	defaultLinkMTU = 1500

	// minLinkMTU is the floor `-datagram-mtu` accepts: 576, the IPv4 minimum
	// reassembly buffer every host must support (RFC 791 §3.2). It is a
	// sanity floor on the FLAG, not a guarantee that every subsystem fits
	// inside it.
	//
	// Flow does fit — all four encoders paginate correctly at 576, emitting
	// 444-536 B payloads against a 548 B budget. Syslog does NOT: its
	// maxSyslogMessageBytes is a fixed 1400 that is deliberately never
	// derived from linkMTU (see the note at the foot of this file), so a
	// 1400-byte syslog message still fragments on a path the operator
	// declared to be 576. Trap and GETBULK likewise keep their own bounds
	// until nl6#487 and nl6#489 land.
	//
	// Rejecting values below 576 therefore prevents an obviously nonsensical
	// configuration; it does not certify the fleet against the value given.
	minLinkMTU = 576

	// Fixed header sizes subtracted from the MTU to reach a payload budget.
	// IPv4 options and IPv6 extension headers are not accounted for; nothing
	// in nl6's egress path adds either.
	udpHeaderBytes  = 8
	ipv4HeaderBytes = 20
	ipv6HeaderBytes = 40
)

// linkMTU is the assumed path MTU, settable once at startup via
// `-datagram-mtu` (see SetLinkMTU).
//
// It is an assumption about the EGRESS path to the collector, which nl6 does
// not control — NOT a property of nl6's own interfaces. A device socket sits
// in the nl6sim netns, routes over a veth pair, and leaves through whatever
// the host's routing table picks. nl6 creates the first two (kernel default
// 1500) and has no say over the third, which is the binding constraint.
//
// This is a variable rather than a constant because 1500 is wrong on common
// deployments and being wrong here silently re-breaks nl6#485. Measured frame
// sizes on a stock Docker overlay (MTU 1450): NetFlow v9 1480, IPFIX 1484,
// NetFlow v5 1492 and an OpenNMS-default GETBULK at 1464 all fragment, with
// only sFlow and traps fitting. See nl6#488 and design D2.
//
// Deliberately NOT auto-discovered. Reading the route's interface MTU would
// work for flow, trap and syslog, which each have a configured collector known
// at attach time — but not for SNMP, which answers whoever polls it and knows
// the destination only per request. Since the point of this file is ONE
// definition covering every subsystem, discovery cannot be the base mechanism.
// It could later supply this variable's default for the collector-based
// subsystems. There is also no PMTU discovery: the route lookup would see only
// the first hop, so a tunnel further along the path stays invisible either way.
//
// Not synchronised. In production it is written once during startup, before
// any device, exporter or listener exists, and is read-only thereafter.
//
// Tests that call SetLinkMTU are the one exception and must not run alongside
// a live SimulatorManager: initFlowSubsystem starts a flow ticker at manager
// CONSTRUCTION which only Shutdown stops, and that ticker reads
// maxFlowPayloadIPv4 / flowBufSize on every tick. Use restoreLinkMTU (see
// datagram_budget_test.go) and keep the manager out of the same test.
var linkMTU = defaultLinkMTU

// SetLinkMTU sets the assumed egress path MTU and recomputes every budget
// derived from it. Call once, from startup, after flag parsing and before any
// subsystem is constructed.
//
// Budgets are recomputed here rather than being const expressions so that a
// single flag reaches every subsystem. A subsystem that captured its ceiling
// at package-init time would keep the 1500-derived value and silently
// fragment on exactly the deployments this flag exists to fix — which is the
// failure mode the whole nl6#485 / #487 / #489 family is made of.
//
// Returns an error for an out-of-range value so startup can fail loudly.
func SetLinkMTU(mtu int) error {
	if mtu < minLinkMTU || mtu > 65535 {
		return fmt.Errorf("datagram MTU %d out of range (%d..65535)", mtu, minLinkMTU)
	}
	linkMTU = mtu
	recomputeDatagramBudgets()
	return nil
}

// recomputeDatagramBudgets refreshes every ceiling derived from linkMTU.
//
// Any subsystem that derives a budget MUST be recomputed here. Adding one and
// forgetting this function is the bug this file exists to prevent: the budget
// would silently keep its 1500-derived value.
func recomputeDatagramBudgets() {
	maxFlowPayloadIPv4 = linkMTU - ipv4HeaderBytes - udpHeaderBytes
	maxFlowPayloadIPv6 = linkMTU - ipv6HeaderBytes - udpHeaderBytes
	flowBufSize = linkMTU
	// Trap notifications (nl6#487). udp4-only, so no address-family branch.
	maxTrapPDU = linkMTU - ipv4HeaderBytes - udpHeaderBytes
	// nl6#489 (the GETBULK response ceiling) joins here when it lands. Also
	// udp4-only, so it derives the same expression.
}

// Budgets are PER-SUBSYSTEM and deliberately not unified into one constant.
// The inputs above are shared because they are facts about the path; the
// ceilings below are separate because they are different USES of those facts:
//
//	subsystem  ceiling                          semantics           families
//	---------  -------------------------------  ------------------  --------
//	flow       maxFlowPayloadIPv4 / ...IPv6      packing target      v4 + v6
//	trap       maxTrapPDU                        rejection threshold udp4 only
//	getbulk    (response truncation ceiling)     truncation ceiling  udp4 only
//	syslog     maxSyslogMessageBytes = 1400      dry-render ceiling  all transports
//
// Flow packs records to fill a datagram, so every unused byte is throughput
// and the budget must be exact — and it must branch on address family, since
// an IPv6 collector is reachable through the shared dual-stack socket. Trap
// and getbulk resolve their collectors as udp4 only, so neither needs that
// branch. Forcing one budget constant on all of them would push flow's
// address-family branching onto two subsystems that cannot use it, and erase
// the semantic differences that make each one correct.
//
// Syslog is deliberately NOT derived from linkMTU. maxSyslogMessageBytes is
// 1400 rather than 1472, carrying extra headroom explicitly justified as room
// for small collector-side framing, and it applies that bound across UDP, TCP
// and TLS on purpose (the check is a once-per-entry dry render at catalog
// load; making it transport-aware would defer it to a per-device runtime
// failure). Rederiving it here would either change its value or bolt a second
// rationale onto a constant that already has a good one.
