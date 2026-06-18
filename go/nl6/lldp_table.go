/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// LLDP-MIB (IEEE 802.1AB) OID subtree. Note the second sub-identifier is
// 0 (iso.std(0).iso8802(8802)…), so the entire LLDP tree sorts
// lexicographically BEFORE every standard mib-2 OID (which start
// .1.3.6.1…). findNextOID's fast path must account for this — see
// lldpWalkClear.
const (
	lldpRoot = ".1.0.8802.1.1.2"

	// lldpLocalSystemData scalars (.1.3.x.0)
	oidLldpLocChassisIdSubtype = ".1.0.8802.1.1.2.1.3.1.0"
	oidLldpLocChassisId        = ".1.0.8802.1.1.2.1.3.2.0"
	oidLldpLocSysName          = ".1.0.8802.1.1.2.1.3.3.0"
	oidLldpLocSysDesc          = ".1.0.8802.1.1.2.1.3.4.0"

	// lldpLocPortTable entry: <prefix><col>.<portNum>. Col 1 (lldpLocPortNum)
	// is the not-accessible index; accessible cols start at 2.
	lldpLocPortPrefix = ".1.0.8802.1.1.2.1.3.7.1."

	// lldpRemTable entry: <prefix><col>.<timeMark>.<localPortNum>.<remIndex>.
	// timeMark and remIndex are fixed (0 and 1); cols 1-3 are the
	// not-accessible index, accessible cols start at 4.
	lldpRemPrefix = ".1.0.8802.1.1.2.1.4.1.1."

	// ifAlias (ifXTable column .18) — the transparent link label.
	ifAliasPrefix = ".1.3.6.1.2.1.31.1.1.1.18."

	// sysDescr scalar, reused for lldp*SysDesc.
	oidSysDescr = ".1.3.6.1.2.1.1.1.0"
)

// Local port table accessible columns.
const (
	colLldpLocPortIdSubtype = 2
	colLldpLocPortId        = 3
	colLldpLocPortDesc      = 4
)

// Remote table accessible columns (capability columns 11/12 are out of scope).
const (
	colLldpRemChassisIdSubtype = 4
	colLldpRemChassisId        = 5
	colLldpRemPortIdSubtype    = 6
	colLldpRemPortId           = 7
	colLldpRemPortDesc         = 8
	colLldpRemSysName          = 9
	colLldpRemSysDesc          = 10
)

// LLDP chassis/port id subtype enum values (IEEE 802.1AB).
const (
	lldpChassisIdSubtypeMAC = "4" // macAddress
	lldpPortIdSubtypeIfName = "5" // interfaceName
)

// isLLDPOID reports whether oid is within the served LLDP-MIB subtree.
func isLLDPOID(oid string) bool {
	return strings.HasPrefix(oid, lldpRoot+".")
}

// isIfAliasOID reports whether oid is an ifAlias instance (ifXTable .18.N).
func isIfAliasOID(oid string) bool {
	return strings.HasPrefix(oid, ifAliasPrefix)
}

// chassisMACBytes returns the 6 raw bytes of the device's synthesized
// chassis MAC (02:42 + IPv4), the value carried by lldp*ChassisId under
// chassisIdSubtype=macAddress. Derived from the SAME function on both the
// local and the remote side so the two half-links stitch by construction.
func chassisMACBytes(ip net.IP) string {
	v4 := ip.To4()
	if v4 == nil {
		return ""
	}
	return string([]byte{0x02, 0x42, v4[0], v4[1], v4[2], v4[3]})
}

// lldpManager returns the global manager when topology is available, else nil.
func lldpManager() *SimulatorManager {
	if manager == nil || manager.topology == nil {
		return nil
	}
	return manager
}

// deviceLinks returns this device's configured links (sorted by local
// ifIndex), or nil when topology is unavailable or the device has none.
// A device with no configured links advertises no LLDP at all — this both
// matches the link-driven nature of the feature and keeps the SNMP
// fast-path clear for the ~all devices that aren't in a topology.
func (s *SNMPServer) deviceLinks() []localLink {
	mgr := lldpManager()
	if mgr == nil {
		return nil
	}
	return mgr.topology.LinksFor(s.device.IP.String())
}

// operUp reports whether the interface is operationally up. A device with
// no interface-state engine (a type without HC counters) is treated as UP
// so configured topology with no liveness signal is still advertised. The
// metricsCycler / ifCounters / State chain is nil-guarded to keep the SNMP
// read path panic-free.
func operUp(dev *DeviceSimulator, ifIndex int) bool {
	if dev == nil || dev.metricsCycler == nil {
		return true
	}
	ic := dev.metricsCycler.ifCounters.Load()
	if ic == nil {
		return true
	}
	st := ic.State()
	if st == nil {
		return true
	}
	return st.OperStatus(ifIndex) == OperUp
}

// devIfDescr returns ifDescr.<ifIndex> for a device, falling back to the
// synthesized GigabitEthernet0/<N> name when the OID is absent.
func devIfDescr(dev *DeviceSimulator, ifIndex int) string {
	if d := lookupIfDescr(dev, ifIndex); d != "" {
		return d
	}
	return synthIfName(ifIndex)
}

// devSysDescr returns the device's sysDescr.0, or "" when absent.
func devSysDescr(dev *DeviceSimulator) string {
	if dev == nil || dev.resources == nil || dev.resources.oidIndex == nil {
		return ""
	}
	if v, ok := dev.resources.oidIndex.Load(oidSysDescr); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// localSysName returns this device's sysName (cached, lock-free).
func (s *SNMPServer) localSysName() string {
	if v := s.device.cachedSysName.Load(); v != nil {
		return v.(string)
	}
	return s.device.sysName
}

// lldpGet resolves a single LLDP-MIB or ifAlias OID to its dynamic value,
// or "" when this device does not own/serve it (caller falls through to
// the static oidIndex). It computes one OID directly — no full-table build
// — so it is cheap on the GET / walk-override hot path.
func (s *SNMPServer) lldpGet(oid string) string {
	mgr := lldpManager()
	if mgr == nil {
		return ""
	}

	// ifAlias (.18.N): dynamic label for a resolvable linked port.
	if isIfAliasOID(oid) {
		ifIndex, ok := atoiAfter(oid, ifAliasPrefix)
		if !ok {
			return ""
		}
		ll, found := findLink(s.deviceLinks(), ifIndex)
		if !found {
			return ""
		}
		peer := mgr.FindDeviceByIP(ll.PeerIP)
		if peer == nil || peer.sysName == "" {
			return "" // unresolvable peer / no sysName → no label (never "to__")
		}
		return "to_" + peer.sysName + "_" + devIfDescr(peer, ll.PeerIfIndex)
	}

	if !isLLDPOID(oid) {
		return ""
	}

	links := s.deviceLinks()
	if len(links) == 0 {
		return "" // device not in any topology → advertises no LLDP
	}

	// Local system scalars.
	switch oid {
	case oidLldpLocChassisIdSubtype:
		return lldpChassisIdSubtypeMAC
	case oidLldpLocChassisId:
		return chassisMACBytes(s.device.IP)
	case oidLldpLocSysName:
		return s.localSysName()
	case oidLldpLocSysDesc:
		return devSysDescr(s.device)
	}

	// Local port table: <prefix><col>.<portNum>.
	if strings.HasPrefix(oid, lldpLocPortPrefix) {
		col, port, ok := parseColIndex(oid, lldpLocPortPrefix)
		if !ok {
			return ""
		}
		if _, found := findLink(links, port); !found {
			return ""
		}
		switch col {
		case colLldpLocPortIdSubtype:
			return lldpPortIdSubtypeIfName
		case colLldpLocPortId, colLldpLocPortDesc:
			return devIfDescr(s.device, port)
		}
		return ""
	}

	// Remote table: <prefix><col>.0.<localPort>.1.
	if strings.HasPrefix(oid, lldpRemPrefix) {
		col, localPort, ok := parseRemIndex(oid)
		if !ok {
			return ""
		}
		ll, found := findLink(links, localPort)
		if !found {
			return ""
		}
		peer := mgr.FindDeviceByIP(ll.PeerIP)
		if peer == nil {
			return "" // peer not yet created → no remote row (lazy)
		}
		// Liveness: both ends must be operationally up.
		if !operUp(s.device, localPort) || !operUp(peer, ll.PeerIfIndex) {
			return ""
		}
		switch col {
		case colLldpRemChassisIdSubtype:
			return lldpChassisIdSubtypeMAC
		case colLldpRemChassisId:
			return chassisMACBytes(peer.IP)
		case colLldpRemPortIdSubtype:
			return lldpPortIdSubtypeIfName
		case colLldpRemPortId, colLldpRemPortDesc:
			return devIfDescr(peer, ll.PeerIfIndex)
		case colLldpRemSysName:
			return peer.sysName
		case colLldpRemSysDesc:
			return devSysDescr(peer)
		}
		return ""
	}

	return ""
}

// lldpServedOIDs builds the sorted list of every LLDP / ifAlias OID this
// device currently serves, paired with its value. Used by NextDynamicOID
// for walk enumeration. Returns nil when the device serves no LLDP.
//
// Remote-table rows are included only when the link is live (both ends up)
// and the peer is resolvable; ifAlias rows are included for every
// resolvable linked port regardless of oper-status (configured intent).
// invalidateLLDPServedCache bumps the topology generation so every device's
// cached LLDP served-OID set rebuilds on next access. Called on the two
// mutation sources outside the link graph itself: oper-status transitions
// (which add/remove live lldpRemTable rows) and device creation (which
// resolves a previously-absent peer). Guarded — a no-op when no topology
// exists, so it is safe to call from low-level paths (e.g. InterfaceState)
// that have no manager reference.
func invalidateLLDPServedCache() {
	if manager != nil && manager.topology != nil {
		manager.topology.bumpGen()
	}
}

// lldpServedOIDs returns this device's sorted LLDP served-OID set, memoised
// per topology generation. The set only changes on a topology mutation, an
// oper-status transition, or device creation (all of which bump the
// generation), so a steady-state Enlinkd walk reuses one snapshot across every
// GETBULK request instead of rebuilding and re-sorting it each time — the
// remaining hot spot after compareOIDs was made allocation-free.
//
// Note: the generation is global, so any oper-status flap anywhere invalidates
// every device's snapshot. This is correct (a peer's oper change alters this
// device's live remote rows) and never worse than the previous
// rebuild-every-request behaviour; under heavy flapping it degrades toward it,
// and under a steady fabric (the common Enlinkd case) it is a near-100 % hit.
func (s *SNMPServer) lldpServedOIDs() []kvOID {
	mgr := lldpManager()
	if mgr == nil {
		return nil
	}
	gen := mgr.topology.Gen()
	if snap := s.lldpServedCache.Load(); snap != nil && snap.gen == gen {
		return snap.served
	}
	served := s.buildLLDPServedOIDs(mgr)
	s.lldpServedCache.Store(&lldpServedSnapshot{gen: gen, served: served})
	return served
}

// buildLLDPServedOIDs constructs the device's full LLDP/ifAlias served-OID set
// from current topology and oper-status. Always returns a freshly-allocated,
// compareOIDs-ascending slice (or nil when the device serves no LLDP) so the
// result is safe to cache and share read-only across goroutines.
func (s *SNMPServer) buildLLDPServedOIDs(mgr *SimulatorManager) []kvOID {
	links := s.deviceLinks()
	if len(links) == 0 {
		return nil
	}

	var out []kvOID
	add := func(oid, val string) {
		if val != "" {
			out = append(out, kvOID{oid: oid, val: val})
		}
	}

	// Local system scalars.
	add(oidLldpLocChassisIdSubtype, lldpChassisIdSubtypeMAC)
	add(oidLldpLocChassisId, chassisMACBytes(s.device.IP))
	add(oidLldpLocSysName, s.localSysName())
	add(oidLldpLocSysDesc, devSysDescr(s.device))

	for _, ll := range links {
		port := ll.LocalIfIndex
		desc := devIfDescr(s.device, port)
		// Local port table.
		add(lldpLocPortPrefix+strconv.Itoa(colLldpLocPortIdSubtype)+"."+strconv.Itoa(port), lldpPortIdSubtypeIfName)
		add(lldpLocPortPrefix+strconv.Itoa(colLldpLocPortId)+"."+strconv.Itoa(port), desc)
		add(lldpLocPortPrefix+strconv.Itoa(colLldpLocPortDesc)+"."+strconv.Itoa(port), desc)

		peer := mgr.FindDeviceByIP(ll.PeerIP)
		if peer == nil {
			continue // peer not created → no ifAlias, no remote row
		}
		peerDesc := devIfDescr(peer, ll.PeerIfIndex)

		// ifAlias label (intent — present regardless of liveness). Skipped
		// when the peer has no sysName so we never emit a malformed "to__".
		if peer.sysName != "" {
			add(ifAliasPrefix+strconv.Itoa(port), "to_"+peer.sysName+"_"+peerDesc)
		}

		// Remote table — live links only.
		if !operUp(s.device, port) || !operUp(peer, ll.PeerIfIndex) {
			continue
		}
		idx := "0." + strconv.Itoa(port) + ".1"
		add(lldpRemPrefix+strconv.Itoa(colLldpRemChassisIdSubtype)+"."+idx, lldpChassisIdSubtypeMAC)
		add(lldpRemPrefix+strconv.Itoa(colLldpRemChassisId)+"."+idx, chassisMACBytes(peer.IP))
		add(lldpRemPrefix+strconv.Itoa(colLldpRemPortIdSubtype)+"."+idx, lldpPortIdSubtypeIfName)
		add(lldpRemPrefix+strconv.Itoa(colLldpRemPortId)+"."+idx, peerDesc)
		add(lldpRemPrefix+strconv.Itoa(colLldpRemPortDesc)+"."+idx, peerDesc)
		add(lldpRemPrefix+strconv.Itoa(colLldpRemSysName)+"."+idx, peer.sysName)
		add(lldpRemPrefix+strconv.Itoa(colLldpRemSysDesc)+"."+idx, devSysDescr(peer))
	}

	sort.Slice(out, func(i, j int) bool { return compareOIDs(out[i].oid, out[j].oid) < 0 })
	return out
}

// lldpNextFromServed returns the smallest entry in a sorted served-OID set
// strictly greater than currentOID. served must be ascending by compareOIDs
// (as produced by lldpServedOIDs). Returns ("","") past the end. Callers build
// the served set once (per GET lookup, or once per GETBULK request) and pass
// it here, so the device's LLDP/ifAlias view is not recomputed per walk step.
func lldpNextFromServed(served []kvOID, currentOID string) (string, string) {
	// served is ascending by compareOIDs (built by buildLLDPServedOIDs), so
	// binary-search for the first entry strictly greater than currentOID
	// instead of scanning — the walk calls this once per GETBULK repetition.
	lo, hi := 0, len(served)
	for lo < hi {
		mid := (lo + hi) / 2
		if compareOIDs(served[mid].oid, currentOID) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < len(served) {
		return served[lo].oid, served[lo].val
	}
	return "", ""
}

// overrideLLDP rewrites the value for any LLDP / ifAlias OID this device
// serves, mirroring overrideIfHC for the cycler. Walk candidate values for
// ifAlias originate from the static oidIndex (39 resource files ship a
// static .18.N); this ensures the dynamic link label wins on GETNEXT /
// GETBULK, not only on GET.
func (s *SNMPServer) overrideLLDP(oid, staticResp string) string {
	if !isLLDPOID(oid) && !isIfAliasOID(oid) {
		return staticResp
	}
	if v := s.lldpGet(oid); v != "" {
		return v
	}
	return staticResp
}

// kvOID is an (oid, value) pair used by walk enumeration.
type kvOID struct {
	oid string
	val string
}

// findLink returns the local link on the given local ifIndex, if any.
func findLink(links []localLink, ifIndex int) (localLink, bool) {
	for _, l := range links {
		if l.LocalIfIndex == ifIndex {
			return l, true
		}
	}
	return localLink{}, false
}

// atoiAfter parses the integer suffix of oid after prefix (no further dots
// expected, e.g. ifAlias .18.<ifIndex>).
func atoiAfter(oid, prefix string) (int, bool) {
	rest := oid[len(prefix):]
	if rest == "" || strings.IndexByte(rest, '.') >= 0 {
		return 0, false
	}
	n, err := strconv.Atoi(rest)
	if err != nil {
		return 0, false
	}
	return n, true
}

// parseColIndex parses "<prefix><col>.<index>" → (col, index).
func parseColIndex(oid, prefix string) (int, int, bool) {
	rest := oid[len(prefix):]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 || dot == len(rest)-1 {
		return 0, 0, false
	}
	col, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return 0, 0, false
	}
	idx, err := strconv.Atoi(rest[dot+1:])
	if err != nil {
		return 0, 0, false
	}
	return col, idx, true
}

// parseRemIndex parses a remote-table OID "<prefix><col>.0.<localPort>.1"
// → (col, localPort). Rejects rows with a non-zero timeMark or remIndex != 1
// since the simulator only ever serves that fixed index.
func parseRemIndex(oid string) (int, int, bool) {
	rest := oid[len(lldpRemPrefix):]
	parts := strings.Split(rest, ".")
	if len(parts) != 4 {
		return 0, 0, false
	}
	col, err1 := strconv.Atoi(parts[0])
	timeMark, err2 := strconv.Atoi(parts[1])
	localPort, err3 := strconv.Atoi(parts[2])
	remIndex, err4 := strconv.Atoi(parts[3])
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return 0, 0, false
	}
	if timeMark != 0 || remIndex != 1 {
		return 0, 0, false
	}
	return col, localPort, true
}
