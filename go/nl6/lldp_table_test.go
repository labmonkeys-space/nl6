/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
)

// lldpFixture builds a manager with a set of devices (each with a state
// engine and ifDescr/sysDescr/sysName seeded) and a topology graph, and
// swaps the global manager. Devices are named dev<N> at 10.42.0.<N>.
type lldpFixture struct {
	mgr  *SimulatorManager
	devs map[string]*DeviceSimulator // keyed by IP string
}

// addDevice registers a device at 10.42.0.<host> with interfaces 1..maxIf.
func (f *lldpFixture) addDevice(t *testing.T, host, maxIf int, name string) *DeviceSimulator {
	t.Helper()
	return f.addDeviceAt(t, net.IPv4(10, 42, 0, byte(host)).String(), maxIf, name, int64(host))
}

// addDeviceAt registers a device at an arbitrary IP with interfaces 1..maxIf
// (all UP), sysName = name, sysDescr = "<name> desc".
func (f *lldpFixture) addDeviceAt(t *testing.T, ipStr string, maxIf int, name string, seed int64) *DeviceSimulator {
	t.Helper()
	speeds := make([]uint64, maxIf)
	for i := range speeds {
		speeds[i] = 1_000_000_000
	}
	res := buildTestResources(t, speeds)
	res.oidIndex.Store(".1.3.6.1.2.1.1.1.0", name+" desc")
	for i := 1; i <= maxIf; i++ {
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.2.%d", i), fmt.Sprintf("GigabitEthernet0/%d", i))
		// Boot state UP.
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.7.%d", i), "1")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.2.2.1.8.%d", i), "1")
	}
	indexResources(res)

	d := &DeviceSimulator{
		ID:            "dev-" + ipStr,
		IP:            net.ParseIP(ipStr),
		sysName:       name,
		resources:     res,
		metricsCycler: NewMetricsCycler(seed, GetDeviceProfile("")),
	}
	d.cachedSysName.Store(name)
	d.metricsCycler.InitIfCountersWithScenario(res, seed, IfErrorClean)
	d.snmpServer = &SNMPServer{device: d}

	f.mgr.mu.Lock()
	f.mgr.devices[d.ID] = d
	f.mgr.deviceIPs[d.IP.String()] = struct{}{}
	f.mgr.mu.Unlock()
	f.devs[d.IP.String()] = d
	return d
}

func newLLDPFixture(t *testing.T) *lldpFixture {
	t.Helper()
	mgr := &SimulatorManager{
		devices:          map[string]*DeviceSimulator{},
		deviceIPs:        map[string]struct{}{},
		deviceTypesByIP:  map[string]string{},
		resourcesCache:   map[string]*DeviceResources{},
		tunInterfacePool: map[string]*TunInterface{},
		topology:         NewTopology(),
	}
	t.Cleanup(swapGlobalManager(mgr))
	return &lldpFixture{mgr: mgr, devs: map[string]*DeviceSimulator{}}
}

// indexResources builds sortedOIDs + oidNextMap from oidIndex so findNextOID
// exercises its real fast path (the production buildResourceIndexes path).
func indexResources(res *DeviceResources) {
	var oids []string
	res.oidIndex.Range(func(k, _ any) bool { oids = append(oids, k.(string)); return true })
	sort.Slice(oids, func(i, j int) bool { return compareOIDs(oids[i], oids[j]) < 0 })
	res.sortedOIDs = oids
	res.oidNextMap = &sync.Map{}
	for i := 0; i+1 < len(oids); i++ {
		res.oidNextMap.Store(oids[i], oids[i+1])
	}
}

func setOper(d *DeviceSimulator, ifIndex int, up bool) {
	st := d.metricsCycler.ifCounters.Load().State()
	if up {
		st.SetOperStatus(ifIndex, OperUp)
	} else {
		st.SetOperStatus(ifIndex, OperDown)
	}
}

// lineTopology: A(.1) if1 <-> B(.2) if2 ; B(.2) if3 <-> C(.3) if1.
func lineTopology(t *testing.T) (*lldpFixture, *DeviceSimulator, *DeviceSimulator, *DeviceSimulator) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	c := f.addDevice(t, 3, 4, "charlie")
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(b.IP.String(), 2)))
	must(t, f.mgr.topology.AddLink(ep(b.IP.String(), 3), ep(c.IP.String(), 1)))
	return f, a, b, c
}

func TestLLDP_LocalScalars(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	if got := a.snmpServer.findResponse(oidLldpLocChassisIdSubtype); got != "4" {
		t.Errorf("chassisIdSubtype = %q, want 4", got)
	}
	wantMAC := chassisMACBytes(a.IP)
	if got := a.snmpServer.findResponse(oidLldpLocChassisId); got != wantMAC {
		t.Errorf("chassisId = %x, want %x", got, wantMAC)
	}
	if got := a.snmpServer.findResponse(oidLldpLocSysName); got != "alpha" {
		t.Errorf("sysName = %q, want alpha", got)
	}
	if got := a.snmpServer.findResponse(oidLldpLocSysDesc); got != "alpha desc" {
		t.Errorf("sysDesc = %q, want 'alpha desc'", got)
	}
}

func TestLLDP_LocalPortRow(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	subtypeOID := fmt.Sprintf("%s%d.1", lldpLocPortPrefix, colLldpLocPortIdSubtype)
	if got := a.snmpServer.findResponse(subtypeOID); got != "5" {
		t.Errorf("locPortIdSubtype = %q, want 5", got)
	}
	idOID := fmt.Sprintf("%s%d.1", lldpLocPortPrefix, colLldpLocPortId)
	if got := a.snmpServer.findResponse(idOID); got != "GigabitEthernet0/1" {
		t.Errorf("locPortId = %q, want GigabitEthernet0/1", got)
	}
	// Unlinked port (if4) has no local port row.
	noRow := fmt.Sprintf("%s%d.4", lldpLocPortPrefix, colLldpLocPortId)
	if got := a.snmpServer.findResponse(noRow); got != "OID not supported" {
		t.Errorf("unlinked locPortId = %q, want OID not supported", got)
	}
}

func remOID(col, localPort int) string {
	return fmt.Sprintf("%s%d.0.%d.1", lldpRemPrefix, col, localPort)
}

func TestLLDP_RemoteMirrorsPeerAndStitches(t *testing.T) {
	_, a, b, _ := lineTopology(t)

	// A's remote view of the A-if1<->B-if2 link.
	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "bravo" {
		t.Errorf("A remSysName = %q, want bravo", got)
	}
	if got := a.snmpServer.findResponse(remOID(colLldpRemPortId, 1)); got != "GigabitEthernet0/2" {
		t.Errorf("A remPortId = %q, want GigabitEthernet0/2", got)
	}
	aRemChassis := a.snmpServer.findResponse(remOID(colLldpRemChassisId, 1))

	// Stitching: A's remote chassis/port-id must equal B's local chassis/port-id.
	bLocChassis := b.snmpServer.findResponse(oidLldpLocChassisId)
	if aRemChassis != bLocChassis {
		t.Errorf("stitch chassis mismatch: A.rem=%x B.loc=%x", aRemChassis, bLocChassis)
	}
	bLocPortId := b.snmpServer.findResponse(fmt.Sprintf("%s%d.2", lldpLocPortPrefix, colLldpLocPortId))
	aRemPortId := a.snmpServer.findResponse(remOID(colLldpRemPortId, 1))
	if aRemPortId != bLocPortId {
		t.Errorf("stitch portId mismatch: A.rem=%q B.loc=%q", aRemPortId, bLocPortId)
	}
}

func TestLLDP_LivenessSuppression(t *testing.T) {
	_, a, b, _ := lineTopology(t)
	row := remOID(colLldpRemSysName, 1)

	if got := a.snmpServer.findResponse(row); got != "bravo" {
		t.Fatalf("precondition: row present, got %q", got)
	}
	// Local port down → row gone.
	setOper(a, 1, false)
	if got := a.snmpServer.findResponse(row); got != "OID not supported" {
		t.Errorf("local down: row = %q, want absent", got)
	}
	setOper(a, 1, true)
	if got := a.snmpServer.findResponse(row); got != "bravo" {
		t.Errorf("local up again: row = %q, want bravo", got)
	}
	// Peer port down → row gone on A too.
	setOper(b, 2, false)
	if got := a.snmpServer.findResponse(row); got != "OID not supported" {
		t.Errorf("peer down: row = %q, want absent", got)
	}
}

func TestLLDP_NoEnginePeerTreatedUp(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	// Peer with NO metricsCycler (no state engine).
	res := buildTestResources(t, []uint64{1_000_000_000, 1_000_000_000})
	res.oidIndex.Store(".1.3.6.1.2.1.1.1.0", "noeng desc")
	res.oidIndex.Store(".1.3.6.1.2.1.2.2.1.2.2", "GigabitEthernet0/2")
	indexResources(res)
	peer := &DeviceSimulator{ID: "dev9", IP: net.IPv4(10, 42, 0, 9), sysName: "noeng", resources: res}
	peer.snmpServer = &SNMPServer{device: peer}
	f.mgr.mu.Lock()
	f.mgr.devices[peer.ID] = peer
	f.mgr.deviceIPs[peer.IP.String()] = struct{}{}
	f.mgr.mu.Unlock()
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(peer.IP.String(), 2)))

	// Must not panic and must emit the row (no-engine peer treated as up).
	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "noeng" {
		t.Errorf("no-engine peer: remSysName = %q, want noeng", got)
	}
}

func TestLLDP_IfAliasGetPersistsWhenDown(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	aliasOID := ifAliasPrefix + "1"
	want := "to_bravo_GigabitEthernet0/2"
	if got := a.snmpServer.findResponse(aliasOID); got != want {
		t.Errorf("ifAlias = %q, want %q", got, want)
	}
	// Down does NOT suppress the alias (configured intent).
	setOper(a, 1, false)
	if got := a.snmpServer.findResponse(aliasOID); got != want {
		t.Errorf("ifAlias while down = %q, want %q", got, want)
	}
	// But the remote row IS gone at the same instant.
	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "OID not supported" {
		t.Errorf("remote row while down = %q, want absent", got)
	}
}

func TestLLDP_IfAliasUnlinkedFallsThrough(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	// if4 has no link; no static .18.4 either → not supported.
	if got := a.snmpServer.findResponse(ifAliasPrefix + "4"); got != "OID not supported" {
		t.Errorf("unlinked ifAlias = %q, want OID not supported", got)
	}
}

func TestLLDP_IfAliasUnresolvablePeerNoGarbage(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	// Link to a peer that does not exist → ifAlias must NOT render "to__".
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep("10.42.0.250", 7)))
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != "OID not supported" {
		t.Errorf("unresolvable-peer ifAlias = %q, want OID not supported (never to__)", got)
	}
}

func TestLLDP_IfAliasDynamicWinsOverStaticOnGetAndWalk(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	// Seed a static ifAlias.1 that the dynamic label must shadow.
	a.resources.oidIndex.Store(ifAliasPrefix+"1", "STATIC-ALIAS")
	indexResources(a.resources)

	want := "to_bravo_GigabitEthernet0/2"
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != want {
		t.Errorf("GET ifAlias = %q, want dynamic %q", got, want)
	}
	// WALK landing on .18.1: GETNEXT from just below it.
	prev := ifAliasPrefix + "0"
	gotOID, gotVal := a.snmpServer.findNextOID(prev)
	if gotOID != ifAliasPrefix+"1" {
		t.Fatalf("walk next from %s = %s, want %s1", prev, gotOID, ifAliasPrefix)
	}
	if gotVal != want {
		t.Errorf("WALK ifAlias value = %q, want dynamic %q", gotVal, want)
	}
}

// TestLLDP_WalkDoesNotSkipDynamicIfAlias reproduces the fast-path skip the
// review flagged: a static next-OID exists past .18, the linked port's .18
// is dynamic-only, and the fast path must NOT jump over it.
func TestLLDP_WalkDoesNotSkipDynamicIfAlias(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 1, "alpha")
	b := f.addDevice(t, 2, 2, "bravo")
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(b.IP.String(), 2)))

	// Add a static ifXTable OID PAST column 18 so oidNextMap has an entry
	// that would otherwise be returned, skipping the dynamic .18.1.
	a.resources.oidIndex.Store(".1.3.6.1.2.1.31.1.1.1.19.1", "0")
	indexResources(a.resources)

	// GETNEXT from ifHighSpeed (.15.1): without the lldpClear fix the fast
	// path returns .19.1 and skips the dynamic ifAlias .18.1.
	gotOID, gotVal := a.snmpServer.findNextOID(".1.3.6.1.2.1.31.1.1.1.15.1")
	if gotOID != ifAliasPrefix+"1" {
		t.Fatalf("walk skipped dynamic ifAlias: next = %s, want %s1", gotOID, ifAliasPrefix)
	}
	if gotVal != "to_bravo_GigabitEthernet0/2" {
		t.Errorf("ifAlias walk value = %q", gotVal)
	}
}

func TestLLDP_WalkEnumeratesSubtreeInOrder(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	// Walk the whole LLDP subtree on A and collect OIDs.
	cur := lldpRoot
	var oids []string
	for i := 0; i < 200; i++ {
		next, _ := a.snmpServer.findNextOID(cur)
		if next == "" || !isLLDPOID(next) {
			break
		}
		oids = append(oids, next)
		cur = next
	}
	if len(oids) == 0 {
		t.Fatal("walk reached no LLDP OIDs")
	}
	// Strictly ascending.
	for i := 1; i < len(oids); i++ {
		if compareOIDs(oids[i-1], oids[i]) >= 0 {
			t.Fatalf("walk not ascending at %d: %s then %s", i, oids[i-1], oids[i])
		}
	}
	// Local scalars present; a remote row present (A has one live link).
	joined := strings.Join(oids, " ")
	if !strings.Contains(joined, oidLldpLocSysName) {
		t.Error("walk missing lldpLocSysName")
	}
	if !strings.Contains(joined, remOID(colLldpRemSysName, 1)) {
		t.Error("walk missing remote sysName row for port 1")
	}
}

// TestLLDP_ChassisIdEncoding pins the wire encoding Enlinkd depends on:
// lldp*ChassisId is a 6-byte OCTET STRING (subtype macAddress), and the
// subtype itself is an INTEGER. Guards against a future oidTypeTable change.
func TestLLDP_ChassisIdEncoding(t *testing.T) {
	enc := encodeTypedValue(oidLldpLocChassisId, chassisMACBytes(net.IPv4(10, 42, 0, 1)))
	if len(enc) != 8 || enc[0] != ASN1_OCTET_STRING || enc[1] != 6 {
		t.Fatalf("chassisId encoding = % x, want octet-string len 6", enc)
	}
	if want := []byte{0x02, 0x42, 0x0a, 0x2a, 0x00, 0x01}; !bytes.Equal(enc[2:], want) {
		t.Errorf("chassisId bytes = % x, want % x", enc[2:], want)
	}
	if sub := encodeTypedValue(oidLldpLocChassisIdSubtype, lldpChassisIdSubtypeMAC); sub[0] != ASN1_INTEGER {
		t.Errorf("subtype tag = %#x, want INTEGER %#x", sub[0], ASN1_INTEGER)
	}
}

// TestLLDP_LazyPeerAppearsLater covers the headline lazy-resolution flip:
// a link to a not-yet-created peer yields no row, and once the peer exists
// the row appears without re-adding the link.
func TestLLDP_LazyPeerAppearsLater(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	peerIP := net.IPv4(10, 42, 0, 2).String()
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(peerIP, 2)))

	// Peer absent → no remote row, no ifAlias.
	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "OID not supported" {
		t.Fatalf("pre-create remote row = %q, want absent", got)
	}
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != "OID not supported" {
		t.Fatalf("pre-create ifAlias = %q, want absent", got)
	}

	// Create the peer — same link, no re-add.
	f.addDevice(t, 2, 4, "bravo")
	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "bravo" {
		t.Errorf("post-create remote row = %q, want bravo", got)
	}
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != "to_bravo_GigabitEthernet0/2" {
		t.Errorf("post-create ifAlias = %q", got)
	}
}

// TestLLDP_DeletePrunesAndRevertsIfAlias covers edge teardown on device
// delete: the peer's row vanishes and the surviving device's ifAlias reverts
// (never "to__").
func TestLLDP_DeletePrunesAndRevertsIfAlias(t *testing.T) {
	f, a, b, _ := lineTopology(t)
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != "to_bravo_GigabitEthernet0/2" {
		t.Fatalf("precondition ifAlias = %q", got)
	}
	// Remove B's device record and prune (simulating DeleteDevice's effect).
	f.mgr.mu.Lock()
	delete(f.mgr.devices, b.ID)
	delete(f.mgr.deviceIPs, b.IP.String())
	f.mgr.mu.Unlock()
	f.mgr.topology.PruneDevice(b.IP.String())

	if got := a.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "OID not supported" {
		t.Errorf("post-delete remote row = %q, want absent", got)
	}
	if got := a.snmpServer.findResponse(ifAliasPrefix + "1"); got != "OID not supported" {
		t.Errorf("post-delete ifAlias = %q, want absent (no to__)", got)
	}
	if n := f.mgr.topology.LinksFor(a.IP.String()); len(n) != 0 {
		t.Errorf("A still has %d links after peer prune", len(n))
	}
}

// TestLLDP_GetBulkReachesSubtree drives the real handleGetBulk over the LLDP
// range (the production access path Enlinkd uses), confirming the subtree is
// enumerated and stitched values appear.
func TestLLDP_GetBulkReachesSubtree(t *testing.T) {
	_, a, _, _ := lineTopology(t)
	// Single repeater column anchored at the LLDP root, many repetitions.
	oids, vals := bulkWalk(a.snmpServer, lldpRoot, 64)
	if len(oids) == 0 {
		t.Fatal("GETBULK returned nothing")
	}
	joined := strings.Join(oids, " ")
	if !strings.Contains(joined, oidLldpLocSysName) {
		t.Error("GETBULK missing lldpLocSysName")
	}
	// The remote sysName row should carry the peer's name.
	for i, o := range oids {
		if o == remOID(colLldpRemSysName, 1) && vals[i] != "bravo" {
			t.Errorf("GETBULK remote sysName = %q, want bravo", vals[i])
		}
	}
}

// bulkWalk repeatedly GETNEXTs one column (mirroring handleGetBulk's repeater
// loop) until it leaves the LLDP subtree or hits the repetition cap.
func bulkWalk(s *SNMPServer, anchor string, maxReps int) (oids, vals []string) {
	cur := anchor
	for i := 0; i < maxReps; i++ {
		next, val := s.findNextOID(cur)
		if next == "" || !isLLDPOID(next) {
			break
		}
		oids = append(oids, next)
		vals = append(vals, val)
		cur = next
	}
	return
}

// TestLLDP_NumericSysNameEncodesAsOctetString guards the wire-type contract:
// a purely-numeric sysName must still encode as OCTET STRING, not INTEGER.
func TestLLDP_NumericSysNameEncodesAsOctetString(t *testing.T) {
	enc := encodeTypedValue(oidLldpLocSysName, "12345")
	if enc[0] != ASN1_OCTET_STRING {
		t.Errorf("numeric lldpLocSysName tag = %#x, want OCTET STRING %#x", enc[0], ASN1_OCTET_STRING)
	}
	// ifAlias likewise.
	if enc2 := encodeTypedValue(ifAliasPrefix+"1", "100"); enc2[0] != ASN1_OCTET_STRING {
		t.Errorf("numeric ifAlias tag = %#x, want OCTET STRING", enc2[0])
	}
	// Subtype stays INTEGER.
	if sub := encodeTypedValue(oidLldpLocChassisIdSubtype, "4"); sub[0] != ASN1_INTEGER {
		t.Errorf("subtype tag = %#x, want INTEGER", sub[0])
	}
}

// countNeighbors returns how many of ports 1..maxPort have a live lldpRem row.
func countNeighbors(d *DeviceSimulator, maxPort int) int {
	n := 0
	for p := 1; p <= maxPort; p++ {
		if d.snmpServer.findResponse(remOID(colLldpRemSysName, p)) != "OID not supported" {
			n++
		}
	}
	return n
}

// TestLLDP_ClosFabricExample verifies the docs' 5-stage Clos example: the
// link/neighbor structure (spine=4 neighbors, leaf=3), the 18-link total, and
// the down-link behavior (neighbor drops on both sides, ifAlias persists).
//
// NOTE: this uses synthetic fixtures with every wired port forced UP, so it
// validates the topology/liveness LOGIC — not that the doc's specific device
// types (cisco_crs_x / arista_7280r3 / cisco_catalyst_9500 / linux_server)
// boot those ifIndexes UP in their real resource JSON. That property is a
// separate resource-file concern (verified out-of-band when the example was
// authored); if a future resource edit downs one of those ports, this test
// won't catch it.
func TestLLDP_ClosFabricExample(t *testing.T) {
	f := newLLDPFixture(t)
	seed := int64(1)
	add := func(ip string, maxIf int, name string) *DeviceSimulator {
		seed++
		return f.addDeviceAt(t, ip, maxIf, name, seed)
	}
	// superspines, spines, leaves, clients
	add("10.0.0.1", 4, "SUPERSPINE-1")
	add("10.0.0.2", 4, "SUPERSPINE-2")
	spine1 := add("10.0.1.1", 4, "SPINE-1")
	add("10.0.1.2", 4, "SPINE-2")
	add("10.0.1.3", 4, "SPINE-3")
	add("10.0.1.4", 4, "SPINE-4")
	leaf1 := add("10.0.2.1", 4, "LEAF-1")
	add("10.0.2.2", 4, "LEAF-2")
	add("10.0.2.3", 4, "LEAF-3")
	add("10.0.2.4", 4, "LEAF-4")
	add("10.0.3.1", 1, "CLIENT-1")
	add("10.0.3.2", 1, "CLIENT-2")

	links := [][4]any{
		{"10.0.0.1", 1, "10.0.1.1", 1}, {"10.0.0.1", 2, "10.0.1.2", 1},
		{"10.0.0.1", 3, "10.0.1.3", 1}, {"10.0.0.1", 4, "10.0.1.4", 1},
		{"10.0.0.2", 1, "10.0.1.1", 2}, {"10.0.0.2", 2, "10.0.1.2", 2},
		{"10.0.0.2", 3, "10.0.1.3", 2}, {"10.0.0.2", 4, "10.0.1.4", 2},
		{"10.0.1.1", 3, "10.0.2.1", 1}, {"10.0.1.1", 4, "10.0.2.2", 1},
		{"10.0.1.2", 3, "10.0.2.1", 2}, {"10.0.1.2", 4, "10.0.2.2", 2},
		{"10.0.1.3", 3, "10.0.2.3", 1}, {"10.0.1.3", 4, "10.0.2.4", 1},
		{"10.0.1.4", 3, "10.0.2.3", 2}, {"10.0.1.4", 4, "10.0.2.4", 2},
		{"10.0.2.1", 3, "10.0.3.1", 1}, {"10.0.2.3", 3, "10.0.3.2", 1},
	}
	for _, l := range links {
		must(t, f.mgr.topology.AddLink(ep(l[0].(string), l[1].(int)), ep(l[2].(string), l[3].(int))))
	}

	if f.mgr.topology.Count() != 18 {
		t.Fatalf("configured links = %d, want 18", f.mgr.topology.Count())
	}
	if got := countNeighbors(spine1, 4); got != 4 {
		t.Errorf("spine1 neighbors = %d, want 4", got)
	}
	if got := countNeighbors(leaf1, 4); got != 3 {
		t.Errorf("leaf1 neighbors = %d, want 3", got)
	}

	// Stitch: leaf1 port1 ↔ spine1 port3.
	if got := leaf1.snmpServer.findResponse(remOID(colLldpRemSysName, 1)); got != "SPINE-1" {
		t.Errorf("leaf1 port1 neighbor = %q, want SPINE-1", got)
	}

	// Down the leaf1↔spine1 link: leaf1 port1 down.
	setOper(leaf1, 1, false)
	if got := countNeighbors(leaf1, 4); got != 2 {
		t.Errorf("leaf1 neighbors after down = %d, want 2", got)
	}
	if got := countNeighbors(spine1, 4); got != 3 {
		t.Errorf("spine1 neighbors after peer down = %d, want 3", got)
	}
	// ifAlias persists (configured intent).
	if got := leaf1.snmpServer.findResponse(ifAliasPrefix + "1"); got != "to_SPINE-1_GigabitEthernet0/3" {
		t.Errorf("leaf1 ifAlias.1 after down = %q, want to_SPINE-1_GigabitEthernet0/3", got)
	}
}

// ---- REST API tests (task 4.4) ----

func doReq(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, strings.NewReader(body))
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	return w
}

func TestTopologyAPI_AddListDeleteRoundTrip(t *testing.T) {
	f := newLLDPFixture(t)
	router := setupRoutes()

	// POST add → 201.
	w := doReq(t, router, http.MethodPost, "/api/v1/topology",
		`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.2","ifindex":12}}]}`)
	if w.Code != http.StatusCreated {
		t.Fatalf("POST add = %d, want 201 (%s)", w.Code, w.Body.String())
	}

	// GET → shape.
	w = doReq(t, router, http.MethodGet, "/api/v1/topology", "")
	if w.Code != http.StatusOK {
		t.Fatalf("GET = %d", w.Code)
	}
	var doc TopologyDocJSON
	if err := json.Unmarshal(w.Body.Bytes(), &doc); err != nil {
		t.Fatalf("GET body: %v", err)
	}
	if len(doc.Links) != 1 || doc.Links[0].A.IfIndex != 5 {
		t.Fatalf("GET links = %+v", doc.Links)
	}

	// DELETE present → 204.
	w = doReq(t, router, http.MethodDelete, "/api/v1/topology",
		`{"a":{"ip":"10.0.0.2","ifindex":12},"b":{"ip":"10.0.0.1","ifindex":5}}`)
	if w.Code != http.StatusNoContent {
		t.Fatalf("DELETE = %d, want 204", w.Code)
	}
	// DELETE absent → 404.
	w = doReq(t, router, http.MethodDelete, "/api/v1/topology",
		`{"a":{"ip":"10.0.0.2","ifindex":12},"b":{"ip":"10.0.0.1","ifindex":5}}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("DELETE absent = %d, want 404", w.Code)
	}
	_ = f
}

func TestTopologyAPI_BadRequests(t *testing.T) {
	newLLDPFixture(t)
	router := setupRoutes()

	cases := map[string]string{
		"self-loop":     `{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.1","ifindex":5}}]}`,
		"unknown-field": `{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.2","ifindex":12}}],"x":1}`,
	}
	for name, body := range cases {
		w := doReq(t, router, http.MethodPost, "/api/v1/topology", body)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: POST = %d, want 400", name, w.Code)
		}
	}

	// Reused port: add one, then a second on the same local port → 400.
	if w := doReq(t, router, http.MethodPost, "/api/v1/topology",
		`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.2","ifindex":12}}]}`); w.Code != http.StatusCreated {
		t.Fatalf("setup add = %d", w.Code)
	}
	if w := doReq(t, router, http.MethodPost, "/api/v1/topology",
		`{"links":[{"a":{"ip":"10.0.0.1","ifindex":5},"b":{"ip":"10.0.0.3","ifindex":7}}]}`); w.Code != http.StatusBadRequest {
		t.Errorf("reused-port POST = %d, want 400", w.Code)
	}
	// And the failed batch must not have mutated the graph beyond the first link.
	if n := manager.topology.Count(); n != 1 {
		t.Errorf("graph count after rejected add = %d, want 1", n)
	}
}

func TestTopologyAPI_StatusConfiguredVsActive(t *testing.T) {
	f := newLLDPFixture(t)
	a := f.addDevice(t, 1, 4, "alpha")
	b := f.addDevice(t, 2, 4, "bravo")
	c := f.addDevice(t, 3, 4, "charlie")
	must(t, f.mgr.topology.AddLink(ep(a.IP.String(), 1), ep(b.IP.String(), 2)))
	must(t, f.mgr.topology.AddLink(ep(b.IP.String(), 3), ep(c.IP.String(), 1)))
	// Take one link down.
	setOper(c, 1, false)

	router := setupRoutes()
	w := doReq(t, router, http.MethodGet, "/api/v1/topology/status", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var st topologyStatus
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.SubsystemActive || st.ConfiguredLinks != 2 || st.ActiveLinks != 1 {
		t.Errorf("status = %+v, want active=true configured=2 active=1", st)
	}
}
