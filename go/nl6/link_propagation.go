/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

// Link-state propagation across the topology graph (nl6#1023).
//
// With -topology-link-propagation, the far end of a topology link loses link
// when the near end stops transmitting, and gets it back when the near end
// transmits again. The far end then raises its own ifOperStatus transition,
// ifLastChange, link trap and syslog, ON_CHANGE updates and counter hold,
// because all of those come from its own Broadcast.
//
// THE MODEL IS A CAUSE, NOT A COPY. The far end's own link is never written.
// Its slot carries a separate peerDown bit and the derivation combines the two
// (deriveOper), so a fault on each end composes: neither end comes back while
// either fault holds, and each end's own flap schedule, REST POST or auto-revert
// keeps owning its own link. Copying the near end's link into the far end's
// instead let one end's up fire cut the other end's outage short.
//
// WHAT PROPAGATES is what the near end transmits: admin up and its own link up
// (StateSnapshot.Transmits), never its peerDown bit. A propagated transition
// therefore changes the far end's derived oper but not what the far end
// transmits, so it never comes back and nothing needs marking. Counting the bit
// would latch a link down: A shut, B held down by A, B's echo stored beneath
// A's shutdown, and neither end up again after `no shutdown`.
//
// WHEN IT RUNS: after every mutation, at each of the sites that broadcast
// (flap scheduler, REST oper-status and admin-status and their auto-revert,
// SNMP SET), through publishStateChanges, and on every topology lifecycle step
// (link added, removed or pruned, device created). A MASKED link move counts:
// it broadcasts nothing, yet it changes what the port transmits, and a far end
// that missed it would come back up while this end's link is still down.
//
// Everything here is a resync, never a delta: it reads the near end's state at
// the time it runs and stores the matching bit, which SetPeerDown makes a no-op
// when nothing changed. linkPropMu serialises the read with the write, so the
// last resync to run always reads state at least as new as the last mutation,
// and a resync racing a link removal cannot store a bit after the release.

import "log"

// SetLinkPropagation records -topology-link-propagation. Startup only: a
// device created while it is off carries no peerDown bits, and turning it on
// later would not resync them.
func (sm *SimulatorManager) SetLinkPropagation(on bool) {
	sm.linkPropagation.Store(on)
}

// linkPropagationOn reports whether propagation applies. Safe on a nil manager
// and on a manager without a topology (tests construct both).
func (sm *SimulatorManager) linkPropagationOn() bool {
	return sm != nil && sm.topology != nil && sm.linkPropagation.Load()
}

// publishStateChanges is THE post-mutation helper. It broadcasts evts on state
// in order, exactly as every mutation site did before, and then resyncs the far
// end of ifIndex. Call it after EVERY mutation that may have moved something,
// including a masked one that returned no events. Nil-safe, so a site that may
// run without a manager calls it unconditionally.
//
// Only ifIndex is resynced, not the subinterfaces in evts: a mutation changes
// what ifIndex transmits and nothing else, because Transmits reads a port's own
// admin and link, never its parent's.
func (sm *SimulatorManager) publishStateChanges(ip string, state *InterfaceState, ifIndex int, evts []StateChange) {
	if state == nil {
		return
	}
	for _, evt := range evts {
		state.Broadcast(evt)
	}
	if sm.linkPropagationOn() {
		sm.resyncFarEnd(ip, ifIndex)
	}
}

// pendingBroadcast is a far end's events, held until linkPropMu is released.
type pendingBroadcast struct {
	state *InterfaceState
	evts  []StateChange
}

// flush broadcasts every pending batch in the order it was produced.
//
// Broadcasting happens outside linkPropMu because Broadcast runs the Tier C
// notify hook, which takes the far device's mu; a device in teardown would
// otherwise stall every propagation in the fleet. Two resyncs of one far end
// racing each other can therefore deliver their events in either order, the
// same contract every mutator already has: the caller broadcasts after the
// mutator returns.
func flush(pending []pendingBroadcast) {
	for _, p := range pending {
		for _, evt := range p.evts {
			p.state.Broadcast(evt)
		}
	}
}

// propEnd is one link end, resolved to its state engine BEFORE linkPropMu is
// taken: resolution reads sm.mu (FindDeviceByIP), and DeleteDevice holds sm.mu
// across a device's teardown. A resync still waits for that writer while it
// resolves its ends, as every FindDeviceByIP caller does, but never while
// holding linkPropMu, so it cannot make every other resync in the fleet wait
// behind one delete. A nil state is an end that holds nothing and takes
// nothing: no device yet, a type with no interface-state engine (treated as
// up, as operUp does), or an ifIndex that is not one of the device's
// interfaces (a typo in a link must not take a real port down).
type propEnd struct {
	end   linkEndpoint
	state *InterfaceState
}

// resolveEnd looks end up. Called without linkPropMu.
func (sm *SimulatorManager) resolveEnd(end linkEndpoint) propEnd {
	ic := deviceIfCounters(sm.FindDeviceByIP(end.IP))
	if ic.State() == nil || !containsInt(ic.IfIndices(), end.IfIndex) {
		return propEnd{end: end}
	}
	sm.warnSubinterfaceEnd(end, ic.State())
	return propEnd{end: end, state: ic.State()}
}

// warnSubinterfaceEnd logs once per end when a topology link names a
// subinterface. The link still works on the unit's own admin and link, but a
// parent outage does not travel through it: LLDP runs on the physical port,
// and a real parent fault reaches the far side through the physical link,
// which is the link to configure (nl6#1028, lldp-topology.md "Link
// propagation"). Not refused: the link may be loaded before its device
// exists, and the topology file is the user's.
func (sm *SimulatorManager) warnSubinterfaceEnd(end linkEndpoint, st *InterfaceState) {
	if st.Parent(end.IfIndex) == 0 {
		return
	}
	if _, seen := sm.subifEndWarned.LoadOrStore(end, struct{}{}); seen {
		return
	}
	log.Printf("topology: link end %s ifIndex %d is a subinterface of ifIndex %d; "+
		"its own shutdown propagates, its parent's outage does not. Link the physical ports; "+
		"units follow through their parent (see docs/reference/lldp-topology.md, Link propagation)",
		end.IP, end.IfIndex, st.Parent(end.IfIndex))
}

// transmits reports whether the end sends its partner a signal. An end with no
// state is inert and counts as transmitting.
func (p propEnd) transmits() bool {
	return p.state == nil || p.state.Snapshot(p.end.IfIndex).Transmits()
}

// linkedLocked reports whether a and b are still linked. A resync re-reads the
// graph under linkPropMu, so a link removed since its ends were resolved has
// already been released and stays released. Caller holds linkPropMu.
func (sm *SimulatorManager) linkedLocked(a, b linkEndpoint) bool {
	far, ok := sm.topology.PeerOf(a.IP, a.IfIndex)
	return ok && far == b
}

// resyncFarEnd stores, on the far end of (ip, ifIndex), whether ifIndex
// transmits. A port with no topology link has no far end and is left alone.
func (sm *SimulatorManager) resyncFarEnd(ip string, ifIndex int) {
	far, ok := sm.topology.PeerOf(ip, ifIndex)
	if !ok {
		return
	}
	nearEnd := linkEndpoint{IP: ip, IfIndex: ifIndex}
	near, farEnd := sm.resolveEnd(nearEnd), sm.resolveEnd(far)

	sm.linkPropMu.Lock()
	var pending []pendingBroadcast
	if sm.linkedLocked(nearEnd, far) {
		pending = setPeerDownLocked(farEnd, !near.transmits(), pending)
	}
	sm.linkPropMu.Unlock()
	flush(pending)
}

// resyncLinks resyncs both directions of every link in links. Called after a
// link is added and after a device is created, the two moments a link can
// start carrying state it did not carry before. With seed (device
// publication, nl6#1029) the ends are written through SeedPeerDown: an end
// whose partner does not transmit is held with the bit and the counter hold
// only, nothing is broadcast, and there is nothing to flush after the lock.
func (sm *SimulatorManager) resyncLinks(links []topoLink, seed bool) {
	if !sm.linkPropagationOn() || len(links) == 0 {
		return
	}
	ends := make([][2]propEnd, len(links))
	for i, l := range links {
		ends[i] = [2]propEnd{sm.resolveEnd(l.A), sm.resolveEnd(l.B)}
	}

	sm.linkPropMu.Lock()
	var pending []pendingBroadcast
	for i, l := range links {
		if !sm.linkedLocked(l.A, l.B) {
			continue
		}
		a, b := ends[i][0], ends[i][1]
		if seed {
			// SeedPeerDown runs the counter-hold hook here, under linkPropMu:
			// the order is linkPropMu, familyMu (released), holdMu. Nothing
			// takes holdMu and then linkPropMu; the hold side reads the engine
			// without locks, which is what keeps that order one-way.
			seedPeerDownLocked(b, !a.transmits())
			seedPeerDownLocked(a, !b.transmits())
			continue
		}
		pending = setPeerDownLocked(b, !a.transmits(), pending)
		pending = setPeerDownLocked(a, !b.transmits(), pending)
	}
	sm.linkPropMu.Unlock()
	flush(pending)
}

// releaseLinks clears peerDown on both ends of every link in links, which
// the caller has just removed from the graph: a port with no link has no far
// end to hold it down. An end whose device is already gone is skipped.
func (sm *SimulatorManager) releaseLinks(links []topoLink) {
	if !sm.linkPropagationOn() || len(links) == 0 {
		return
	}
	ends := make([]propEnd, 0, 2*len(links))
	for _, l := range links {
		ends = append(ends, sm.resolveEnd(l.A), sm.resolveEnd(l.B))
	}

	sm.linkPropMu.Lock()
	var pending []pendingBroadcast
	for _, e := range ends {
		pending = setPeerDownLocked(e, false, pending)
	}
	sm.linkPropMu.Unlock()
	flush(pending)
}

// setPeerDownLocked stores down on end and appends the events to pending. An
// end with no state takes nothing. Caller holds linkPropMu.
func setPeerDownLocked(end propEnd, down bool, pending []pendingBroadcast) []pendingBroadcast {
	if end.state == nil {
		return pending
	}
	if evts := end.state.SetPeerDown(end.end.IfIndex, down); len(evts) > 0 {
		pending = append(pending, pendingBroadcast{state: end.state, evts: evts})
	}
	return pending
}

// seedPeerDownLocked is setPeerDownLocked for a seed: the end's hold is
// stored without a transition. Caller holds linkPropMu.
func seedPeerDownLocked(end propEnd, down bool) {
	if end.state == nil {
		return
	}
	end.state.SeedPeerDown(end.end.IfIndex, down)
}

// AddTopologyLinks adds links to the graph and resyncs them, so a link whose
// near end is already down holds its far end down from the moment it exists.
func (sm *SimulatorManager) AddTopologyLinks(links []LinkJSON) error {
	if err := sm.topology.AddLinks(links); err != nil {
		return err
	}
	sm.resyncLinks(normLinks(links), false)
	return nil
}

// RemoveTopologyLink removes one link and releases both of its ends.
func (sm *SimulatorManager) RemoveTopologyLink(a, b LinkEndpointJSON) bool {
	removed, ok := sm.topology.RemoveLinkReturning(a, b)
	if ok {
		sm.releaseLinks([]topoLink{removed})
	}
	return ok
}

// resyncDeviceLinks seeds every link of a device that has just been
// published (both creation paths, beside invalidateLLDPServedCache),
// through resyncLinks with seed set. A link
// loaded before its devices exist (-topology-config) resolves when the later
// of the two is created, and the seed takes effect on both ends silently, as
// if both boxes had booted together: an end whose partner does not transmit
// at that moment goes down(2) with its counters held and its lastChange
// untouched, and fires no linkDown trap, syslog message or ON_CHANGE update.
// On the new device that is down(2) from the first poll with lastChange at
// boot. On a partner that already existed, polls before this publication
// read up(1) and lastChange stays wherever it was: that port was up only
// because its neighbour did not exist yet, the simulator's fiction and not
// the fleet's. The first later change on either end is a normal transition
// (nl6#1029).
func (sm *SimulatorManager) resyncDeviceLinks(device *DeviceSimulator) {
	if !sm.linkPropagationOn() || device == nil {
		return
	}
	ip := device.IP.String()
	var links []topoLink
	for _, l := range sm.topology.LinksFor(ip) {
		links = append(links, topoLink{
			A: linkEndpoint{IP: ip, IfIndex: l.LocalIfIndex},
			B: linkEndpoint{IP: l.PeerIP, IfIndex: l.PeerIfIndex},
		})
	}
	sm.resyncLinks(links, true)
}

// normLinks converts wire links that AddLinks has already accepted into the
// graph's normalised form.
func normLinks(links []LinkJSON) []topoLink {
	out := make([]topoLink, 0, len(links))
	for _, l := range links {
		a, errA := normEndpoint(l.A)
		b, errB := normEndpoint(l.B)
		if errA != nil || errB != nil {
			log.Printf("topology: link propagation skipped a link AddLinks accepted: %v %v", errA, errB)
			continue
		}
		out = append(out, topoLink{A: a, B: b})
	}
	return out
}

// heldDownByPeer reports whether dev's ifIndex is down ONLY because its
// topology partner is silent: its own admin and link are up and peerDown
// holds it. The graph uses it to name the end that caused an outage.
func heldDownByPeer(dev *DeviceSimulator, ifIndex int) bool {
	state := deviceInterfaceState(dev)
	if state == nil {
		return false
	}
	snap := state.Snapshot(ifIndex)
	return snap.PeerDown && snap.Transmits() && snap.Oper != OperUp
}
