/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
	"time"
)

// The notification fixtures in testdata/netconf/junos are the exact message
// bytes of notifications 1177, 1178, 2395, 2396, 2397 and 2398 of the vJunos
// subscription capture. Regenerate them with:
//
//	python3 -I gen.py <capture>/out-sub.txt go/nl6/testdata/netconf/junos
//
// where gen.py is
//
//	t = open(sys.argv[1], "rb").read().decode(); OUT = sys.argv[2]
//	def note(n):
//	    m = re.search(r"=== notification %d at [^\n]*\n" % n, t)
//	    a = m.end(); b = t.find("=== notification", a)
//	    s = (t[a:b] if b >= 0 else t[a:]).replace("]]>]]>", "")
//	    return s[:-1]
//	for name, n in [("link-down-state", 1177), ("link-down-event", 1178),
//	                ("link-up-state", 2395), ("link-up-event", 2396),
//	                ("unit-up-state", 2397), ("unit-up-event", 2398)]:
//	    open(f"{OUT}/notification-{name}.xml", "wb").write(note(n).encode())

func junosLinkFixtureEvent(id, severity string, priority, ifIndex int, ifName, admin, oper string, at time.Time) junosLinkEvent {
	return junosLinkEvent{ID: id, Severity: severity, Priority: priority, IfIndex: ifIndex, IfName: ifName,
		Admin: admin, Oper: oper, At: at, PID: junosMib2dPID, Hostname: "r1"}
}

func TestJunosLinkEventFor(t *testing.T) {
	at := time.Date(2026, 10, 30, 16, 51, 31, 841089000, time.UTC)
	cases := []struct {
		name string
		evt  StateChange
		unit bool
		ok   bool
		id   string
		sev  string
		pri  int
		adm  string
		oper string
	}{
		{"physical down", StateChange{IfIndex: 1, PrevOper: OperUp, Oper: OperDown, Admin: AdminUp}, false, true, "SNMP_TRAP_LINK_DOWN", "WARNING", 28, "up(1)", "down(2)"},
		{"physical up", StateChange{IfIndex: 1, PrevOper: OperDown, Oper: OperUp, Admin: AdminUp}, false, true, "SNMP_TRAP_LINK_UP", "NOTICE", 29, "up(1)", "up(1)"},
		{"unit up", StateChange{IfIndex: 73, PrevOper: OperDown, Oper: OperUp, Admin: AdminUp}, true, true, "SNMP_TRAP_LINK_UP", "INFORMATIONAL", 30, "up(1)", "up(1)"},
		{"unit down", StateChange{IfIndex: 73, PrevOper: OperUp, Oper: OperDown, Admin: AdminUp}, true, false, "", "", 0, "", ""},
		{"admin only", StateChange{IfIndex: 1, PrevOper: OperUp, Oper: OperUp, Admin: AdminUp, Changed: LeafAdminStatus}, false, false, "", "", 0, "", ""},
		{"admin down", StateChange{IfIndex: 1, PrevOper: OperUp, Oper: OperDown, Admin: AdminDown}, false, true, "SNMP_TRAP_LINK_DOWN", "WARNING", 28, "down(2)", "down(2)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := junosLinkEventFor(c.evt, "xe-0/0/0", c.unit, at, junosMib2dPID, "r1")
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if got.ID != c.id || got.Severity != c.sev || got.Priority != c.pri || got.Admin != c.adm || got.Oper != c.oper ||
				got.IfIndex != c.evt.IfIndex || got.IfName != "xe-0/0/0" || !got.At.Equal(at) || got.PID != junosMib2dPID || got.Hostname != "r1" {
				t.Fatalf("event = %+v", got)
			}
		})
	}
}

func TestJunosNotificationBytes(t *testing.T) {
	down := time.UnixMicro(1793379091841089).UTC()
	up := time.UnixMicro(1793379139541150).UTC()
	unit := time.UnixMicro(1793379139541706).UTC()
	cases := []struct {
		name string
		e    junosLinkEvent
	}{
		{"link-down", junosLinkFixtureEvent("SNMP_TRAP_LINK_DOWN", "WARNING", 28, 529, "ge-0/0/1", "down(2)", "down(2)", down)},
		{"link-up", junosLinkFixtureEvent("SNMP_TRAP_LINK_UP", "NOTICE", 29, 529, "ge-0/0/1", "up(1)", "up(1)", up)},
		{"unit-up", junosLinkFixtureEvent("SNMP_TRAP_LINK_UP", "INFORMATIONAL", 30, 553, "ge-0/0/1.0", "up(1)", "up(1)", unit)},
	}
	for _, c := range cases {
		if got, want := string(renderJunosStateSyslog(c.e)), junosFixture(t, "notification-"+c.name+"-state.xml"); got != want {
			t.Errorf("%s state form:\n%s\nwant:\n%s", c.name, got, want)
		}
		if got, want := string(renderJunosEventSyslog(c.e)), junosFixture(t, "notification-"+c.name+"-event.xml"); got != want {
			t.Errorf("%s event form:\n%s\nwant:\n%s", c.name, got, want)
		}
	}
}

// junosFlapClient subscribes a Junos session and returns it with the engine.
func junosFlapClient(t *testing.T, subscribe bool) (*junosTestClient, *InterfaceState) {
	t.Helper()
	dev := newJunosTestDevice(t)
	dev.sysName = "NY-CORE-01"
	c := startJunosTestClient(t, dev, 1, newNetconfSessionRegistry(), junosClientHello10)
	if subscribe {
		c.send(junosRPCXML("1", `<create-subscription xmlns="`+junosNotificationNS+`"/>`))
		if r := c.readFramed(); !strings.Contains(r, "<ok/>") {
			t.Fatalf("create-subscription reply: %s", r)
		}
	}
	return c, netconfIfCounters(dev).State()
}

// junosPair reads one state-form and one event-form notification and checks
// the interface and identity they carry.
func (c *junosTestClient) junosPair(ifIndex, ifName, id, severity string) {
	c.t.Helper()
	state := c.readFramed()
	event := c.readFramed()
	for _, m := range []string{state, event} {
		for _, want := range []string{"<id>" + id + "</id>", "ifIndex " + ifIndex + ",", "ifName " + ifName + "</", "<value>" + ifName + "</value>"} {
			if !strings.Contains(m, want) {
				c.t.Fatalf("notification lacks %q:\n%s", want, m)
			}
		}
	}
	if !strings.Contains(state, "<state-system-syslog>") || !strings.Contains(state, "<severity>"+severity+"</severity>") {
		c.t.Fatalf("first message is not the %s state form:\n%s", severity, state)
	}
	if !strings.Contains(event, "<junos>") || !strings.Contains(event, "<hostname>NY-CORE-01</hostname>") {
		c.t.Fatalf("second message is not the event form with the device hostname:\n%s", event)
	}
}

func TestJunosSessionPushesOnFlap(t *testing.T) {
	c, state := junosFlapClient(t, true)
	ncLink(state, 1, OperDown)
	c.junosPair("1", "xe-0/0/0", "SNMP_TRAP_LINK_DOWN", "WARNING")
	ncLink(state, 1, OperUp)
	c.junosPair("1", "xe-0/0/0", "SNMP_TRAP_LINK_UP", "NOTICE")
}

func TestJunosSessionNoPushWithoutSubscription(t *testing.T) {
	c, state := junosFlapClient(t, false)
	ncLink(state, 1, OperDown)
	ncLink(state, 1, OperUp)
	_ = c.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if b, err := c.br.ReadByte(); err == nil {
		t.Fatalf("unsubscribed session pushed %q", b)
	}
}

func TestJunosUnitLinkEvents(t *testing.T) {
	c, state := junosFlapClient(t, true)
	if !state.NamedSubinterface(73) {
		t.Fatal("ifIndex 73 is not a logical unit")
	}
	ncLink(state, 1, OperDown)
	c.junosPair("1", "xe-0/0/0", "SNMP_TRAP_LINK_DOWN", "WARNING")
	ncLink(state, 1, OperUp)
	c.junosPair("1", "xe-0/0/0", "SNMP_TRAP_LINK_UP", "NOTICE")
	c.junosPair("73", "xe-0/0/0.0", "SNMP_TRAP_LINK_UP", "INFORMATIONAL")
}
