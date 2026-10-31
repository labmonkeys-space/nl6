/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"time"
)

// junosMib2dPID is the process id mib2d reports in every link event. A real
// device has one value per boot, so one constant for every simulated device
// is the simplest faithful choice.
const junosMib2dPID = 18896

// junosEventTimeFormat is the layout of the notification eventTime.
const junosEventTimeFormat = "2006-01-02T15:04:05+00:00"

// junosLinkEvent is one mib2d link trap as the device logs it. Admin and
// Oper read up(1) or down(2).
type junosLinkEvent struct {
	ID       string
	Severity string
	Priority int
	IfIndex  int
	IfName   string
	Admin    string
	Oper     string
	At       time.Time
	PID      int
	Hostname string
}

// junosStatus renders a status leaf the way mib2d spells it.
func junosStatus(up bool) string {
	if up {
		return "up(1)"
	}
	return "down(2)"
}

// junosLinkEventFor maps one state change to the link event mib2d logs for
// it. An event that did not move the derived oper status logs nothing. A
// logical unit logs only its way up. The interface name and the hostname
// are XML-escaped here, once, because both renderings embed them in the
// body and in an element of their own.
func junosLinkEventFor(evt StateChange, ifName string, unit bool, at time.Time, pid int, hostname string) (junosLinkEvent, bool) {
	if evt.PrevOper == evt.Oper {
		return junosLinkEvent{}, false
	}
	e := junosLinkEvent{
		IfIndex: evt.IfIndex, IfName: netconfEscape(ifName),
		Admin: junosStatus(evt.Admin == AdminUp), Oper: junosStatus(evt.Oper == OperUp),
		At: at, PID: pid, Hostname: netconfEscape(hostname),
	}
	switch {
	case evt.Oper == OperUp && unit:
		e.ID, e.Severity, e.Priority = "SNMP_TRAP_LINK_UP", "INFORMATIONAL", 30
	case evt.Oper == OperUp:
		e.ID, e.Severity, e.Priority = "SNMP_TRAP_LINK_UP", "NOTICE", 29
	case unit:
		return junosLinkEvent{}, false
	default:
		e.ID, e.Severity, e.Priority = "SNMP_TRAP_LINK_DOWN", "WARNING", 28
	}
	return e, true
}

func (e junosLinkEvent) message() string {
	return fmt.Sprintf("%s: ifIndex %d, ifAdminStatus %s, ifOperStatus %s, ifName %s", e.ID, e.IfIndex, e.Admin, e.Oper, e.IfName)
}

// renderJunosStateSyslog renders the state-system-syslog form of e.
func renderJunosStateSyslog(e junosLinkEvent) []byte {
	return fmt.Appendf(nil, `
<notification xmlns="`+junosNotificationNS+`">
<eventTime>%[1]s</eventTime>
<state-system-syslog>
<state>
  <system>
    <syslog>
      <messages>
        <message>
          <timestamp>%[2]d</timestamp>
          <id>%[3]s</id>
          <severity>%[4]s</severity>
          <facility>DAEMON</facility>
          <priority>%[5]d</priority>
          <pid>%[6]d</pid>
          <log-message>%[7]s</log-message>
          <application>mib2d</application>
          <structured-data>
            <parameters>
              <parameter>
                <name>snmp-interface-index</name>
                <value>%[8]d</value>
              </parameter>
              <parameter>
                <name>admin-status</name>
                <value>%[9]s</value>
              </parameter>
              <parameter>
                <name>operational-status</name>
                <value>%[10]s</value>
              </parameter>
              <parameter>
                <name>interface-name</name>
                <value>%[11]s</value>
              </parameter>
            </parameters>
          </structured-data>
        </message>
      </messages>
    </syslog>
  </system>
</state>
</state-system-syslog>
</notification>
`, e.At.UTC().Format(junosEventTimeFormat), e.At.UnixMicro(), e.ID, e.Severity, e.Priority, e.PID,
		e.message(), e.IfIndex, e.Admin, e.Oper, e.IfName)
}

// renderJunosEventSyslog renders the syslog/junos/events form of e.
func renderJunosEventSyslog(e junosLinkEvent) []byte {
	us := e.At.UnixMicro()
	return fmt.Appendf(nil, `
<notification xmlns="`+junosNotificationNS+`">
<eventTime>%[1]s</eventTime>
<syslog>
<junos>
  <events>
    <event>
      <id>%[2]s</id>
      <type>2</type>
      <priority>%[3]d</priority>
      <facility>3</facility>
      <timestamp>
        <seconds>%[4]d</seconds>
        <microseconds>%[5]d</microseconds>
      </timestamp>
      <pid>%[6]d</pid>
      <message>%[7]s</message>
      <daemon>mib2d</daemon>
      <hostname>%[8]s</hostname>
      <attributes>
        <key>snmp-interface-index</key>
        <value>%[9]d</value>
      </attributes>
      <attributes>
        <key>admin-status</key>
        <value>%[10]s</value>
      </attributes>
      <attributes>
        <key>operational-status</key>
        <value>%[11]s</value>
      </attributes>
      <attributes>
        <key>interface-name</key>
        <value>%[12]s</value>
      </attributes>
    </event>
  </events>
</junos>
</syslog>
</notification>
`, e.At.UTC().Format(junosEventTimeFormat), e.ID, e.Priority, us/1e6, us%1e6, e.PID,
		e.message(), e.Hostname, e.IfIndex, e.Admin, e.Oper, e.IfName)
}

// junosStateEvent is the Junos rendering of one state change: the state form
// then the event form, both from the same instant. A session without its
// subscription renders nothing.
func (s *netconfSession) junosStateEvent(e *netconfStateEvent) {
	if s.isClosed() {
		return
	}
	ev := s.ev
	// An admin change renders one pair, not one per event it broadcasts.
	if ev.twinOperEvent(e.evt) {
		return
	}
	ev.mu.Lock()
	var sub *netconfSub
	if len(ev.subs) > 0 {
		sub = ev.subs[0]
	}
	ev.mu.Unlock()
	if sub == nil {
		return
	}
	unit := netconfIfCounters(s.dev).State().NamedSubinterface(e.evt.IfIndex)
	host := s.dev.sysName
	if v := s.dev.cachedSysName.Load(); v != nil {
		host = v.(string)
	}
	le, ok := junosLinkEventFor(e.evt, e.ifName(), unit, e.evt.At, junosMib2dPID, host)
	if !ok {
		return
	}
	s.enqueue(sub, renderJunosStateSyslog(le))
	s.enqueue(sub, renderJunosEventSyslog(le))
}
