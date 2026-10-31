/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// junosSyslogFixture is the state-system-syslog form of one captured mib2d
// link event, reduced to the fields the syslog catalog must reproduce.
type junosSyslogFixture struct {
	Priority   int    `xml:"state-system-syslog>state>system>syslog>messages>message>priority"`
	ID         string `xml:"state-system-syslog>state>system>syslog>messages>message>id"`
	Message    string `xml:"state-system-syslog>state>system>syslog>messages>message>log-message"`
	App        string `xml:"state-system-syslog>state>system>syslog>messages>message>application"`
	Parameters []struct {
		Name  string `xml:"name"`
		Value string `xml:"value"`
	} `xml:"state-system-syslog>state>system>syslog>messages>message>structured-data>parameters>parameter"`
}

func loadJunosSyslogFixture(t *testing.T, name string) junosSyslogFixture {
	t.Helper()
	raw, err := os.ReadFile("testdata/netconf/junos/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var f junosSyslogFixture
	if err := xml.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	if f.ID == "" || len(f.Parameters) != 4 {
		t.Fatalf("fixture %s did not parse: %+v", name, f)
	}
	return f
}

// TestMx10004LinkSyslogMatchesTheMib2dCapture drives an admin-down and an
// admin-up through a wired juniper_mx10004 device and compares each
// RFC 5424 datagram with the vJunos capture: PRI, TAG, MSGID, the four
// structured-data parameters and the body, with ifAdminStatus following
// the engine. The capture's ifIndex 529 is mapped to the fixture's
// interface 1 and its name to the capture's port name.
func TestMx10004LinkSyslogMatchesTheMib2dCapture(t *testing.T) {
	fx := buildWired(t, false, false)
	syslogColl, addr := newLocalUDPCollector(t)
	sx := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP: fx.device.IP, Encoder: &RFC5424Encoder{}, Collector: addr,
		SharedConn: newTestSharedSocket(t), SysName: "r1",
		IfNameFn:        func(int) string { return "ge-0/0/1" },
		IfAdminStatusFn: deviceIfAdminStatusFn(fx.device),
	})
	t.Cleanup(func() { _ = sx.Close() })
	fx.device.syslogExporter = sx
	universal, _ := LoadEmbeddedSyslogCatalog()
	jnx, err := LoadSyslogCatalogFromFile("resources/juniper_mx10004/syslog.json")
	if err != nil {
		t.Fatal(err)
	}
	fx.sm.syslogCatalogsByType = map[string]*SyslogCatalog{
		universalCatalogKey: universal,
		"juniper_mx10004":   universal.MergeOverlay(jnx),
	}
	fx.sm.deviceTypesByIP = map[string]string{fx.device.IP.String(): "juniper_mx10004"}

	check := func(t *testing.T, fixture string, admin uint8) {
		t.Helper()
		want := loadJunosSyslogFixture(t, fixture)
		for _, evt := range fx.state.ApplyAdminStatus(1, admin) {
			fx.state.Broadcast(evt)
		}
		payload, _ := readNextDatagram(t, syslogColl, 500*time.Millisecond)
		got := string(payload)
		wantMsg := strings.ReplaceAll(want.Message, "529", "1")
		for _, s := range []string{
			fmt.Sprintf("<%d>1 ", want.Priority),
			" r1 " + want.App + " ",
			" " + want.ID + " ",
			wantMsg,
		} {
			if !strings.Contains(got, s) {
				t.Errorf("%s: datagram %q lacks %q", fixture, got, s)
			}
		}
		for _, p := range want.Parameters {
			kv := fmt.Sprintf(`%s="%s"`, p.Name, strings.ReplaceAll(p.Value, "529", "1"))
			if !strings.Contains(got, kv) {
				t.Errorf("%s: datagram %q lacks SD-PARAM %s", fixture, got, kv)
			}
		}
	}
	check(t, "notification-link-down-state.xml", AdminDown)
	check(t, "notification-link-up-state.xml", AdminUp)
	if n := sx.Stats().Sent.Load(); n != 2 {
		t.Errorf("syslog Sent = %d, want 2", n)
	}

	// The message reports the admin status its event carried, not the
	// engine's value at fire time: an auto-revert that lands between the
	// mutation and the fire must not make the message contradict the event.
	evts := fx.state.ApplyAdminStatus(1, AdminDown)
	fx.state.ApplyAdminStatus(1, AdminUp)
	for _, evt := range evts {
		fx.state.Broadcast(evt)
	}
	payload, _ := readNextDatagram(t, syslogColl, 500*time.Millisecond)
	if got := string(payload); !strings.Contains(got, "ifAdminStatus down(2), ifOperStatus down(2)") || !strings.Contains(got, `admin-status="down(2)"`) {
		t.Errorf("link-down fired after a revert reports the engine, not its event: %q", got)
	}
}

// TestIfAdminStatusFieldOnBothSides pins the shared field: both catalogs
// accept {{.IfAdminStatus}}, both exporters fill it from their option in
// their own spelling (syslog down(2), trap 2), both override paths take
// only that spelling, and a device without an engine reads up.
func TestIfAdminStatusFieldOnBothSides(t *testing.T) {
	down := func(int) uint8 { return AdminDown }

	syslogCat, err := parseSyslogCatalog([]byte(`{"entries":[{"name":"a","weight":1,"facility":"daemon","severity":"notice","appName":"t","msgId":"M","structuredData":{"admin-status":"{{.IfAdminStatus}}"},"template":"admin {{.IfAdminStatus}}"}]}`), "<test>")
	if err != nil {
		t.Fatal(err)
	}
	sx := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP: net.IPv4(127, 0, 0, 1), Encoder: &RFC5424Encoder{},
		Collector: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, SharedConn: newTestSharedSocket(t),
		IfAdminStatusFn: down,
	})
	t.Cleanup(func() { _ = sx.Close() })
	res, err := syslogCat.Entries[0].Resolve(sx.buildCtx(1), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Message != "admin down(2)" || len(res.StructuredData) != 1 || res.StructuredData[0].Value != "down(2)" {
		t.Errorf("syslog resolve = %+v, want down(2) in body and SD", res)
	}
	res, err = syslogCat.Entries[0].Resolve(sx.buildCtx(1), map[string]string{"IfAdminStatus": "up(1)"})
	if err != nil || res.Message != "admin up(1)" {
		t.Errorf("syslog override: %q, %v", res.Message, err)
	}
	if _, err := syslogCat.Entries[0].Resolve(sx.buildCtx(1), map[string]string{"IfAdminStatus": "testing(3)"}); err == nil {
		t.Error("syslog override accepted a spelling the engine never produces")
	}

	trapCat, err := parseCatalog([]byte(`{"traps":[{"name":"a","weight":1,"snmpTrapOID":"1.3.6.1.6.3.1.1.5.1","varbinds":[{"oid":"1.3.6.1.2.1.2.2.1.7.1","type":"integer","value":"{{.IfAdminStatus}}"}]}]}`), "<test>")
	if err != nil {
		t.Fatal(err)
	}
	coll := newMockCollector(t, false)
	t.Cleanup(coll.Close)
	tx := NewTrapExporter(TrapExporterOptions{
		DeviceIP: net.IPv4(127, 0, 0, 1), Community: "public", Mode: TrapModeTrap,
		Collector: coll.addr, IfAdminStatusFn: down,
	})
	tx.SetConn(openTestUDPConn(t))
	tx.StartBackgroundLoops(context.Background())
	t.Cleanup(func() { _ = tx.Close() })
	vbs, err := trapCat.Entries[0].Resolve(tx.buildCtx(1, nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) != 1 || fmt.Sprint(vbs[0].Value) != "2" {
		t.Errorf("trap resolve = %+v, want 2", vbs)
	}
	vbs, err = trapCat.Entries[0].Resolve(tx.buildCtx(1, nil), map[string]string{"IfAdminStatus": "1"})
	if err != nil || len(vbs) != 1 || fmt.Sprint(vbs[0].Value) != "1" {
		t.Errorf("trap override: %+v, %v", vbs, err)
	}
	if _, err := trapCat.Entries[0].Resolve(tx.buildCtx(1, nil), map[string]string{"IfAdminStatus": "down(2)"}); err == nil {
		t.Error("trap override accepted the display spelling, which cannot fill an integer varbind")
	}

	if got := deviceIfAdminStatusFn(nil)(1); got != AdminUp {
		t.Errorf("no device: %d, want AdminUp", got)
	}
	if got := deviceIfAdminStatusFn(&DeviceSimulator{})(1); got != AdminUp {
		t.Errorf("no engine: %d, want AdminUp", got)
	}
	// Default option: an exporter built without the function reads up(1).
	plain := NewSyslogExporter(SyslogExporterOptions{
		DeviceIP: net.IPv4(127, 0, 0, 1), Encoder: &RFC5424Encoder{},
		Collector: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, SharedConn: newTestSharedSocket(t),
	})
	t.Cleanup(func() { _ = plain.Close() })
	if got := plain.buildCtx(1).IfAdminStatus; got != "up(1)" {
		t.Errorf("default syslog option: %q, want up(1)", got)
	}
}
