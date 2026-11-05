/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startVrpTestClient drives a session built by newVrpNetconfSession over
// net.Pipe with base:1.1 chunked framing, as NetGauze connects.
func startVrpTestClient(t *testing.T, dev *DeviceSimulator) *netconfTestClient {
	t.Helper()
	srv, cli := net.Pipe()
	sess := newVrpNetconfSession(5, dev, srv, newNetconfSessionRegistry(), USERNAME)
	done := make(chan error, 1)
	go func() { done <- sess.Serve(context.Background()) }()
	t.Cleanup(func() { _ = cli.Close(); sess.close() })

	c := &netconfTestClient{t: t, conn: cli, f: newNetconfFramer(cli, cli), done: done}
	_ = cli.SetDeadline(time.Now().Add(10 * time.Second))
	h, err := c.f.ReadMessage()
	if err != nil {
		t.Fatalf("read server hello: %v", err)
	}
	c.hello = string(h)
	ch := `<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.1</capability></capabilities></hello>`
	if err := c.f.WriteMessage([]byte(ch)); err != nil {
		t.Fatalf("write client hello: %v", err)
	}
	c.f.chunked = true
	return c
}

// newVrpTestDevice is a huawei_ne8000 at 192.0.2.13. With exporter true it
// holds an unstarted exporter for collector 198.51.100.7:10003.
func newVrpTestDevice(exporter bool) *DeviceSimulator {
	dev := &DeviceSimulator{IP: net.IPv4(192, 0, 2, 13), resourceFile: "huawei_ne8000.json"}
	if exporter {
		dev.yangPushExporter = &YangPushExporter{dev: dev, collector: "198.51.100.7:10003", segSize: 1436, subs: vrpSubs}
	}
	return dev
}

// vrpDataInner returns what sits between <data> and </data>: the buffer
// NetGauze copies out (copy_buffer_till) and parses on its own, so every
// prefix it uses must be declared inside it.
func vrpDataInner(t *testing.T, reply string) string {
	t.Helper()
	if strings.Contains(reply, "<data/>") {
		return ""
	}
	i := strings.Index(reply, "<data>")
	j := strings.LastIndex(reply, "</data>")
	if i < 0 || j < i {
		t.Fatalf("no <data> in reply:\n%s", reply)
	}
	return reply[i+len("<data>") : j]
}

// NetGauze's literal requests.
const (
	vrpNGYangLibraryReq = `<get><filter type="subtree"><yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
                    </yang-library>
                    <modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library">
                    </modules-state></filter></get>`
	vrpNGFiltersReq = `<get><filter type="subtree"><filters xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications" /></filter></get>`
)

func vrpNGSubscriptionReq(id int) string {
	return fmt.Sprintf(`<get><filter type="subtree"><subscriptions xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">
                  <subscription>
                    <id>%d</id>
                  </subscription>
                </subscriptions></filter></get>`, id)
}

func vrpGetSchemaReq(name, version string) string {
	v := ""
	if version != "" {
		v = "<version>" + version + "</version>"
	}
	return `<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>` + name + `</identifier>` + v + `<format>yang</format></get-schema>`
}

func TestVrpHello(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(false))
	var h struct {
		Caps      []string `xml:"capabilities>capability"`
		SessionID uint32   `xml:"session-id"`
	}
	if err := xml.Unmarshal([]byte(c.hello), &h); err != nil {
		t.Fatalf("hello: %v\n%s", err, c.hello)
	}
	want := []string{
		netconfBase10,
		netconfBase11,
		"urn:ietf:params:netconf:capability:yang-library:1.1?revision=2019-01-04&content-id=" + vrpContentID(),
		"urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring?module=ietf-netconf-monitoring&revision=2010-10-04",
	}
	if strings.Join(h.Caps, "\n") != strings.Join(want, "\n") {
		t.Fatalf("capabilities\n got: %q\nwant: %q", h.Caps, want)
	}
	if h.SessionID != 5 {
		t.Fatalf("session-id = %d, want 5", h.SessionID)
	}
	// The framing switched to chunked: a request round-trips.
	if r := c.rpc(vrpGetSchemaReq("ietf-interfaces", "")); !strings.Contains(r, "module ietf-interfaces") {
		t.Fatalf("chunked request failed:\n%.300s", r)
	}
}

func TestVrpGetYangLibrary(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(false))
	r := c.rpc(vrpNGYangLibraryReq)
	if !strings.HasPrefix(r, `<rpc-reply xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="m1"`) {
		t.Fatalf("reply envelope:\n%.300s", r)
	}
	// NetGauze takes the YangLibrary branch only when <yang-library> is the
	// first child of <data>.
	if got := vrpDataInner(t, r); got != string(vrpYangLibraryXML()) {
		t.Fatalf("data\n got: %.400s\nwant: %.400s", got, vrpYangLibraryXML())
	}

	// Each subtree alone returns only itself.
	lib := c.rpc(`<get><filter type="subtree"><yang-library xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"/></filter></get>`)
	if in := vrpDataInner(t, lib); !strings.HasPrefix(in, "<yang-library ") || strings.Contains(in, "modules-state") {
		t.Fatalf("yang-library alone:\n%.300s", in)
	}
	ms := c.rpc(`<get><filter type="subtree"><modules-state xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-library"/></filter></get>`)
	if in := vrpDataInner(t, ms); !strings.HasPrefix(in, "<modules-state ") || strings.Contains(in, "<yang-library") {
		t.Fatalf("modules-state alone:\n%.300s", in)
	}
}

func TestVrpGetSchema(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(false))
	const open = `<data xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring">`
	for _, m := range vrpYangModules() {
		r := c.rpc(vrpGetSchemaReq(m.Name, m.Revision))
		i := strings.Index(r, open)
		j := strings.LastIndex(r, "</data>")
		if i < 0 || j < i {
			t.Fatalf("%s: no monitoring <data>:\n%.300s", m.Name, r)
		}
		// Decode the text as an XML parser does and compare with the source.
		var d struct {
			Text string `xml:",chardata"`
		}
		if err := xml.Unmarshal([]byte(r[i:j+len("</data>")]), &d); err != nil {
			t.Fatalf("%s: %v", m.Name, err)
		}
		if d.Text != string(m.Source) {
			t.Fatalf("%s: schema text differs from the embedded source", m.Name)
		}
		if again := c.rpc(vrpGetSchemaReq(m.Name, m.Revision)); again[strings.Index(again, open):] != r[i:] {
			t.Fatalf("%s: second get-schema differs", m.Name)
		}
	}
	// No version means the served revision.
	if r := c.rpc(vrpGetSchemaReq("ietf-interfaces", "")); !strings.Contains(r, "module ietf-interfaces") {
		t.Fatalf("no version:\n%.300s", r)
	}
	for _, bad := range []string{vrpGetSchemaReq("no-such-module", ""), vrpGetSchemaReq("ietf-interfaces", "1999-01-01")} {
		r := c.rpc(bad)
		if !strings.Contains(r, "<error-tag>invalid-value</error-tag>") || strings.Contains(r, "<data") {
			t.Fatalf("unknown schema:\n%s", r)
		}
	}
	if r := c.rpc(`<get-schema xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><identifier>ietf-interfaces</identifier><format>yin</format></get-schema>`); !strings.Contains(r, "<error-tag>invalid-value</error-tag>") {
		t.Fatalf("yin format:\n%s", r)
	}
}

func TestVrpGetSubscriptionByID(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(true))
	in := vrpDataInner(t, c.rpc(vrpNGSubscriptionReq(8)))
	// Prefixed identities resolve inside the copied fragment.
	for _, s := range []string{
		`<subscriptions xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"><subscription><id>8</id>`,
		`<datastore xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push" xmlns:ds="urn:ietf:params:xml:ns:yang:ietf-datastores">ds:operational</datastore>`,
		`<transport xmlns:unt="urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport">unt:udp-notif</transport>`,
	} {
		if !strings.Contains(in, s) {
			t.Fatalf("missing %s in\n%s", s, in)
		}
	}
	type receiver struct {
		Name string `xml:"name"`
		Ref  string `xml:"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers receiver-instance-ref"`
	}
	type udp struct {
		Addr    string `xml:"remote-address"`
		Port    int    `xml:"remote-port"`
		Seg     bool   `xml:"enable-segmentation"`
		MaxSize int    `xml:"max-segment-size"`
	}
	var doc struct {
		XMLName xml.Name `xml:"urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications subscriptions"`
		Subs    []struct {
			ID        uint32     `xml:"id"`
			Datastore string     `xml:"urn:ietf:params:xml:ns:yang:ietf-yang-push datastore"`
			FilterRef string     `xml:"urn:ietf:params:xml:ns:yang:ietf-yang-push selection-filter-ref"`
			Transport string     `xml:"transport"`
			Encoding  string     `xml:"encoding"`
			Receivers []receiver `xml:"receivers>receiver"`
			Periodic  *struct {
				Period uint32 `xml:"period"`
				Anchor string `xml:"anchor-time"`
			} `xml:"urn:ietf:params:xml:ns:yang:ietf-yang-push periodic"`
		} `xml:"subscription"`
		Instances []struct {
			Name string `xml:"name"`
			UDP  udp    `xml:"urn:ietf:params:xml:ns:yang:ietf-udp-notif-transport udp-notif-receiver"`
		} `xml:"urn:ietf:params:xml:ns:yang:ietf-subscribed-notif-receivers receiver-instances>receiver-instance"`
	}
	if err := xml.Unmarshal([]byte(in), &doc); err != nil {
		t.Fatalf("fragment: %v\n%s", err, in)
	}
	if len(doc.Subs) != 1 {
		t.Fatalf("got %d subscriptions, want 1", len(doc.Subs))
	}
	s := doc.Subs[0]
	if s.ID != 8 || s.FilterRef != "STATEINTERFACE2" || s.Encoding != "encode-json" || s.Periodic == nil ||
		s.Periodic.Period != 6000 || s.Periodic.Anchor != "2025-01-01T00:00:30Z" {
		t.Fatalf("subscription 8 = %+v", s)
	}
	if len(s.Receivers) != 1 || s.Receivers[0].Ref != s.Receivers[0].Name || len(doc.Instances) != 1 || doc.Instances[0].Name != s.Receivers[0].Name {
		t.Fatalf("receiver = %+v, instances = %+v", s.Receivers, doc.Instances)
	}
	if u := doc.Instances[0].UDP; u.Addr != "198.51.100.7" || u.Port != 10003 || !u.Seg || u.MaxSize != 1436 {
		t.Fatalf("udp-notif-receiver = %+v", u)
	}
	// NetGauze's Subscription parser stops at the first </subscription>, so
	// the receiver instances must come after it.
	if strings.Index(in, "<receiver-instances") < strings.Index(in, "</subscription>") {
		t.Fatal("receiver-instances precede the subscription")
	}

	on := vrpDataInner(t, c.rpc(vrpNGSubscriptionReq(10)))
	want := `<on-change xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><dampening-period>0</dampening-period><sync-on-start>true</sync-on-start></on-change>`
	if !strings.Contains(on, "<id>10</id>") || !strings.Contains(on, want) || strings.Contains(on, "periodic") ||
		!strings.Contains(on, ">ONCHANGEINTERFACE</selection-filter-ref>") {
		t.Fatalf("subscription 10:\n%s", on)
	}

	if r := c.rpc(vrpNGSubscriptionReq(77)); !strings.Contains(r, "<data/>") {
		t.Fatalf("unknown id:\n%s", r)
	}
	// A device that has not opted in serves no subscriptions.
	off := startVrpTestClient(t, newVrpTestDevice(false))
	if r := off.rpc(vrpNGSubscriptionReq(8)); !strings.Contains(r, "<data/>") {
		t.Fatalf("no exporter:\n%s", r)
	}
}

func TestVrpGetFilters(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(true))
	in := vrpDataInner(t, c.rpc(vrpNGFiltersReq))
	want := `<filters xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications">` +
		`<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><filter-id>STATEINTERFACE2</filter-id><datastore-xpath-filter xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">/if:interfaces/if:interface/if:statistics</datastore-xpath-filter></selection-filter>` +
		`<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><filter-id>STATSINTERFACE2</filter-id><datastore-xpath-filter xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">/if:interfaces/if:interface</datastore-xpath-filter></selection-filter>` +
		`<selection-filter xmlns="urn:ietf:params:xml:ns:yang:ietf-yang-push"><filter-id>ONCHANGEINTERFACE</filter-id><datastore-xpath-filter xmlns:if="urn:ietf:params:xml:ns:yang:ietf-interfaces">/if:interfaces/if:interface/if:oper-status | /if:interfaces/if:interface/if:admin-status</datastore-xpath-filter></selection-filter>` +
		`</filters>`
	if in != want {
		t.Fatalf("filters\n got: %s\nwant: %s", in, want)
	}
	off := startVrpTestClient(t, newVrpTestDevice(false))
	if r := off.rpc(vrpNGFiltersReq); !strings.Contains(r, "<data/>") {
		t.Fatalf("no exporter:\n%s", r)
	}
}

func TestVrpUnknownRPC(t *testing.T) {
	c := startVrpTestClient(t, newVrpTestDevice(false))
	r := c.rpc(`<get-config><source><running/></source></get-config>`)
	if !strings.Contains(r, "<error-tag>operation-not-supported</error-tag>") {
		t.Fatalf("unknown rpc:\n%s", r)
	}
	if r := c.rpc(`<close-session/>`); !strings.Contains(r, "<ok/>") {
		t.Fatalf("close-session:\n%s", r)
	}
	c.waitDone()
}

func TestNetconfPublicKeyLogin(t *testing.T) {
	good, bad := newNetconfTestSigner(t), newNetconfTestSigner(t)
	path := filepath.Join(t.TempDir(), "authorized_keys")
	body := "# nl6 test\n\n" + string(ssh.MarshalAuthorizedKey(good.PublicKey()))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadNetconfAuthorizedKeys(path)
	if err != nil || len(keys) != 1 {
		t.Fatalf("loadNetconfAuthorizedKeys = %d keys, %v", len(keys), err)
	}

	mgr := useNetconfTestManager(t, true)
	mgr.netconfAuthorizedKeys = keys
	dev := newVrpTestDevice(false)
	dev.ID, dev.IP = "ne8000-test", net.IPv4(127, 0, 0, 1)
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err = dev.startNetconfServer()
	dev.mu.Unlock()
	if err != nil || dev.netconfListener == nil {
		t.Fatalf("startNetconfServer: %v", err)
	}
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	addr := dev.netconfListener.Addr().String()

	dial := func(user string, s ssh.Signer) (*ssh.Client, error) {
		return ssh.Dial("tcp", addr, &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(s)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // test server
			Timeout:         5 * time.Second,
		})
	}
	cl, err := dial(USERNAME, good)
	if err != nil {
		t.Fatalf("authorized key refused: %v", err)
	}
	t.Cleanup(func() { _ = cl.Close() })
	f, _ := openNetconfOverSSH(t, cl)
	if r, err := netconfRPCWithin(f, "1", vrpGetSchemaReq("ietf-datastores", ""), 5*time.Second); err != nil || !strings.Contains(r, "module ietf-datastores") {
		t.Fatalf("VRP get-schema over SSH: %.300s %v", r, err)
	}
	if c, err := dial(USERNAME, bad); err == nil {
		_ = c.Close()
		t.Fatal("unknown key accepted")
	}
	if c, err := dial("other", good); err == nil {
		_ = c.Close()
		t.Fatal("authorized key accepted for another user")
	}
	// Password login stays.
	_ = dialNetconfTestSSH(t, addr)
}

func TestNetconfAuthorizedKeysBadFile(t *testing.T) {
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, _ := ssh.NewSignerFromKey(priv)
	for name, body := range map[string]string{
		"garbage": string(ssh.MarshalAuthorizedKey(s.PublicKey())) + "not a key\n",
		"empty":   "# only a comment\n",
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadNetconfAuthorizedKeys(p); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	if _, err := loadNetconfAuthorizedKeys(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file: no error")
	}
}

func TestNetconfDialectTableVrp(t *testing.T) {
	d, ok := netconfDialectFor(&DeviceSimulator{resourceFile: "huawei_ne8000.json"})
	if !ok || d.Name != "vrp" || !d.SSH || d.TLS || d.CallHome || d.NewSession == nil {
		t.Fatalf("huawei_ne8000 = %+v, %v; want vrp over SSH only", d, ok)
	}
}
