/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The fixtures in testdata/netconf/junos are exact byte ranges of a vJunos
// 25.4R1.12 capture. Regenerate them from the capture directory with:
//
//	python3 -I gen.py <capture-dir> go/nl6/testdata/netconf/junos
//
// where gen.py is
//
//	C, OUT = sys.argv[1], sys.argv[2]
//	def read(n): return open(f"{C}/{n}.txt", "rb").read().decode()
//	def hello(n):
//	    t = read(n); a = t.index("raw:\n") + 5; b = t.index("\n# end server hello")
//	    return t[a:b]
//	def reply(n):
//	    m = "# rpc reply (err=<nil>):\n"
//	    t = read(n); a = t.index(m) + len(m); b = t.index("\n# end", a)
//	    return t[a:b]
//	def put(name, s): open(f"{OUT}/{name}", "wb").write(s.encode())
//	put("hello-p10.xml", hello("out-p10"))
//	put("syntax-error-bogus.xml", reply("out-rpc-bogus"))
//	put("syntax-error-estsub.xml", reply("out-rpc-estsub"))
//	put("get-streams-p11.xml", reply("out-p11"))
//	put("get-ncstate.xml", reply("out-rpc-ncstate"))
//	g = reply("out-rpc-get"); i = g.index("<configuration"); j = g.index("\n", i) + 1
//	put("get-config-head.xml", g[:j])
//	put("get-config-tail.xml", g[g.index("</data>\n</rpc-reply>\n"):])
//	p = reply("out-p1-rsa"); i = p.index("<configuration"); j = p.index("\n", i) + 1
//	put("get-configuration-head.xml", p[:j])
//	put("get-configuration-tail.xml", p[p.index("</rpc-reply>\n"):])
//
// The capture reports 25.4R1.12. The commit and change times in the head
// fixtures are 1793379138 and 1793378977.
const junosCaptureVersion = "25.4R1.12"

func junosFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "netconf", "junos", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJunosVersionFromSysDescr(t *testing.T) {
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		t.Fatal(err)
	}
	if got := junosVersion(&DeviceSimulator{resources: res}); got != "24.2R1.17" {
		t.Errorf("junosVersion = %q, want 24.2R1.17", got)
	}
	if got := junosVersion(&DeviceSimulator{}); got != "" {
		t.Errorf("junosVersion without resources = %q, want empty", got)
	}
	if got := junosVersion(&DeviceSimulator{resources: &DeviceResources{}}); got != "" {
		t.Errorf("junosVersion without sysDescr = %q, want empty", got)
	}
}

func TestJunosHelloBytes(t *testing.T) {
	got := string(junosServerHello(22853, "ncuser"))
	if want := junosFixture(t, "hello-p10.xml"); got != want {
		t.Errorf("hello differs from capture\n got: %q\nwant: %q", got, want)
	}
}

func TestJunosSyntaxErrorBytes(t *testing.T) {
	if got, want := string(junosSyntaxError(junosCaptureVersion, "101", "bogus-rpc", 1)), junosFixture(t, "syntax-error-bogus.xml"); got != want {
		t.Errorf("repeat 1 differs\n got: %q\nwant: %q", got, want)
	}
	if got, want := string(junosSyntaxError(junosCaptureVersion, "101", "establish-subscription", 2)), junosFixture(t, "syntax-error-estsub.xml"); got != want {
		t.Errorf("repeat 2 differs\n got: %q\nwant: %q", got, want)
	}
}

func TestJunosGetReplies(t *testing.T) {
	v := junosCaptureVersion
	if got, want := string(junosStreamsReply(v, "101")), junosFixture(t, "get-streams-p11.xml"); got != want {
		t.Errorf("streams reply differs\n got: %q\nwant: %q", got, want)
	}
	if got, want := string(junosNetconfStateReply(v, "101")), junosFixture(t, "get-ncstate.xml"); got != want {
		t.Errorf("netconf-state reply differs\n got: %q\nwant: %q", got, want)
	}
	wantOK := "\n<rpc-reply xmlns:junos=\"http://xml.juniper.net/junos/25.4R1.12/junos\" xmlns=\"urn:ietf:params:xml:ns:netconf:base:1.0\" message-id=\"102\">\n<ok/>\n</rpc-reply>\n"
	if got := string(junosOKReply(v, "102")); got != wantOK {
		t.Errorf("ok reply = %q, want %q", got, wantOK)
	}

	dev := &DeviceSimulator{sysName: "r1"}
	body := "    <version>25.4R1.12</version>\n    <system>\n        <host-name>r1</host-name>\n    </system>\n</configuration>\n"

	commit := time.Unix(1793379138, 0).UTC()
	got := string(junosGetReply(dev, v, "101", commit))
	want := junosFixture(t, "get-config-head.xml") + body + junosFixture(t, "get-config-tail.xml")
	if got != want {
		t.Errorf("get reply differs\n got: %q\nwant: %q", got, want)
	}

	changed := time.Unix(1793378977, 0).UTC()
	got = string(junosGetConfigurationReply(dev, v, "101", changed))
	want = junosFixture(t, "get-configuration-head.xml") + body + junosFixture(t, "get-configuration-tail.xml")
	if got != want {
		t.Errorf("get-configuration reply differs\n got: %q\nwant: %q", got, want)
	}
	if n := strings.Count(got, "<version>") + strings.Count(got, "<host-name>"); n != 2 {
		t.Errorf("reduced body has %d version/host-name elements, want 2", n)
	}
}
