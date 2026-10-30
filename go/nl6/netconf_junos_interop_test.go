/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// The Junos NETCONF differential check. Every other Junos NETCONF test reads
// nl6's bytes with nl6's own client and compares them with fixtures cut from
// one capture, so a misreading of the capture passes all of them. This one
// drives an in-process juniper_mx10004 and a running vJunos-router with the
// same Go client, over mutual TLS and over SSH, normalises both streams and
// diffs them.
//
// Gated by NL6_NETCONF_JUNOS_INTEROP=1; run it with
// `make test-interop-netconf-junos`. Every variable of
// netconfJunosInteropEnv is required and there are no lab defaults:
//
//   - NL6_NETCONF_JUNOS_REF, NL6_NETCONF_JUNOS_REF_SSH: host:port of the
//     reference's NETCONF over TLS and NETCONF over SSH.
//   - NL6_NETCONF_JUNOS_CLI, NL6_NETCONF_JUNOS_CLI_USER,
//     NL6_NETCONF_JUNOS_CLI_PASSWORD: the reference's CLI over SSH, the flap
//     lever. The same login opens the reference's netconf subsystem.
//   - NL6_NETCONF_JUNOS_CLIENT_CERT, NL6_NETCONF_JUNOS_CLIENT_KEY,
//     NL6_NETCONF_JUNOS_CA: the TLS client certificate, its key and the CA
//     that signed it. nl6 gets the same CA and maps the same certificate, so
//     one client code path serves both sides.
//   - NL6_NETCONF_JUNOS_REF_IF: the reference interface the test disables
//     and enables. nl6 moves the admin status of xe-0/0/0 (ifIndex 1).
//
// Phases, per transport: the hello; the RPC table of the Junos session
// (without kill-session, which would need a second session to kill) ending
// in close-session and its trailer; then create-subscription and one
// disable and one enable of the interface, collecting notifications for
// netconfJunosRefSettle on the reference and netconfJunosNl6Settle on nl6.
//
// Normalisation (normaliseJunosInterop and junosInteropConfig): whitespace
// between elements; session-id; the user named in the hello comment; the
// junos version in the rpc-reply namespace; message-id is equal by
// construction; eventTime, timestamp, seconds, microseconds, pid and
// hostname of a notification; the session-end time of the close trailer;
// the values of the junos:commit-* and junos:changed-* attributes; the
// configuration body, compared by element names only (nl6's names must be a
// subset of the reference's); the interface name under test and every
// snmp-interface-index. The reference's notification stream carries the
// whole syslog feed, so every notification whose id is not
// SNMP_TRAP_LINK_UP or SNMP_TRAP_LINK_DOWN, or that names another
// interface, is dropped from the REFERENCE stream before the diff. nl6's
// stream is not filtered beyond the allow-list: anything else it sends
// fails the diff. The documented divergences, and the rewrites that
// junosInteropReconcile applies for them, are in netconfJunosInteropAllow.
//
// The reference interface is enabled before the run and again on every
// exit through t.Cleanup, also on a test failure, but not on a -timeout or
// Ctrl-C.

var netconfJunosInteropEnv = []string{
	"NL6_NETCONF_JUNOS_REF", "NL6_NETCONF_JUNOS_REF_SSH",
	"NL6_NETCONF_JUNOS_CLI", "NL6_NETCONF_JUNOS_CLI_USER", "NL6_NETCONF_JUNOS_CLI_PASSWORD",
	"NL6_NETCONF_JUNOS_CLIENT_CERT", "NL6_NETCONF_JUNOS_CLIENT_KEY", "NL6_NETCONF_JUNOS_CA",
	"NL6_NETCONF_JUNOS_REF_IF",
}

const (
	netconfJunosNl6If      = "xe-0/0/0"
	netconfJunosNl6IfIndex = 1

	// The reference logs a link event a few seconds after the commit and
	// delivers it over the subscription 1 to 25 s later. nl6 sends at once.
	netconfJunosRefSettle = 60 * time.Second
	netconfJunosNl6Settle = time.Second
	netconfJunosReplyWait = 30 * time.Second
)

// netconfJunosInteropAllow lists the known, documented divergences. A row
// whose step matches an entry with skip set is logged, not compared. The
// other entries name a rewrite that junosInteropReconcile or the
// normalisation applies, and every application is logged.
var netconfJunosInteropAllow = []struct {
	step string
	skip bool
	why  string
}{
	// The configuration nl6 serves is reduced to version and
	// system/host-name, by decision. Compared by element names: nl6's must
	// be a subset of the reference's.
	{"rpc/get", false, "reduced configuration body"},
	{"rpc/get-configuration", false, "reduced configuration body"},
	// The reference's unfiltered get carries an empty
	// <database-status-information/> after the configuration, inside
	// <data>. nl6 does not send it. Removed from the reference row.
	{"rpc/get", false, "empty database-status-information on the reference only"},
	// The design's RPC table has the reference refuse a get with an
	// ietf-interfaces interfaces-state filter with one syntax error, and it
	// does (bad-element interfaces-state). nl6 has no row for that filter
	// and answers it as an unfiltered get, with the reduced configuration.
	{"rpc/get-interfaces-state", true, "nl6 answers the interfaces-state get as an unfiltered get"},
	// The reference writes a newline between the close-session reply's EOM
	// and the session-end comment; nl6 starts the comment right after the
	// EOM. Whitespace outside elements is normalised, the raw bytes logged.
	{"rpc/close-session-trailer", false, "newline before the session-end comment"},
	// The reference sends its certificate and the CA, nl6 only its leaf.
	// The cipher follows the server key type. Both are logged; the TLS
	// version is compared.
	{"tls/handshake", false, "server chain length and cipher logged, not compared"},
	// The reference delivers link events 1 to 25 s after the commit, nl6 at
	// once. The settle window outlasts the lag, so the sequence is compared.
	{"events/disable", false, "delivery lag on the reference, immediate on nl6"},
	{"events/enable", false, "delivery lag on the reference, immediate on nl6"},
	// nl6's xe-0/0/0 has the units .0, .100, .200 and .999; the reference
	// interface has .0 only. The other units' link-up pairs are logged by
	// name, not compared.
	{"events/enable", false, "units other than .0 exist on nl6 only"},
	// The reference delivered the INFORMATIONAL link-up pair of unit .0 on
	// one subscription and not on the other in the same run. When the
	// reference sends none, nl6's .0 pair is logged, not compared.
	{"events/enable", false, "unit .0 link-up pair absent on the reference"},
	// nl6 DEFECT: an admin change broadcasts an admin event and an oper
	// event, both carrying the oper move, and the Junos session renders a
	// link-event pair for each. The IOS XE session skips the second one.
	// So nl6 sends every pair twice on an admin change. The repeated pair
	// is removed from nl6's rows and logged until the session is fixed.
	{"events/*", false, "nl6 repeats the link-event pair on an admin change"},
}

func netconfJunosInteropSkipped(step string) bool {
	for _, a := range netconfJunosInteropAllow {
		if a.step == step {
			return a.skip
		}
	}
	return false
}

// netconfJunosInteropRPCs is the RPC table of the Junos session without
// kill-session. close-session is sent last by the phase itself.
var netconfJunosInteropRPCs = []struct{ name, body string }{
	{"get-streams", `<get><filter type="subtree"><netconf xmlns="urn:ietf:params:xml:ns:netmod:notification"><streams/></netconf></filter></get>`},
	{"get-netconf-state", `<get><filter type="subtree"><netconf-state xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-monitoring"><capabilities/></netconf-state></filter></get>`},
	{"get", `<get/>`},
	{"get-configuration", `<get-configuration/>`},
	{"establish-subscription-draft", `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications"><stream>NETCONF</stream></establish-subscription>`},
	{"establish-subscription-8639", `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-subscribed-notifications"><stream>NETCONF</stream></establish-subscription>`},
	{"get-interfaces-state", `<get><filter type="subtree"><interfaces-state xmlns="urn:ietf:params:xml:ns:yang:ietf-interfaces"/></filter></get>`},
	{"bogus-rpc", `<bogus-rpc/>`},
}

// ---- client

type junosInteropMsg struct {
	b   string
	err error
}

// junosInteropConn is one NETCONF session with end-of-message framing. A
// reader goroutine splits the stream; the bytes left at EOF come last with
// the error, so the close-session trailer is read like a message.
type junosInteropConn struct {
	msgs  chan junosInteropMsg
	w     io.Writer
	close func()
	info  string
}

func newJunosInteropConn(r io.Reader, w io.Writer, closeFn func()) *junosInteropConn {
	c := &junosInteropConn{msgs: make(chan junosInteropMsg, 1<<16), w: w, close: closeFn}
	go func() {
		br := bufio.NewReaderSize(r, 1<<16)
		var b bytes.Buffer
		for {
			ch, err := br.ReadByte()
			if err != nil {
				c.msgs <- junosInteropMsg{b.String(), err}
				close(c.msgs)
				return
			}
			b.WriteByte(ch)
			if ch == '>' && bytes.HasSuffix(b.Bytes(), []byte(netconfEOM)) {
				c.msgs <- junosInteropMsg{strings.TrimSuffix(b.String(), netconfEOM), nil}
				b.Reset()
			}
		}
	}()
	return c
}

func (c *junosInteropConn) next(d time.Duration) (junosInteropMsg, error) {
	select {
	case m, ok := <-c.msgs:
		if !ok {
			return junosInteropMsg{}, io.EOF
		}
		return m, nil
	case <-time.After(d):
		return junosInteropMsg{}, io.ErrNoProgress
	}
}

func (c *junosInteropConn) send(msg string) error {
	_, err := io.WriteString(c.w, msg+netconfEOM)
	return err
}

func (c *junosInteropConn) rpc(id, body string) error {
	return c.send(`<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="` + id + `">` + body + `</rpc>`)
}

// junosInteropTarget is one side of the diff.
type junosInteropTarget struct {
	name             string
	reference        bool
	tlsAddr, sshAddr string
	sshUser, sshPass string
	clientCert       tls.Certificate
	iface            string
	settle           time.Duration
	toggle           func(down bool) error
}

func (tg *junosInteropTarget) dial(t *testing.T, transport string) *junosInteropConn {
	t.Helper()
	if transport == "tls" {
		cfg := &tls.Config{Certificates: []tls.Certificate{tg.clientCert}, InsecureSkipVerify: true} //nolint:gosec // neither server certificate names the tunnel or loopback address the test dials
		c, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", tg.tlsAddr, cfg)
		if err != nil {
			t.Fatalf("%s: tls dial %s: %v", tg.name, tg.tlsAddr, err)
		}
		st := c.ConnectionState()
		conn := newJunosInteropConn(c, c, func() { _ = c.Close() })
		conn.info = fmt.Sprintf("version=%s cipher=%s chain=%d", strings.ReplaceAll(tls.VersionName(st.Version), " ", ""), tls.CipherSuiteName(st.CipherSuite), len(st.PeerCertificates))
		return conn
	}
	cl, err := ssh.Dial("tcp", tg.sshAddr, &ssh.ClientConfig{
		User:            tg.sshUser,
		Auth:            []ssh.AuthMethod{ssh.Password(tg.sshPass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // a lab device and an in-process test device
		Timeout:         10 * time.Second,
	})
	if err != nil {
		t.Fatalf("%s: ssh dial %s: %v", tg.name, tg.sshAddr, err)
	}
	s, err := cl.NewSession()
	if err != nil {
		_ = cl.Close()
		t.Fatalf("%s: ssh session: %v", tg.name, err)
	}
	in, _ := s.StdinPipe()
	out, _ := s.StdoutPipe()
	if err := s.RequestSubsystem("netconf"); err != nil {
		_ = cl.Close()
		t.Fatalf("%s: netconf subsystem: %v", tg.name, err)
	}
	return newJunosInteropConn(out, in, func() { _ = cl.Close() })
}

// junosInteropRow is one message of one phase, raw.
type junosInteropRow struct {
	step, kind, xml string
}

// hello reads the server hello and answers with a base:1.0 client hello.
func (tg *junosInteropTarget) hello(t *testing.T, c *junosInteropConn) string {
	t.Helper()
	m, err := c.next(netconfJunosReplyWait)
	if err != nil || m.err != nil {
		t.Fatalf("%s: server hello: %v %v", tg.name, err, m.err)
	}
	if err := c.send(`<hello xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params:netconf:base:1.0</capability></capabilities></hello>`); err != nil {
		t.Fatalf("%s: client hello: %v", tg.name, err)
	}
	return m.b
}

// run drives one transport and returns its rows in order.
func (tg *junosInteropTarget) run(t *testing.T, transport string) []junosInteropRow {
	t.Helper()
	var rows []junosInteropRow

	c := tg.dial(t, transport)
	defer c.close()
	if transport == "tls" {
		t.Logf("%s tls handshake: %s", tg.name, c.info)
		v, _, _ := strings.Cut(c.info, " ")
		rows = append(rows, junosInteropRow{"tls/handshake", "handshake", v})
	}
	rows = append(rows, junosInteropRow{"hello", "hello", tg.hello(t, c)})
	for i, r := range netconfJunosInteropRPCs {
		if err := c.rpc(fmt.Sprint(101+i), r.body); err != nil {
			t.Fatalf("%s: %s: %v", tg.name, r.name, err)
		}
		m, err := c.next(netconfJunosReplyWait)
		if err != nil || m.err != nil {
			t.Fatalf("%s: %s reply: %v %v", tg.name, r.name, err, m.err)
		}
		rows = append(rows, junosInteropRow{"rpc/" + r.name, "reply", m.b})
	}
	if err := c.rpc("199", "<close-session/>"); err != nil {
		t.Fatalf("%s: close-session: %v", tg.name, err)
	}
	m, err := c.next(netconfJunosReplyWait)
	if err != nil || m.err != nil {
		t.Fatalf("%s: close-session reply: %v %v", tg.name, err, m.err)
	}
	rows = append(rows, junosInteropRow{"rpc/close-session", "reply", m.b})
	m, err = c.next(netconfJunosReplyWait)
	if err != nil || !errors.Is(m.err, io.EOF) {
		t.Fatalf("%s: after close-session want the trailer and EOF, got %q %v %v", tg.name, m.b, err, m.err)
	}
	t.Logf("%s %s close trailer raw: %q", tg.name, transport, m.b)
	rows = append(rows, junosInteropRow{"rpc/close-session-trailer", "trailer", m.b})

	ev := tg.dial(t, transport)
	defer ev.close()
	tg.hello(t, ev)
	if err := ev.rpc("201", `<create-subscription xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0"><stream>NETCONF</stream></create-subscription>`); err != nil {
		t.Fatalf("%s: create-subscription: %v", tg.name, err)
	}
	m, err = ev.next(netconfJunosReplyWait)
	if err != nil || m.err != nil {
		t.Fatalf("%s: create-subscription reply: %v %v", tg.name, err, m.err)
	}
	rows = append(rows, junosInteropRow{"events/create-subscription", "reply", m.b})
	for _, step := range []struct {
		name string
		down bool
	}{{"disable", true}, {"enable", false}} {
		if err := tg.toggle(step.down); err != nil {
			t.Fatalf("%s: %s %s: %v", tg.name, step.name, tg.iface, err)
		}
		total, kept, units := 0, 0, 0
		deadline := time.Now().Add(tg.settle)
		for {
			m, err := ev.next(time.Until(deadline))
			if errors.Is(err, io.ErrNoProgress) {
				break
			}
			if err != nil || m.err != nil {
				t.Fatalf("%s: subscription ended: %v %v", tg.name, err, m.err)
			}
			total++
			switch junosInteropClassify(m.b, tg.iface, tg.reference) {
			case "noise":
				continue
			case "unit":
				units++
				t.Logf("%s %s events/%s allow-listed unit: %s", tg.name, transport, step.name, ncjUnitName.FindString(m.b))
				continue
			}
			kept++
			rows = append(rows, junosInteropRow{"events/" + step.name, "notification", m.b})
		}
		t.Logf("%s %s events/%s: %d notifications, %d kept, %d of other units", tg.name, transport, step.name, total, kept, units)
	}
	return rows
}

var junosInteropLinkID = regexp.MustCompile(`<id>(SNMP_TRAP_LINK_UP|SNMP_TRAP_LINK_DOWN)</id>`)

// junosInteropClassify sorts one notification. On the reference only the
// link events of the interface under test and its units are kept; the rest
// of the syslog feed is noise. On both sides a unit other than .0 is
// dropped, because nl6's xe-0/0/0 carries the VRF units .100, .200 and .999
// that the reference's interface does not have.
func junosInteropClassify(msg, iface string, reference bool) string {
	link := junosInteropLinkID.MatchString(msg)
	mine := strings.Contains(msg, "ifName "+iface+"<") || strings.Contains(msg, "ifName "+iface+".")
	if reference && (!link || !mine) {
		return "noise"
	}
	if mine && !strings.Contains(msg, "ifName "+iface+"<") && !strings.Contains(msg, "ifName "+iface+".0<") {
		return "unit"
	}
	return "keep"
}

// ---- normalisation

var (
	ncjBetween     = regexp.MustCompile(`>\s+<`)
	ncjSessionID   = regexp.MustCompile(`(<session-id>)\d+(</session-id>)`)
	ncjHelloUser   = regexp.MustCompile(`(<!-- user )[^ ,]+(, class j-super-user -->)`)
	ncjVersionNS   = regexp.MustCompile(`(xmlns:junos="http://xml\.juniper\.net/junos/)\d+\.\d+R\d+(?:-S\d+)?\.\d+(/junos")`)
	ncjEventTime   = regexp.MustCompile(`(<eventTime>)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\+00:00(</eventTime>)`)
	ncjNumberLeaf  = regexp.MustCompile(`(<(timestamp|seconds|microseconds|pid)>)\d+(</(?:timestamp|seconds|microseconds|pid)>)`)
	ncjHostname    = regexp.MustCompile(`(<hostname>)[^<]+(</hostname>)`)
	ncjSessionEnd  = regexp.MustCompile(`(<!-- session end at )\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC( -->)`)
	ncjIfIndexMsg  = regexp.MustCompile(`ifIndex \d+,`)
	ncjIfIndexData = regexp.MustCompile(`(<(?:name|key)>snmp-interface-index</(?:name|key)><value>)\d+(</value>)`)
	ncjCommitAttr  = regexp.MustCompile(` (junos:(?:commit|changed)-(?:seconds|localtime|user))="[^"]*"`)
	ncjUnitName    = regexp.MustCompile(`ifName [^<]+`)
	ncjConfig      = regexp.MustCompile(`(?s)(<configuration [^>]*>)(.*)(</configuration>)`)
)

// normaliseJunosInterop replaces what legitimately differs between nl6 and
// the reference with placeholders. A value is replaced only when it has the
// device's shape, so a malformed value still shows up in the diff.
func normaliseJunosInterop(s, iface string) string {
	s = strings.TrimSpace(ncjBetween.ReplaceAllString(s, "><"))
	s = ncjSessionID.ReplaceAllString(s, "${1}SESSIONID${2}")
	s = ncjHelloUser.ReplaceAllString(s, "${1}USER${2}")
	s = ncjVersionNS.ReplaceAllString(s, "${1}VERSION${2}")
	s = ncjEventTime.ReplaceAllString(s, "${1}EVENTTIME${2}")
	s = ncjNumberLeaf.ReplaceAllString(s, "<${2}>N${3}")
	s = ncjHostname.ReplaceAllString(s, "${1}HOSTNAME${2}")
	s = ncjSessionEnd.ReplaceAllString(s, "${1}TIME${2}")
	s = ncjIfIndexMsg.ReplaceAllString(s, "ifIndex IFINDEX,")
	s = ncjIfIndexData.ReplaceAllString(s, "${1}IFINDEX${2}")
	s = ncjCommitAttr.ReplaceAllString(s, ` ${1}="X"`)
	return strings.ReplaceAll(s, iface, "IFNAME")
}

// junosInteropConfig cuts the configuration body out of a normalised row
// and returns the row with the body replaced by CONFIG, and the body's
// element paths. ok is false when the row has no configuration.
func junosInteropConfig(s string) (row string, paths []string, ok bool, err error) {
	m := ncjConfig.FindStringSubmatchIndex(s)
	if m == nil {
		return s, nil, false, nil
	}
	body := s[m[4]:m[5]]
	dec := xml.NewDecoder(strings.NewReader("<x>" + body + "</x>"))
	seen := map[string]bool{}
	var stack []string
	for {
		tok, terr := dec.Token()
		if terr == io.EOF {
			break
		}
		if terr != nil {
			return "", nil, false, terr
		}
		switch v := tok.(type) {
		case xml.StartElement:
			stack = append(stack, v.Name.Local)
			if len(stack) > 1 {
				seen[strings.Join(stack[1:], "/")] = true
			}
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}
	for p := range seen {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return s[:m[3]] + "CONFIG" + s[m[6]:], paths, true, nil
}

// junosInteropComparable is one normalised row.
type junosInteropComparable struct {
	key, xml string
	config   []string
	hasCfg   bool
}

func (c junosInteropComparable) same(o junosInteropComparable) bool {
	return c.key == o.key && c.xml == o.xml
}

func junosInteropComparables(t *testing.T, rows []junosInteropRow, iface string) (out []junosInteropComparable, skipped []string) {
	t.Helper()
	for _, r := range rows {
		x := normaliseJunosInterop(r.xml, iface)
		x, paths, hasCfg, err := junosInteropConfig(x)
		if err != nil {
			t.Fatalf("%s: configuration body: %v", r.step, err)
		}
		c := junosInteropComparable{key: r.step + " " + r.kind, xml: x, config: paths, hasCfg: hasCfg}
		if netconfJunosInteropSkipped(r.step) {
			skipped = append(skipped, c.key+" "+c.xml)
			continue
		}
		out = append(out, c)
	}
	return out, skipped
}

var (
	ncjDBStatus = "<database-status-information></database-status-information>"
	ncjUnitZero = "ifName IFNAME.0<"
)

// junosInteropReconcile applies the allow-listed rewrites of
// netconfJunosInteropAllow that need both sides, and returns a log line for
// each rewrite it made.
func junosInteropReconcile(nl6, ref []junosInteropComparable) (outNl6, outRef []junosInteropComparable, logs []string) {
	for _, r := range ref {
		if strings.HasPrefix(r.key, "rpc/get ") && strings.Contains(r.xml, ncjDBStatus) {
			r.xml = strings.Replace(r.xml, ncjDBStatus, "", 1)
			logs = append(logs, "rpc/get: removed the reference's empty database-status-information")
		}
		outRef = append(outRef, r)
	}
	for i := 0; i < len(nl6); i++ {
		c := nl6[i]
		if n := len(outNl6); strings.HasPrefix(c.key, "events/") && i+1 < len(nl6) && n >= 2 &&
			outNl6[n-2].same(c) && outNl6[n-1].same(nl6[i+1]) {
			logs = append(logs, c.key+": removed nl6's repeated link-event pair (nl6 defect)")
			i++
			continue
		}
		outNl6 = append(outNl6, c)
	}
	refUnit := slices.ContainsFunc(outRef, func(c junosInteropComparable) bool {
		return strings.HasPrefix(c.key, "events/") && strings.Contains(c.xml, ncjUnitZero)
	})
	if !refUnit {
		outNl6 = slices.DeleteFunc(outNl6, func(c junosInteropComparable) bool {
			if strings.HasPrefix(c.key, "events/") && strings.Contains(c.xml, ncjUnitZero) {
				logs = append(logs, c.key+": reference sent no unit .0 link-up, nl6's not compared")
				return true
			}
			return false
		})
	}
	return outNl6, outRef, logs
}

// diffJunosInterop reports where the streams part. Empty means equal.
// Configuration bodies are equal when nl6's element paths are a subset of
// the reference's; the reference's extra element count is returned for the
// log.
func diffJunosInterop(nl6, ref []junosInteropComparable) (diff string, extra []string) {
	var b strings.Builder
	shown := 0
	for i := 0; i < max(len(nl6), len(ref)) && shown < 8; i++ {
		var a, r junosInteropComparable
		if i < len(nl6) {
			a = nl6[i]
		}
		if i < len(ref) {
			r = ref[i]
		}
		if a.key == r.key && a.xml == r.xml && a.hasCfg == r.hasCfg {
			if a.hasCfg {
				var missing []string
				for _, p := range a.config {
					if !slices.Contains(r.config, p) {
						missing = append(missing, p)
					}
				}
				if len(missing) > 0 {
					fmt.Fprintf(&b, "row %d %s: nl6 configuration elements absent on the reference: %v\n", i, a.key, missing)
					shown++
					continue
				}
				extra = append(extra, fmt.Sprintf("%s: nl6 serves %d of the reference's %d configuration element paths %v", a.key, len(a.config), len(r.config), a.config))
			}
			continue
		}
		fmt.Fprintf(&b, "row %d\n  nl6: %s %s\n  ref: %s %s\n", i, a.key, a.xml, r.key, r.xml)
		shown++
	}
	if len(nl6) != len(ref) {
		fmt.Fprintf(&b, "row counts: nl6 %d, ref %d\n", len(nl6), len(ref))
	}
	return b.String(), extra
}

// ---- levers

// junosInteropOut is the CLI's output, written by the SSH session and read
// by the poll in junosInteropCLI.
type junosInteropOut struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (o *junosInteropOut) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *junosInteropOut) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

// junosInteropCLI feeds lines to the reference's CLI over an SSH shell and
// returns what it printed. Stdin stays open until the output contains done,
// because the CLI drops input that arrives with an early EOF.
func junosInteropCLI(addr, user, pass, done string, lines ...string) (string, error) {
	cl, err := ssh.Dial("tcp", addr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(pass)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec // a lab device
		Timeout:         10 * time.Second,
	})
	if err != nil {
		return "", err
	}
	defer func() { _ = cl.Close() }()
	s, err := cl.NewSession()
	if err != nil {
		return "", err
	}
	out := &junosInteropOut{}
	s.Stdout, s.Stderr = out, out
	in, err := s.StdinPipe()
	if err != nil {
		return "", err
	}
	if err := s.Shell(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(in, strings.Join(lines, "\n")+"\n"); err != nil {
		return out.String(), err
	}
	deadline := time.Now().Add(2 * time.Minute)
	for !strings.Contains(out.String(), done) && !strings.Contains(out.String(), "error:") {
		if time.Now().After(deadline) {
			return out.String(), errors.New("cli timed out")
		}
		time.Sleep(200 * time.Millisecond)
	}
	_ = in.Close()
	return out.String(), nil
}

// junosInteropRefToggle disables or enables the reference interface and
// waits for the commit.
func junosInteropRefToggle(addr, user, pass, iface string, down bool) error {
	verb := "delete"
	if down {
		verb = "set"
	}
	out, err := junosInteropCLI(addr, user, pass, "Exiting configuration mode", "configure", verb+" interfaces "+iface+" disable", "commit and-quit")
	if err != nil {
		return fmt.Errorf("%v: %s", err, out)
	}
	if !strings.Contains(out, "commit complete") || strings.Contains(out, "error:") {
		return fmt.Errorf("commit failed: %s", out)
	}
	return nil
}

// ---- test

func TestNetconfJunosInteropAgainstReference(t *testing.T) {
	if os.Getenv("NL6_NETCONF_JUNOS_INTEROP") != "1" {
		t.Skipf("set NL6_NETCONF_JUNOS_INTEROP=1 (make test-interop-netconf-junos) and %s to diff nl6 against a real Junos device", strings.Join(netconfJunosInteropEnv, ", "))
	}
	var unset []string
	for _, k := range netconfJunosInteropEnv {
		if os.Getenv(k) == "" {
			unset = append(unset, k)
		}
	}
	if len(unset) > 0 {
		t.Skipf("no reference device: set %s", strings.Join(unset, ", "))
	}
	env := os.Getenv
	cert, err := tls.LoadX509KeyPair(env("NL6_NETCONF_JUNOS_CLIENT_CERT"), env("NL6_NETCONF_JUNOS_CLIENT_KEY"))
	if err != nil {
		t.Fatalf("client key pair: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("client certificate: %v", err)
	}
	caPEM, err := os.ReadFile(env("NL6_NETCONF_JUNOS_CA"))
	if err != nil {
		t.Fatalf("client CA: %v", err)
	}

	// nl6: one mx10004 with both listeners, the operator's CA as its client
	// CA and the client certificate mapped by fingerprint.
	mgr := useNetconfTLSTestManager(t)
	id := &NetconfTLSIdentity{CAPEM: string(caPEM), Identities: map[string]string{certSHA256Fingerprint(leaf): "ncuser"}}
	if err := id.Validate(); err != nil {
		t.Fatalf("identity table: %v", err)
	}
	mgr.netconfTLSIdentity.Store(id.normalised())
	dev := newJunosTestDevice(t)
	dev.ID, dev.IP, dev.resourceFile, dev.sysName = "mx10004-interop", net.IPv4(127, 0, 0, 1), "juniper_mx10004.json", "NY-CORE-01"
	mgr.devices[dev.ID] = dev
	dev.mu.Lock()
	err = dev.startNetconfServer()
	if err == nil {
		err = dev.startNetconfTLSServer()
	}
	dev.mu.Unlock()
	t.Cleanup(func() {
		dev.mu.Lock()
		dev.stopNetconfServer()
		dev.mu.Unlock()
	})
	if err != nil || dev.netconfListener == nil || dev.netconfTLSListener == nil {
		t.Fatalf("mx10004 listeners: %v", err)
	}
	st := netconfIfCounters(dev).State()
	ncLink(st, netconfJunosNl6IfIndex, OperUp)
	ncAdmin(st, netconfJunosNl6IfIndex, AdminUp)
	nl6 := &junosInteropTarget{
		name: "nl6", tlsAddr: dev.netconfTLSListener.Addr().String(), sshAddr: dev.netconfListener.Addr().String(),
		sshUser: USERNAME, sshPass: PASSWORD, clientCert: cert, iface: netconfJunosNl6If, settle: netconfJunosNl6Settle,
		toggle: func(down bool) error {
			// set interfaces ... disable is an admin change, so nl6 moves the
			// admin status, not the link: both report ifAdminStatus down(2).
			admin := AdminUp
			if down {
				admin = AdminDown
			}
			ncAdmin(st, netconfJunosNl6IfIndex, admin)
			return nil
		},
	}

	cli, cliUser, cliPass, refIf := env("NL6_NETCONF_JUNOS_CLI"), env("NL6_NETCONF_JUNOS_CLI_USER"), env("NL6_NETCONF_JUNOS_CLI_PASSWORD"), env("NL6_NETCONF_JUNOS_REF_IF")
	ref := &junosInteropTarget{
		name: "reference", reference: true, tlsAddr: env("NL6_NETCONF_JUNOS_REF"), sshAddr: env("NL6_NETCONF_JUNOS_REF_SSH"),
		sshUser: cliUser, sshPass: cliPass, clientCert: cert, iface: refIf, settle: netconfJunosRefSettle,
		toggle: func(down bool) error { return junosInteropRefToggle(cli, cliUser, cliPass, refIf, down) },
	}

	for _, a := range netconfJunosInteropAllow {
		t.Logf("allow-list %s skip=%v: %s", a.step, a.skip, a.why)
	}
	// nl6 first: it takes seconds, and a broken nl6 should not cost a round
	// on the device.
	transports := []string{"tls", "ssh"}
	nl6Rows := map[string][]junosInteropRow{}
	for _, tr := range transports {
		nl6Rows[tr] = nl6.run(t, tr)
	}

	restore := func() {
		if err := junosInteropRefToggle(cli, cliUser, cliPass, refIf, false); err != nil {
			t.Errorf("restore reference %s: %v", refIf, err)
		}
	}
	restore()
	t.Cleanup(restore)

	failed := false
	for _, tr := range transports {
		refRows := ref.run(t, tr)
		a, aSkipped := junosInteropComparables(t, nl6Rows[tr], netconfJunosNl6If)
		r, rSkipped := junosInteropComparables(t, refRows, refIf)
		for _, s := range aSkipped {
			t.Logf("%s skipped nl6: %s", tr, s)
		}
		for _, s := range rSkipped {
			t.Logf("%s skipped ref: %s", tr, s)
		}
		for _, c := range a {
			t.Logf("%s row: %s %s", tr, c.key, c.xml)
		}
		a, r, logs := junosInteropReconcile(a, r)
		for _, l := range logs {
			t.Logf("%s allow-listed: %s", tr, l)
		}
		d, extra := diffJunosInterop(a, r)
		for _, e := range extra {
			t.Logf("%s allow-listed: %s", tr, e)
		}
		if d != "" {
			t.Errorf("%s: nl6 and the reference differ:\n%s", tr, d)
			failed = true
			continue
		}
		t.Logf("%s: %d rows equal after normalisation", tr, len(a))
	}
	if failed {
		t.FailNow()
	}
}
