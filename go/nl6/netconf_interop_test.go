/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The NETCONF differential check. Every other NETCONF test reads nl6's bytes
// with nl6's own client, so a shared misreading of the IOS XE dialect passes
// all of them. This one runs scripts/netconf-probe.py (paramiko, raw RFC 6242
// framing) against an in-process cisco_catalyst_9500 and against a real
// IOS XE device, normalises both streams and diffs them.
//
// Gated by NL6_NETCONF_INTEROP=1; run it with `make test-interop-netconf`.
// The reference is NL6_NETCONF_REF (host), NL6_NETCONF_REF_USER (default
// admin) and NL6_NETCONF_REF_PASSWORD. Its carrier is toggled through
// Proxmox: NL6_NETCONF_REF_PVE is the ssh target of the Proxmox host,
// NL6_NETCONF_REF_VMID the VM and NL6_NETCONF_REF_NIC the `qm set --net1`
// spec of its second NIC. Its admin state is toggled through native-config
// shutdown. The test skips when any of these is unset. There are no lab
// defaults.

const (
	netconfInteropNl6If = "GigabitEthernet1/0/24"
	netconfInteropNl6Ix = 24
	netconfInteropRefIf = "GigabitEthernet2"

	netconfInteropRefUser = "admin"

	// The c8000v reports a carrier change within about 10 s and needs
	// 11 s after no shutdown to report ready. nl6 answers at once.
	netconfInteropRefSettle = "30"
	netconfInteropRefQuiet  = "2"
	netconfInteropNl6Settle = "1"
	netconfInteropNl6Quiet  = "0.5"
)

// netconfInteropAllow lists the known, documented divergences. A row whose
// phase and step match an entry with skip set is logged but not compared.
var netconfInteropAllow = []struct {
	phase, step string
	skip        bool
	why         string
}{
	// (a) After no shutdown the c8000v sends invalid and lower-layer-down at
	// once and ready about 11 s later (VM link negotiation). nl6 sends ready
	// immediately, by decision. The settle window outlasts the gap, so the
	// SEQUENCE is still compared; only the timing differs.
	{"events", "admin-up", false, "ready timing after no shutdown"},
	// (b) The device accepts a periodic subscription and RFC 5277
	// create-subscription. Both are out of scope for nl6, which refuses
	// them (error-no-such-option and operation-not-supported).
	{"period", "sub-period", true, "periodic subscription refused by nl6"},
	{"create-subscription", "create-subscription", true, "create-subscription refused by nl6"},
	// (c) nl6 caps a session at 256 subscriptions (error-other on the
	// 257th). The c8000v caps subscriptions at about 128 per DEVICE: it
	// answered error-insufficient-resources from the 126th. The Cat9300
	// accepted 150 on one session (cat9k-sandbox edges.out, MANY_ACCEPTED
	// 150), so the c8000v limit is not the IOS XE rule. A dropped
	// session's subscriptions stay in that pool, and pushing to them
	// crashed the device's telemetry process. This test must never send
	// more than a handful of subscriptions per run, so the cap row is not
	// sent; this entry records the divergence.
	{"cap", "sub-257", true, "subscription cap: nl6 256 per session, c8000v about 125"},
}

func netconfInteropSkipped(phase, step string) bool {
	for _, a := range netconfInteropAllow {
		if a.phase == phase && a.step == step {
			return a.skip
		}
	}
	return false
}

type netconfProbeLine struct {
	Phase string `json:"phase"`
	Step  string `json:"step"`
	Kind  string `json:"kind"`
	XML   string `json:"xml"`
}

// netconfProbeTarget is one side of the diff.
type netconfProbeTarget struct {
	name, host, port, user, password, iface string
	// quiet ends a reply row after that many seconds without a message;
	// settle is how long to collect after each toggle.
	quiet, settle string
	toggle        func(action string) error
}

func netconfProbeScript(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "scripts", "netconf-probe.py"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("probe script: %v", err)
	}
	return p
}

// netconfProbeCmd runs the probe. The password goes to the probe in its
// environment (NETCONF_PROBE_PASSWORD), never on argv, where any local
// user could read it from the process list.
func netconfProbeCmd(script string, tg netconfProbeTarget, args ...string) *exec.Cmd {
	base := []string{"run", "-q", "--with", "ncclient==0.7.1", "python", "-I", script,
		"--host", tg.host, "--port", tg.port, "--user", tg.user, "--interface", tg.iface}
	cmd := exec.Command("uv", append(base, args...)...)
	cmd.Env = append(os.Environ(), "NETCONF_PROBE_PASSWORD="+tg.password)
	return cmd
}

// runNetconfProbe runs the probe against one target, answers its toggle
// requests and returns every reply and notification line.
func runNetconfProbe(t *testing.T, script string, tg netconfProbeTarget) []netconfProbeLine {
	t.Helper()
	cmd := netconfProbeCmd(script, tg, "--quiet", tg.quiet, "--settle", tg.settle, "run")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start probe: %v", err)
	}
	var lines []netconfProbeLine
	sc := bufio.NewScanner(stdout)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	var runErr error
	for sc.Scan() {
		var l netconfProbeLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			runErr = fmt.Errorf("probe line %q: %w", sc.Text(), err)
			break
		}
		if l.Kind == "toggle" {
			if err := tg.toggle(l.Step); err != nil {
				runErr = fmt.Errorf("toggle %s: %w", l.Step, err)
				break
			}
			_, _ = io.WriteString(stdin, "ok\n")
		}
		lines = append(lines, l)
	}
	_ = stdin.Close()
	_, _ = io.Copy(io.Discard, stdout)
	werr := cmd.Wait()
	if runErr != nil || werr != nil {
		t.Fatalf("probe against %s: %v %v\nstderr:\n%s", tg.name, runErr, werr, stderr.String())
	}
	return lines
}

// ---- normalisation

var (
	ncnEventTime  = regexp.MustCompile(`<eventTime>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\dZ</eventTime>`)
	ncnSubID      = regexp.MustCompile(`(<subscription-id(?: [^>]*)?>)(\d+)(</subscription-id>)`)
	ncnMessageID  = regexp.MustCompile(` message-id="[^"]*"`)
	ncnSessionID  = regexp.MustCompile(`(<session-id>)\d+(</session-id>)`)
	ncnTimestamp  = regexp.MustCompile(`(<(?:last-change|discontinuity-time)>)\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{6}\+00:00(</(?:last-change|discontinuity-time)>)`)
	ncnCounter    = regexp.MustCompile(`(<(?:in|out)-[a-z-]+>)\d+(</(?:in|out)-[a-z-]+>)`)
	ncnIfIndex    = regexp.MustCompile(`(<if-index>)\d+(</if-index>)`)
	ncnPhysAddr   = regexp.MustCompile(`(<phys-address>)[0-9a-f]{2}(?::[0-9a-f]{2}){5}(</phys-address>)`)
	ncnIfNames    = strings.NewReplacer(netconfInteropNl6If, "IFNAME", "GigabitEthernet1%2F0%2F24", "IFNAME", netconfInteropRefIf, "IFNAME")
	ncnKeylessNm  = regexp.MustCompile(`(<name>|<target>/interfaces/interface=)[^<]*(</name>|</target>)`)
	ncnKeylessVal = regexp.MustCompile(`(<(?:admin-status|oper-status|interface-type|speed)>)[^<]*(</(?:admin-status|oper-status|interface-type|speed)>)`)
)

// normaliseNetconfLine replaces the values that legitimately differ between
// two IOS XE targets with placeholders: eventTime, subscription ids,
// last-change, discontinuity-time, counter values, message-id, session ids
// and the interface under test (plain and percent-encoded). if-index and
// phys-address are the interface's identity and are masked too. A value is
// replaced only when it has the device's shape, so a malformed value still
// shows up in the diff.
func normaliseNetconfLine(line string) string {
	line = ncnEventTime.ReplaceAllString(line, "<eventTime>EVENTTIME</eventTime>")
	line = ncnSubID.ReplaceAllString(line, "${1}SUBID${3}")
	line = ncnMessageID.ReplaceAllString(line, ` message-id="MSGID"`)
	line = ncnSessionID.ReplaceAllString(line, "${1}SESSIONID${2}")
	line = ncnTimestamp.ReplaceAllString(line, "${1}TIMESTAMP${2}")
	line = ncnCounter.ReplaceAllString(line, "${1}COUNTER${2}")
	line = ncnIfIndex.ReplaceAllString(line, "${1}IFINDEX${2}")
	line = ncnPhysAddr.ReplaceAllString(line, "${1}MAC${2}")
	return ncnIfNames.Replace(line)
}

// netconfOrdinalSubIDs rewrites subscription ids to S1, S2, ... in order of
// first appearance within each phase, so the diff still sees which
// subscription a push belongs to. normaliseNetconfLine leaves them alone
// because they are no longer digits.
func netconfOrdinalSubIDs(lines []netconfProbeLine) {
	seen := map[string]map[string]int{}
	for i := range lines {
		m := seen[lines[i].Phase]
		if m == nil {
			m = map[string]int{}
			seen[lines[i].Phase] = m
		}
		lines[i].XML = ncnSubID.ReplaceAllStringFunc(lines[i].XML, func(s string) string {
			g := ncnSubID.FindStringSubmatch(s)
			n, ok := m[g[2]]
			if !ok {
				n = len(m) + 1
				m[g[2]] = n
			}
			return fmt.Sprintf("%sS%d%s", g[1], n, g[3])
		})
	}
}

// ---- projection of the device row onto the leaves nl6 serves

// netconfServedLeaves are the interface leaves nl6 serves in a row
// subscription. The device sends well over 100; the comparison covers only
// these, in the device's order. nl6 is NOT projected: a leaf nl6 sends that
// the device does not, or in another order, fails the diff.
var netconfServedLeaves = map[string]bool{
	"name": true, "interface-type": true, "admin-status": true, "oper-status": true,
	"last-change": true, "if-index": true, "phys-address": true, "speed": true, "statistics": true,
}

var netconfServedStats = map[string]bool{
	"discontinuity-time": true, "in-octets": true, "in-unicast-pkts": true, "in-broadcast-pkts": true,
	"in-multicast-pkts": true, "in-discards": true, "in-errors": true, "out-octets": true,
	"out-unicast-pkts": true, "out-broadcast-pkts": true, "out-multicast-pkts": true,
	"out-discards": true, "out-errors": true,
}

type ncNode struct {
	ns, local, text string
	attrs           []xml.Attr
	kids            []*ncNode
}

func parseNcCanon(s string) (*ncNode, error) {
	dec := xml.NewDecoder(strings.NewReader(s))
	var stack []*ncNode
	var root *ncNode
	for {
		tok, err := dec.Token()
		if err == io.EOF {
			return root, nil
		}
		if err != nil {
			return nil, err
		}
		switch v := tok.(type) {
		case xml.StartElement:
			n := &ncNode{ns: v.Name.Space, local: v.Name.Local}
			for _, a := range v.Attr {
				if a.Name.Space == "" && a.Name.Local == "xmlns" {
					continue
				}
				n.attrs = append(n.attrs, a)
			}
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, n)
			} else {
				root = n
			}
			stack = append(stack, n)
		case xml.EndElement:
			stack = stack[:len(stack)-1]
		case xml.CharData:
			if len(stack) > 0 {
				stack[len(stack)-1].text += string(v)
			}
		}
	}
}

// write mirrors the probe's canonical form.
func (n *ncNode) write(b *bytes.Buffer, parentNS string) {
	b.WriteString("<" + n.local)
	if n.ns != parentNS {
		b.WriteString(` xmlns="` + n.ns + `"`)
	}
	for _, a := range n.attrs {
		k := a.Name.Local
		if a.Name.Space != "" {
			k = "{" + a.Name.Space + "}" + k
		}
		b.WriteString(" " + k + `="`)
		_ = xml.EscapeText(b, []byte(a.Value))
		b.WriteString(`"`)
	}
	b.WriteString(">")
	_ = xml.EscapeText(b, []byte(strings.TrimSpace(n.text)))
	for _, k := range n.kids {
		k.write(b, n.ns)
	}
	b.WriteString("</" + n.local + ">")
}

func (n *ncNode) project() {
	if n.ns == iosxeNSIfOper && n.local == "interface" {
		var kept []*ncNode
		for _, k := range n.kids {
			if !netconfServedLeaves[k.local] {
				continue
			}
			if k.local == "statistics" {
				var st []*ncNode
				for _, s := range k.kids {
					if netconfServedStats[s.local] {
						st = append(st, s)
					}
				}
				k.kids = st
			}
			kept = append(kept, k)
		}
		n.kids = kept
		return
	}
	for _, k := range n.kids {
		k.project()
	}
}

// projectNetconfReference cuts a device row down to the leaves nl6 serves.
// Lines without an IOS XE interface element pass through unchanged.
func projectNetconfReference(s string) (string, error) {
	if !strings.Contains(s, iosxeNSIfOper) {
		return s, nil
	}
	root, err := parseNcCanon(s)
	if err != nil {
		return "", err
	}
	root.project()
	var b bytes.Buffer
	root.write(&b, "")
	return b.String(), nil
}

// netconfComparable turns one side's stream into diffable rows.
func netconfComparable(t *testing.T, lines []netconfProbeLine, reference bool) (rows, skipped []string) {
	t.Helper()
	netconfOrdinalSubIDs(lines)
	keyless := map[string]map[string]bool{}
	for _, l := range lines {
		x := l.XML
		if reference {
			p, err := projectNetconfReference(x)
			if err != nil {
				t.Fatalf("reference line %q: %v", x, err)
			}
			x = p
		}
		x = normaliseNetconfLine(x)
		row := l.Phase + "/" + l.Step + " " + l.Kind + " " + x
		if netconfInteropSkipped(l.Phase, l.Step) {
			skipped = append(skipped, row)
			continue
		}
		// An all-interface subscription pushes once per interface, and the
		// two targets have different interfaces (the c8000v has a
		// loopback). Compare the distinct shapes with names, states, types
		// and speeds masked.
		if l.Phase == "keyless" && l.Kind == "notification" {
			x = ncnKeylessNm.ReplaceAllString(x, "${1}NAME${2}")
			x = ncnKeylessVal.ReplaceAllString(x, "${1}STATE${2}")
			if keyless[l.Step] == nil {
				keyless[l.Step] = map[string]bool{}
			}
			keyless[l.Step][x] = true
			continue
		}
		rows = append(rows, row)
	}
	steps := make([]string, 0, len(keyless))
	for s := range keyless {
		steps = append(steps, s)
	}
	sort.Strings(steps)
	for _, s := range steps {
		shapes := make([]string, 0, len(keyless[s]))
		for x := range keyless[s] {
			shapes = append(shapes, x)
		}
		sort.Strings(shapes)
		for _, x := range shapes {
			rows = append(rows, "keyless/"+s+" notification-shape "+x)
		}
	}
	return rows, skipped
}

// diffNetconfRows reports the rows where the streams part. Empty means
// equal.
func diffNetconfRows(nl6, ref []string) string {
	var b strings.Builder
	n := max(len(nl6), len(ref))
	shown := 0
	for i := 0; i < n && shown < 8; i++ {
		var a, r string
		if i < len(nl6) {
			a = nl6[i]
		}
		if i < len(ref) {
			r = ref[i]
		}
		if a == r {
			continue
		}
		fmt.Fprintf(&b, "row %d\n  nl6: %s\n  ref: %s\n", i, a, r)
		shown++
	}
	if len(nl6) != len(ref) {
		fmt.Fprintf(&b, "row counts: nl6 %d, ref %d\n", len(nl6), len(ref))
	}
	return b.String()
}

// ---- toggles

// netconfNl6Toggle drives the in-process device through the same engine
// calls the REST interface-state handler makes.
func netconfNl6Toggle(st *InterfaceState) func(string) error {
	return func(action string) error {
		switch action {
		case "link-down", "link-up":
			link := OperUp
			if action == "link-down" {
				link = OperDown
			}
			if res, evts := st.SetLinkState(netconfInteropNl6Ix, link); res == LinkMovedVisible {
				for _, e := range evts {
					st.Broadcast(e)
				}
			}
		case "admin-down", "admin-up":
			admin := AdminUp
			if action == "admin-down" {
				admin = AdminDown
			}
			for _, e := range st.ApplyAdminStatus(netconfInteropNl6Ix, admin) {
				st.Broadcast(e)
			}
		default:
			return fmt.Errorf("unknown action %q", action)
		}
		return nil
	}
}

func netconfInteropEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// netconfInteropRefEnv lists the variables a live reference run needs.
var netconfInteropRefEnv = []string{"NL6_NETCONF_REF", "NL6_NETCONF_REF_PASSWORD", "NL6_NETCONF_REF_PVE", "NL6_NETCONF_REF_VMID", "NL6_NETCONF_REF_NIC"}

func netconfRefLink(pve, vmid, nic string, down bool) error {
	spec := nic
	if down {
		spec += ",link_down=1"
	}
	out, err := exec.Command("ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", pve,
		"qm set "+vmid+" --net1 "+spec).CombinedOutput()
	if err != nil {
		return fmt.Errorf("qm set: %v: %s", err, out)
	}
	return nil
}

func netconfRefAdmin(script string, tg netconfProbeTarget, down bool) error {
	state := "up"
	if down {
		state = "down"
	}
	out, err := netconfProbeCmd(script, tg, "admin", state).CombinedOutput()
	if err != nil {
		return fmt.Errorf("admin %s: %v: %s", state, err, out)
	}
	return nil
}

// runNetconfReference probes the live reference and leaves its interface
// up, also on failure.
func runNetconfReference(t *testing.T, script string) []netconfProbeLine {
	t.Helper()
	ref := netconfProbeTarget{
		name: "reference", host: os.Getenv("NL6_NETCONF_REF"), port: "830",
		user:     netconfInteropEnv("NL6_NETCONF_REF_USER", netconfInteropRefUser),
		password: os.Getenv("NL6_NETCONF_REF_PASSWORD"),
		iface:    netconfInteropRefIf, quiet: netconfInteropRefQuiet, settle: netconfInteropRefSettle,
	}
	pve, vmid, nic := os.Getenv("NL6_NETCONF_REF_PVE"), os.Getenv("NL6_NETCONF_REF_VMID"), os.Getenv("NL6_NETCONF_REF_NIC")
	restore := func() {
		if err := netconfRefLink(pve, vmid, nic, false); err != nil {
			t.Errorf("restore reference link: %v", err)
		}
		if err := netconfRefAdmin(script, ref, false); err != nil {
			t.Errorf("restore reference admin: %v", err)
		}
	}
	restore()
	t.Cleanup(restore)
	ref.toggle = func(action string) error {
		switch action {
		case "link-down", "link-up":
			return netconfRefLink(pve, vmid, nic, action == "link-down")
		case "admin-down", "admin-up":
			return netconfRefAdmin(script, ref, action == "admin-down")
		}
		return fmt.Errorf("unknown action %q", action)
	}
	return runNetconfProbe(t, script, ref)
}

func loadNetconfProbeLines(t *testing.T, path string) []netconfProbeLine {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var lines []netconfProbeLine
	for _, raw := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var l netconfProbeLine
		if err := json.Unmarshal(raw, &l); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		lines = append(lines, l)
	}
	return lines
}

func saveNetconfProbeLines(t *testing.T, path string, lines []netconfProbeLine) {
	t.Helper()
	var b bytes.Buffer
	for _, l := range lines {
		j, _ := json.Marshal(l)
		b.Write(append(j, '\n'))
	}
	if err := os.WriteFile(path, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestNetconfInteropAgainstReference(t *testing.T) {
	if os.Getenv("NL6_NETCONF_INTEROP") != "1" {
		t.Skip("set NL6_NETCONF_INTEROP=1 (make test-interop-netconf) to diff nl6 against a real IOS XE device")
	}
	if os.Getenv("NL6_NETCONF_REF_STREAM") == "" {
		var unset []string
		for _, k := range netconfInteropRefEnv {
			if os.Getenv(k) == "" {
				unset = append(unset, k)
			}
		}
		if len(unset) > 0 {
			t.Skipf("no reference device: set %s, or replay a saved stream with NL6_NETCONF_REF_STREAM", strings.Join(unset, ", "))
		}
	}
	if _, err := exec.LookPath("uv"); err != nil {
		t.Fatal("uv not found: it runs scripts/netconf-probe.py")
	}
	script := netconfProbeScript(t)

	// nl6 first: it takes seconds, and a broken nl6 should not cost a
	// round on the device.
	mgr := useNetconfTestManager(t, true)
	_, st, addr := newNetconfListenDevice(t, mgr)
	_ = netconfNl6Toggle(st)("link-up")
	_ = netconfNl6Toggle(st)("admin-up")
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	nl6Lines := runNetconfProbe(t, script, netconfProbeTarget{
		name: "nl6", host: host, port: port, user: USERNAME, password: PASSWORD,
		iface: netconfInteropNl6If, quiet: netconfInteropNl6Quiet, settle: netconfInteropNl6Settle, toggle: netconfNl6Toggle(st),
	})
	nl6Rows, nl6Skipped := netconfComparable(t, nl6Lines, false)

	// NL6_NETCONF_REF_STREAM replays a reference stream saved earlier with
	// NL6_NETCONF_REF_SAVE, so a change to nl6 can be re-checked without
	// touching the device.
	var refLines []netconfProbeLine
	if p := os.Getenv("NL6_NETCONF_REF_STREAM"); p != "" {
		refLines = loadNetconfProbeLines(t, p)
		t.Logf("reference replayed from %s, device not contacted", p)
	} else {
		refLines = runNetconfReference(t, script)
		if p := os.Getenv("NL6_NETCONF_REF_SAVE"); p != "" {
			saveNetconfProbeLines(t, p, refLines)
		}
	}
	refRows, refSkipped := netconfComparable(t, refLines, true)

	for _, a := range netconfInteropAllow {
		t.Logf("allow-list %s/%s skip=%v: %s", a.phase, a.step, a.skip, a.why)
	}
	for _, r := range nl6Skipped {
		t.Logf("skipped nl6: %s", r)
	}
	for _, r := range refSkipped {
		t.Logf("skipped ref: %s", r)
	}
	for _, r := range nl6Rows {
		t.Logf("row: %s", r)
	}
	if d := diffNetconfRows(nl6Rows, refRows); d != "" {
		t.Fatalf("nl6 and the reference differ:\n%s", d)
	}
	t.Logf("%d rows equal after normalisation", len(nl6Rows))
}
