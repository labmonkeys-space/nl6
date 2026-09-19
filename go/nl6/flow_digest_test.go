/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// Byte-identity harness for non-NBAR2 flow output.
//
// Plan B changes the generation path, the config struct and the encoder
// selection. The claim that every device not using NBAR2 still emits the same
// bytes is measured here rather than argued: the harness drives the real Tick
// path for every shipped device type under every non-NBAR2 protocol and option
// shape with a held clock and the device's own seeded RNG, and hashes every
// datagram in order. The table in testdata/flow-digests/pre-nbar2.tsv was
// produced by this harness at the parent commit of the Plan B branch (plus the
// flowWallClock seam, which is what makes a held clock possible) and the test
// requires the live build to reproduce it row for row.
//
// Regenerate with NL6_FLOW_DIGEST_WRITE=1 ONLY when a wire change is intended,
// and say so in the commit that moves the file.

const flowDigestFile = "testdata/flow-digests/pre-nbar2.tsv"

// flowDigestClock is the held wall clock. Any fixed instant works; this one is
// recorded in the TSV header so a reader can reproduce the table.
var flowDigestClock = time.Date(2026, 9, 19, 12, 0, 0, 0, time.UTC)

// flowDigestDeviceIP seeds the exporter RNG through domainID and is the
// source address on every record.
const flowDigestDeviceIP = "10.42.7.13"

// flowDigestTicks is how many 5-second ticks the harness drives. Thirteen
// covers one template refresh (60 s) so template-bearing and data-only ticks
// are both in the digest, and enough expiries that every protocol paginates.
const flowDigestTicks = 13

type flowDigestCase struct {
	deviceType string
	protocol   string
	shape      string
}

// flowDigestCases enumerates (type, protocol, shape) for the shipped tree:
// every non-NBAR2 protocol on every flow-capable type, and both option shapes
// where the protocol carries options.
func flowDigestCases(t *testing.T) []flowDigestCase {
	t.Helper()
	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources: %v", err)
	}
	var cases []flowDigestCase
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		rf := e.Name() + ".json"
		if !SupportsFlowExport(rf) {
			continue
		}
		for _, proto := range []string{"netflow5", "netflow9", "ipfix", "sflow"} {
			cases = append(cases, flowDigestCase{e.Name(), proto, ""})
			if proto == "netflow9" || proto == "ipfix" {
				cases = append(cases, flowDigestCase{e.Name(), proto, flowOptionShapeIfScoped})
				cases = append(cases, flowDigestCase{e.Name(), proto, flowOptionShapeSystemScoped})
			}
		}
	}
	if len(cases) == 0 {
		t.Fatal("enumerated zero cases; the resources layout changed and this harness is hashing nothing")
	}
	return cases
}

// flowDigestFor drives one case through the real Tick and returns the sha256
// over every emitted datagram, each length-prefixed so a boundary shift cannot
// hash the same.
func flowDigestFor(t *testing.T, c flowDigestCase) string {
	t.Helper()
	enc, canon, err := buildFlowEncoder(c.protocol)
	if err != nil {
		t.Fatalf("%v: %v", c, err)
	}
	collector := &net.UDPAddr{IP: net.ParseIP("127.0.0.1").To4(), Port: 2055}
	fe := NewFlowExporter(testDevice(flowDigestDeviceIP), GetFlowProfile(c.deviceType+".json"),
		30*time.Second, 15*time.Second, 60*time.Second,
		collector.String(), collector, canon, enc, 0)
	fe.startTime = flowDigestClock
	if c.shape != "" {
		fe.optionShape = c.shape
		fe.optionIfaces = []flowOptionIface{
			{ifIndex: 1, name: "GigabitEthernet0/1"},
			{ifIndex: 2, name: "GigabitEthernet0/2"},
			{ifIndex: 3, name: "GigabitEthernet0/3"},
		}
	}

	h := sha256.New()
	var lenBuf [4]byte
	datagrams := 0
	fe.writeOverride = func(pdu []byte) error {
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(pdu)))
		h.Write(lenBuf[:])
		h.Write(pdu)
		datagrams++
		return nil
	}

	// Tick needs a non-nil socket to proceed even though writeOverride takes
	// every write; the socket is never used.
	conn := testSender(t)
	defer conn.Close()
	pool := testPool()

	prev := flowWallClock
	defer func() { flowWallClock = prev }()
	for i := 1; i <= flowDigestTicks; i++ {
		now := flowDigestClock.Add(time.Duration(i) * 5 * time.Second)
		flowWallClock = func() time.Time { return now }
		fe.Tick(now, conn, pool)
	}
	if datagrams == 0 {
		t.Fatalf("%v: emitted no datagrams; the harness is hashing nothing", c)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func flowDigestKey(c flowDigestCase) string {
	return c.deviceType + "\t" + c.protocol + "\t" + c.shape
}

// readFlowDigests parses the TSV into key -> digest, ignoring the header.
func readFlowDigests(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v (generate it with NL6_FLOW_DIGEST_WRITE=1 at the baseline commit)", path, err)
	}
	defer f.Close()
	got := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		i := strings.LastIndexByte(line, '\t')
		if i < 0 {
			t.Fatalf("%s: malformed line %q", path, line)
		}
		got[line[:i]] = line[i+1:]
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan %s: %v", path, err)
	}
	return got
}

// TestNonNbar2WireOutputUnchanged is the byte-identity gate: every
// (type, protocol, shape) row must hash to what the baseline table records.
//
// With NL6_FLOW_DIGEST_WRITE=1 it instead rewrites the table from the live
// build and fails, so a regeneration can never pass by accident.
func TestNonNbar2WireOutputUnchanged(t *testing.T) {
	cases := flowDigestCases(t)
	live := make(map[string]string, len(cases))
	for _, c := range cases {
		live[flowDigestKey(c)] = flowDigestFor(t, c)
	}

	if os.Getenv("NL6_FLOW_DIGEST_WRITE") != "" {
		if err := os.MkdirAll(filepath.Dir(flowDigestFile), 0o755); err != nil {
			t.Fatal(err)
		}
		keys := make([]string, 0, len(live))
		for k := range live {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		fmt.Fprintf(&sb, "# Flow datagram digests, one per (device type, protocol, option shape).\n")
		fmt.Fprintf(&sb, "# Produced by TestNonNbar2WireOutputUnchanged with NL6_FLOW_DIGEST_WRITE=1.\n")
		fmt.Fprintf(&sb, "# Clock held at %s; device %s; %d ticks of 5s; timeouts 30s/15s/60s.\n",
			flowDigestClock.Format(time.RFC3339), flowDigestDeviceIP, flowDigestTicks)
		fmt.Fprintf(&sb, "# Command: cd go && NL6_FLOW_DIGEST_WRITE=1 go test ./nl6/ -run TestNonNbar2WireOutputUnchanged\n")
		fmt.Fprintf(&sb, "# The commit that produced this table is named in the commit that added it.\n")
		for _, k := range keys {
			fmt.Fprintf(&sb, "%s\t%s\n", k, live[k])
		}
		if err := os.WriteFile(flowDigestFile, []byte(sb.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Fatalf("wrote %d rows to %s; unset NL6_FLOW_DIGEST_WRITE to compare", len(keys), flowDigestFile)
	}

	want := readFlowDigests(t, flowDigestFile)
	for _, c := range cases {
		k := flowDigestKey(c)
		w, ok := want[k]
		if !ok {
			t.Errorf("%s: no baseline row; a new type or protocol needs the table regenerated deliberately", strings.ReplaceAll(k, "\t", " "))
			continue
		}
		if live[k] != w {
			t.Errorf("%s: wire output changed (live %s, baseline %s)", strings.ReplaceAll(k, "\t", " "), live[k][:12], w[:12])
		}
	}
	for k := range want {
		if _, ok := live[k]; !ok {
			t.Errorf("%s: baseline row has no live case; a type or protocol was removed", strings.ReplaceAll(k, "\t", " "))
		}
	}
}

// TestFlowDigestIsDeterministic is the harness's own control: two runs of one
// case must agree, or every row in the table is noise.
func TestFlowDigestIsDeterministic(t *testing.T) {
	c := flowDigestCase{"cisco_ios", "ipfix", flowOptionShapeIfScoped}
	a := flowDigestFor(t, c)
	b := flowDigestFor(t, c)
	if a != b {
		t.Fatalf("two runs differ: %s vs %s", a, b)
	}
}
