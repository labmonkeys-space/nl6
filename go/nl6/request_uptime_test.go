/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// tickingFrom gives a device an uptime clock that starts at boot+start and
// moves one tick (10 ms) forward on every read. A request that reads it once
// serves one uptime to every binding; one that reads it per binding serves
// values a tick apart (nl6#1087).
func tickingFrom(d *DeviceSimulator, start time.Duration) {
	reads := 0
	d.now = func() time.Time {
		at := d.bootTime.Add(start + time.Duration(reads)*10*time.Millisecond)
		reads++
		return at
	}
}

// assertOneUptimePerRequest serves one request with a clock that moves on
// every read and requires the answer to equal the one served with the clock
// frozen at the request's first reading.
func assertOneUptimePerRequest(t *testing.T, d *DeviceSimulator, serve func() []byte) {
	t.Helper()
	const start = time.Hour
	frozen := d.bootTime.Add(start)
	d.now = func() time.Time { return frozen }
	want := serve()
	tickingFrom(d, start)
	if got := serve(); !bytes.Equal(got, want) {
		t.Fatalf("a request answered with a clock that moves on every read differs from the answer at one instant:\n got % x\nwant % x", got, want)
	}
}

// uptimeDevice is a booted shipped profile that serves both uptimes.
func uptimeDevice(t *testing.T) *SNMPServer {
	t.Helper()
	s := bootedShippedDevice(t, "nvidia_dgx_h100.json", time.Now().Add(-2*time.Hour), nil)
	if _, ok := s.device.resources.oidIndex.Load(hrSystemUptimeOID); !ok {
		t.Fatal("fixture: nvidia_dgx_h100 carries no hrSystemUptime.0 row")
	}
	return s
}

// sysObjectID.0 and the hrSystem group sort just before the two uptimes, so a
// GETNEXT or a GETBULK column from each lands on one.
var uptimePredecessors = []string{".1.3.6.1.2.1.1.2.0", ".1.3.6.1.2.1.25.1"}

func TestGetOfBothUptimesIsOneInstant(t *testing.T) {
	s := uptimeDevice(t)
	oids := []string{sysUpTimeOID, hrSystemUptimeOID}
	req := getRequestAtVersionMulti(snmpVersion2c, oids)
	assertOneUptimePerRequest(t, s.device, func() []byte {
		return s.handleGetRequestVarbinds(oids, req)
	})
}

func TestGetNextOfBothUptimesIsOneInstant(t *testing.T) {
	s := uptimeDevice(t)
	assertOneUptimePerRequest(t, s.device, func() []byte {
		respOIDs, respVals := s.getNextBindingsForRequest(uptimePredecessors, s.lldpServedOIDs(), snmpVersion2c,
			newCounter64SkipBudget())
		if respOIDs[0] != sysUpTimeOID || respOIDs[1] != hrSystemUptimeOID {
			t.Fatalf("GETNEXT returned %v, want [%s %s]", respOIDs, sysUpTimeOID, hrSystemUptimeOID)
		}
		return []byte(strings.Join(respVals, " "))
	})
}

// requireBothUptimes fails unless a response carries both uptimes, so a
// change of the fixture's walk order cannot make a GETBULK test vacuous.
func requireBothUptimes(t *testing.T, oids []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, o := range oids {
		seen["."+strings.TrimPrefix(o, ".")] = true
	}
	if !seen[sysUpTimeOID] || !seen[hrSystemUptimeOID] {
		t.Fatalf("response carries %v, want both %s and %s", oids, sysUpTimeOID, hrSystemUptimeOID)
	}
}

// The GETBULK tests run once with every column a repeater and once with the
// first a non-repeater, since the two sections are separate loops.
func TestGetBulkOfBothUptimesIsOneInstant(t *testing.T) {
	for _, nonRep := range []int{0, 1} {
		t.Run(fmt.Sprintf("non-repeaters=%d", nonRep), func(t *testing.T) {
			s := uptimeDevice(t)
			req := v2cGetBulkRequest(nonRep, 3, uptimePredecessors)
			assertOneUptimePerRequest(t, s.device, func() []byte {
				resp := s.handleGetBulk(uptimePredecessors[0], req)
				var oids []string
				for _, vb := range decodeVarbindPairs(t, decodeResponseHeader(t, resp).varbinds) {
					oids = append(oids, vb.oid)
				}
				requireBothUptimes(t, oids)
				return resp
			})
		})
	}
}

func TestV3GetBulkOfBothUptimesIsOneInstant(t *testing.T) {
	for _, nonRep := range []int{0, 1} {
		t.Run(fmt.Sprintf("non-repeaters=%d", nonRep), func(t *testing.T) {
			s := uptimeDevice(t)
			s.v3Config = v3TestServer(nil).v3Config
			assertOneUptimePerRequest(t, s.device, func() []byte {
				vbs := v3Bulk(t, s, nonRep, 3, uptimePredecessors).varbinds
				oids := make([]string, len(vbs))
				for i, vb := range vbs {
					oids[i] = vb.oid
				}
				requireBothUptimes(t, oids)
				return []byte(fmt.Sprint(vbs))
			})
		})
	}
}

// TestGetNextOverBothWalkRoutesIsOneInstant: on a fixture with no interface
// rows, the GETNEXT from sysDescr.0 takes the slow path onto sysUpTime.0 and
// the one from ifNumber.0 the fast path onto the hrSystemUptime.0 row. Both
// routes serve the request's one reading.
func TestGetNextOverBothWalkRoutesIsOneInstant(t *testing.T) {
	s := newTestServer(hrUptimeRows())
	s.device.bootTime = time.Now().Add(-2 * time.Hour)
	preds := []string{".1.3.6.1.2.1.1.1.0", ".1.3.6.1.2.1.2.1.0"}
	assertOneUptimePerRequest(t, s.device, func() []byte {
		respOIDs, respVals := s.getNextBindingsForRequest(preds, s.lldpServedOIDs(), snmpVersion2c,
			newCounter64SkipBudget())
		if respOIDs[0] != sysUpTimeOID || respOIDs[1] != hrSystemUptimeOID {
			t.Fatalf("GETNEXT returned %v, want [%s %s]", respOIDs, sysUpTimeOID, hrSystemUptimeOID)
		}
		return []byte(strings.Join(respVals, " "))
	})
}

// Separate requests each read the clock, so the uptime still moves between
// two polls.
func TestSeparateRequestsReadTheUptimeClock(t *testing.T) {
	s := uptimeDevice(t)
	tickingFrom(s.device, time.Hour)
	first, second := s.findResponse(hrSystemUptimeOID), s.findResponse(hrSystemUptimeOID)
	if first != "360000" || second != "360001" {
		t.Fatalf("two requests one tick apart = %s, %s, want 360000, 360001", first, second)
	}
}
