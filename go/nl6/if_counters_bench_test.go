/*
 * Copyright 2026 The OpenNMS Group, Inc.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Created by Ronny Trommer <ronny@opennms.com>
 */

package main

import (
	"fmt"
	"strconv"
	"sync"
	"testing"
)

// buildBenchResources is the benchmark-side equivalent of
// buildTestResources — accepts *testing.B (vs *testing.T) so it can be
// used outside the standard test entry points without changing the
// existing helpers.
func buildBenchResources(b *testing.B, speeds []uint64) *DeviceResources {
	b.Helper()
	res := &DeviceResources{oidIndex: &sync.Map{}}
	for i, spd := range speeds {
		ifIndex := i + 1
		res.oidIndex.Store(
			fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.15.%d", ifIndex),
			strconv.FormatUint(spd/1_000_000, 10),
		)
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.6.%d", ifIndex), "0")
		res.oidIndex.Store(fmt.Sprintf(".1.3.6.1.2.1.31.1.1.1.10.%d", ifIndex), "0")
	}
	return res
}

// BenchmarkNextDynamicOID measures NextDynamicOID at four representative
// walk positions on a 1000-interface device:
//
//   - "before-first": currentOID sorts before the first owned dynamic
//     OID (cold-start of an snmpwalk that begins at the IF-MIB root).
//   - "ifTable-mid":   middle of an ifTable column — exercises the
//     successor-ifIndex binary search inside sortedIfIndexes.
//   - "table-cross":   last ifIndex of the last ifTable column —
//     exercises the cross-table boundary.
//   - "near-last":     last ifIndex of the second-to-last ifXTable
//     column — exercises end-of-walk advance.
//
// All four sub-benchmarks call b.ReportAllocs() so the per-step
// allocation profile is visible alongside ns/op.
func BenchmarkNextDynamicOID(b *testing.B) {
	const numIfaces = 1000
	speeds := make([]uint64, numIfaces)
	for i := range speeds {
		speeds[i] = 1_000_000_000
	}
	res := buildBenchResources(b, speeds)
	c := &MetricsCycler{}
	c.InitIfCounters(res, 42)
	ic := c.ifCounters.Load()
	if ic == nil {
		b.Fatal("InitIfCounters did not create ifCounters")
	}

	cases := []struct {
		name string
		oid  string
	}{
		// Before the first dynamic OID — falls into the !matched
		// before-first branch.
		{"before-first", ".1.3.6.1.2.1.2"},
		// Middle of ifTable column 14 (ifInErrors) at ifIndex 500 —
		// hits the same-column successor-search hot path.
		{"ifTable-mid", ".1.3.6.1.2.1.2.2.1.14.500"},
		// Last ifIndex of last ifTable column (.20) — successor falls
		// off the end of sortedIfIndexes and must cross into the first
		// ifXTable column (.2).
		{"table-cross", ".1.3.6.1.2.1.2.2.1.20.1000"},
		// Last ifIndex of the second-to-last ifXTable column (.12).
		{"near-last", ".1.3.6.1.2.1.31.1.1.1.12.1000"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, _ = ic.NextDynamicOID(tc.oid)
			}
		})
	}
}
