/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"runtime"
	"testing"
)

// BenchmarkCatalogResolverMemory reports the per-device cost of the
// shared-catalogue design (Review Focus 5): the catalogue is parsed
// once; each device adds a resolver with a pointer and an ifDescr map.
func BenchmarkCatalogResolverMemory(b *testing.B) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		b.Fatal(err)
	}
	cat := cats["juniper_mx10004"]
	const n = 30000
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	keep := make([]*catalogResolver, 0, n)
	for i := 0; i < n; i++ {
		d := &DeviceSimulator{ID: "d", IP: net.IPv4(10, byte(i>>16), byte(i>>8), byte(i))}
		keep = append(keep, newCatalogResolver(d, cat))
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Signed: the catalogue map must stay live (KeepAlive below) or the
	// GC frees the other catalogues and HeapAlloc shrinks.
	perDevice := float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)) / n
	b.ReportMetric(perDevice, "bytes/device")
	if perDevice > 2048 {
		b.Fatalf("catalogue resolver costs %.0f bytes per device, want under 2048", perDevice)
	}
	runtime.KeepAlive(keep)
	runtime.KeepAlive(cats)
}
