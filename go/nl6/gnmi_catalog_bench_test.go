/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"net"
	"runtime"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// BenchmarkCatalogResolverMemory reports the per-device cost of the
// shared-catalogue design: the catalogue is parsed once; each device
// adds a resolver with a pointer and an ifDescr map.
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

// BenchmarkASR9902ComponentsGet compares a JSON_IETF Get of /components
// on the ASR 9902 catalogue per leaf and folded into one value.
func BenchmarkASR9902ComponentsGet(b *testing.B) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		b.Fatal(err)
	}
	r := newCatalogResolver(&DeviceSimulator{ID: "d", IP: net.IPv4(10, 0, 0, 1)}, cats["cisco_asr9902"])
	req := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "components"}}}
	for _, layout := range []string{gnmiJSONIETFLayoutLeaf, gnmiJSONIETFLayoutContainer} {
		b.Run(layout, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				cn, err := r.Resolve(req, time.Now())
				if err != nil {
					b.Fatal(err)
				}
				if layout == gnmiJSONIETFLayoutContainer {
					_, err = foldJSONIETFGet(req, cn)
				} else {
					for _, n := range cn {
						if _, err = encodeUpdates(n.Updates, gnmipb.Encoding_JSON_IETF); err != nil {
							break
						}
					}
				}
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkCatalogComponentsTick is one SAMPLE tick of a /components
// subscription per shipped catalogue, the resolver's hot path. The clock
// is fixed so the op measures Resolve alone.
func BenchmarkCatalogComponentsTick(b *testing.B) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		b.Fatal(err)
	}
	req := &gnmipb.Path{Elem: []*gnmipb.PathElem{{Name: "components"}}}
	now := time.Now()
	for _, name := range []string{"juniper_mx10004", "cisco_asr9902"} {
		r := newCatalogResolver(&DeviceSimulator{ID: "d", IP: net.IPv4(10, 0, 0, 1)}, cats[name])
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := r.Resolve(req, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
