/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"hash/fnv"
	"math/rand/v2"
	"net"
)

// deviceSeed is the seed of a device's generated curves and dials: CPU, memory
// and temperature, GPUs, interface counters and optical channels. It is a hash
// of the device's IP, so a device serves the same values whichever request
// created it and in whatever position. It used to be the device's index within
// its creation request, which restarts at 0 on every request, so the first
// device of every request served identical curves (nl6#989). Each subsystem
// still salts it, so the streams of one device differ from one another.
func deviceSeed(ip net.IP) int64 {
	h := fnv.New64a()
	h.Write([]byte(ip.String()))
	return int64(h.Sum64())
}

// gpuSeed is the seed of GPU k of a device. A hash of both, so no GPU of one
// device shares a seed with a GPU of another; base+17*k made GPU 1 of a device
// GPU 0 of the device whose seed was 17 higher.
func gpuSeed(base int64, k int) int64 {
	var b [16]byte
	binary.BigEndian.PutUint64(b[:8], uint64(base))
	binary.BigEndian.PutUint64(b[8:], uint64(k))
	h := fnv.New64a()
	h.Write(b[:])
	return int64(h.Sum64())
}

// seedPCGStream is the fixed second word of every seeded generator. The seed is
// the first, so the stream depends on all 64 bits of it.
const seedPCGStream = 0x6e6c_365f_7365_6564

// newSeededRand returns the generator of one seeded stream. math/rand reduces
// every seed modulo 2^31-1, so two seeds that agree modulo that prime would
// draw identical streams; PCG keeps the whole seed.
func newSeededRand(seed int64) *rand.Rand {
	return rand.New(rand.NewPCG(uint64(seed), seedPCGStream))
}
