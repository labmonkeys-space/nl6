/*
 * © 2025 Labmonkeys Space
 *
 * Layer 8 Ecosystem is licensed under the Apache License, Version 2.0.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package main

import (
	"math/rand"
	"net"
	"testing"
	"time"
)

// makeRecord is a test helper that returns a minimal FlowRecord with the given
// 5-tuple. Bytes and Packets are set to 1 so accumulation is easy to verify.
func makeRecord(srcIP, dstIP string, srcPort, dstPort uint16, proto uint8) FlowRecord {
	return FlowRecord{
		SrcIP:    net.ParseIP(srcIP).To4(),
		DstIP:    net.ParseIP(dstIP).To4(),
		NextHop:  net.IPv4(0, 0, 0, 0).To4(),
		SrcPort:  srcPort,
		DstPort:  dstPort,
		Protocol: proto,
		Bytes:    100,
		Packets:  1,
		StartMs:  1000,
		EndMs:    2000,
		InIface:  1,
		OutIface: 2,
		SrcMask:  24,
		DstMask:  24,
	}
}

func TestFlowCache_AddAndLen(t *testing.T) {
	fc := NewFlowCache(60*time.Second, 15*time.Second, 256)
	now := time.Now()

	fc.Add(makeRecord("10.0.0.1", "10.0.0.2", 12345, 443, 6), now)
	fc.Add(makeRecord("10.0.0.1", "10.0.0.3", 12346, 80, 6), now)

	if got := fc.Len(); got != 2 {
		t.Errorf("expected 2 flows, got %d", got)
	}
}

func TestFlowCache_Accumulate(t *testing.T) {
	fc := NewFlowCache(60*time.Second, 15*time.Second, 256)
	now := time.Now()

	r := makeRecord("10.0.0.1", "10.0.0.2", 12345, 443, 6)
	fc.Add(r, now)
	fc.Add(r, now) // second add to same 5-tuple must accumulate

	if fc.Len() != 1 {
		t.Fatalf("expected 1 flow after duplicate add, got %d", fc.Len())
	}

	expired := fc.Expire(now.Add(61 * time.Second))
	if len(expired) != 1 {
		t.Fatalf("expected 1 expired record, got %d", len(expired))
	}
	if expired[0].Bytes != 200 {
		t.Errorf("expected accumulated bytes=200, got %d", expired[0].Bytes)
	}
	if expired[0].Packets != 2 {
		t.Errorf("expected accumulated packets=2, got %d", expired[0].Packets)
	}
}

func TestFlowCache_ActiveTimeout(t *testing.T) {
	active := 5 * time.Second
	inactive := 30 * time.Second
	fc := NewFlowCache(active, inactive, 256)
	now := time.Now()

	fc.Add(makeRecord("10.0.0.1", "10.0.0.2", 1000, 443, 6), now)

	// Should not expire before active timeout.
	if got := fc.Expire(now.Add(4 * time.Second)); len(got) != 0 {
		t.Errorf("expected 0 expired before active timeout, got %d", len(got))
	}

	// Should expire at/after active timeout.
	if got := fc.Expire(now.Add(5 * time.Second)); len(got) != 1 {
		t.Errorf("expected 1 expired at active timeout, got %d", len(got))
	}

	if fc.Len() != 0 {
		t.Errorf("expected empty cache after expiry, got %d", fc.Len())
	}
}

func TestFlowCache_InactiveTimeout(t *testing.T) {
	active := 60 * time.Second
	inactive := 5 * time.Second
	fc := NewFlowCache(active, inactive, 256)
	t0 := time.Now()

	fc.Add(makeRecord("10.0.0.1", "10.0.0.2", 2000, 80, 6), t0)

	// Not yet inactive.
	if got := fc.Expire(t0.Add(4 * time.Second)); len(got) != 0 {
		t.Errorf("expected 0 expired before inactive timeout, got %d", len(got))
	}

	// Crossed inactive threshold without a fresh packet.
	if got := fc.Expire(t0.Add(5 * time.Second)); len(got) != 1 {
		t.Errorf("expected 1 expired at inactive timeout, got %d", len(got))
	}
}

func TestFlowCache_InactiveReset(t *testing.T) {
	// A second Add on the same 5-tuple resets the inactive timer.
	active := 60 * time.Second
	inactive := 5 * time.Second
	fc := NewFlowCache(active, inactive, 256)
	t0 := time.Now()

	r := makeRecord("10.0.0.1", "10.0.0.2", 3000, 443, 6)
	fc.Add(r, t0)

	// Re-add (simulate new packet) at t+4s — resets lastSeenAt.
	t1 := t0.Add(4 * time.Second)
	fc.Add(r, t1)

	// At t+8s the flow is 4s from the last packet — still within inactive timeout.
	if got := fc.Expire(t0.Add(8 * time.Second)); len(got) != 0 {
		t.Errorf("expected 0 expired (inactive reset), got %d", len(got))
	}

	// At t+10s the flow is 6s from the last packet — inactive timeout exceeded.
	if got := fc.Expire(t0.Add(10 * time.Second)); len(got) != 1 {
		t.Errorf("expected 1 expired after inactive reset, got %d", len(got))
	}
}

func TestFlowCache_MaxFlows(t *testing.T) {
	const cap = 3
	fc := NewFlowCache(60*time.Second, 15*time.Second, cap)
	now := time.Now()

	for i := 0; i < cap+5; i++ {
		fc.Add(makeRecord("10.0.0.1", "10.0.0.2", uint16(10000+i), 443, 6), now)
	}

	if got := fc.Len(); got != cap {
		t.Errorf("expected cache capped at %d, got %d", cap, got)
	}
}

func TestFlowCache_ExpireEmpty(t *testing.T) {
	fc := NewFlowCache(60*time.Second, 15*time.Second, 256)
	expired := fc.Expire(time.Now().Add(time.Hour))
	if len(expired) != 0 {
		t.Errorf("expected 0 expired from empty cache, got %d", len(expired))
	}
}

func TestFlowCache_GenerateFlows(t *testing.T) {
	profile := flowProfileServer
	deviceIP := net.ParseIP("192.168.1.1")
	rng := rand.New(rand.NewSource(42))
	fc := NewFlowCache(60*time.Second, 15*time.Second, profile.MaxFlows)
	now := time.Now()

	fc.GenerateFlows(profile, deviceIP, rng, now, 0)

	if got := fc.Len(); got != profile.ConcurrentFlows {
		t.Errorf("expected %d concurrent flows, got %d", profile.ConcurrentFlows, got)
	}

	// A second call should be a no-op (already at target).
	fc.GenerateFlows(profile, deviceIP, rng, now, 0)
	if got := fc.Len(); got != profile.ConcurrentFlows {
		t.Errorf("expected no extra flows on second generate, got %d", got)
	}
}

func TestFlowCache_GeneratedFlowsHaveValidFields(t *testing.T) {
	profile := flowProfileCoreRouter
	deviceIP := net.ParseIP("10.1.2.3")
	rng := rand.New(rand.NewSource(7))
	fc := NewFlowCache(60*time.Second, 15*time.Second, profile.MaxFlows)
	now := time.Now()

	fc.GenerateFlows(profile, deviceIP, rng, now, 5000)
	expired := fc.Expire(now.Add(61 * time.Second))

	for i, r := range expired {
		if r.SrcIP == nil || r.SrcIP.To4() == nil {
			t.Errorf("record %d: nil or non-IPv4 SrcIP", i)
		}
		if r.DstIP == nil || r.DstIP.To4() == nil {
			t.Errorf("record %d: nil or non-IPv4 DstIP", i)
		}
		if r.Protocol != 6 && r.Protocol != 17 && r.Protocol != 1 {
			t.Errorf("record %d: unexpected protocol %d", i, r.Protocol)
		}
		if r.EndMs < r.StartMs {
			t.Errorf("record %d: EndMs (%d) < StartMs (%d)", i, r.EndMs, r.StartMs)
		}
	}
}

func TestFlowProfile_SampleProtocol(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	counts := map[uint8]int{}
	const n = 10000
	for i := 0; i < n; i++ {
		counts[flowProfileCoreRouter.SampleProtocol(rng)]++
	}
	// TCP weight 0.65 — expect roughly 6000-7000 TCP samples.
	if counts[6] < 5500 || counts[6] > 7500 {
		t.Errorf("TCP count %d out of expected range [5500,7500] over %d samples", counts[6], n)
	}
	// No unexpected protocol values.
	for proto, c := range counts {
		if proto != 6 && proto != 17 && proto != 1 {
			t.Errorf("unexpected protocol %d with count %d", proto, c)
		}
	}
}

func TestFlowProfile_SampleDstPort_AllCovered(t *testing.T) {
	rng := rand.New(rand.NewSource(99))
	seen := map[uint16]bool{}
	for i := 0; i < 10000; i++ {
		seen[flowProfileEdgeRouter.SampleDstPort(rng)] = true
	}
	for _, pw := range flowProfileEdgeRouter.DstPorts {
		if !seen[pw.Port] {
			t.Errorf("port %d never sampled in 10000 draws", pw.Port)
		}
	}
}

func TestGetFlowProfile_KnownDevice(t *testing.T) {
	p := GetFlowProfile("cisco_nexus_9500.json")
	if p != flowProfileDCSwitch {
		t.Error("expected flowProfileDCSwitch for cisco_nexus_9500.json")
	}
}

func TestGetFlowProfile_UnknownDevice(t *testing.T) {
	p := GetFlowProfile("unknown_device.json")
	if p != flowProfileEdgeRouter {
		t.Error("expected fallback to flowProfileEdgeRouter for unknown device")
	}
}
