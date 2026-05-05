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
	"encoding/binary"
	"fmt"
	"log"
	"sync/atomic"
	"time"
)

// Cisco NetFlow v5 wire constants. NetFlow v5 predates the RFC era and has no
// template mechanism; record layout is fixed at the protocol level.
const (
	netFlow5Version    = 5
	netFlow5MaxRecords = 30 // Cisco datagram cap; larger counts are rejected by strict collectors.
	netFlow5HeaderLen  = 24
	netFlow5RecordLen  = 48
	// netFlow5ASTrans is the "AS_TRANS" reserved ASN per RFC 6793 §2 (also
	// RFC 4893), used on the wire whenever a 32-bit ASN cannot be represented
	// in v5's 16-bit src_as/dst_as fields.
	netFlow5ASTrans = 23456 // 0x5BA0
)

// NetFlow5Encoder encodes FlowRecords into Cisco NetFlow v5 UDP payloads.
//
// Pointer-receiver deviation: unlike NetFlow9Encoder and IPFIXEncoder, which
// are value-typed and use value receivers, NetFlow5Encoder uses a pointer
// receiver because its atomic.Bool fields require it — copying the struct by
// value (e.g. via a `NetFlow5Encoder{}` literal in InitFlowExport) would
// silently produce a non-functional encoder whose one-shot state never persists.
// Always construct with `&NetFlow5Encoder{}`.
//
// The encoder is effectively stateless on the wire side — all variable state
// (sequence number, uptime, domain ID) flows in through EncodePacket so a
// single instance is shared across every device. The two atomic.Bool fields
// exist only to gate the first-skip / first-clamp warnings; because the
// encoder is fleet-wide rather than per-device, these warnings fire at most
// once per simulator lifetime — not per device. Losing the CAS race merely
// means no warning is emitted this time.
type NetFlow5Encoder struct {
	ipv6WarnOnce atomic.Bool
	asnWarnOnce  atomic.Bool
}

// SeqIncrement returns how much to advance flow_sequence after a packet that
// carried packetRecordCount data records.
//
// Cisco's v5 spec defines flow_sequence as "sequence counter of total flows
// seen" — i.e. the counter advances by the number of records in each packet,
// not once per packet. NetFlow9Encoder and IPFIXEncoder, by contrast, advance
// by 1 per packet (RFC 3954's "sequence number of all export packets" and
// RFC 7011's "per-SCTP-stream message count").
func (*NetFlow5Encoder) SeqIncrement(packetRecordCount int) int {
	return packetRecordCount
}

// PacketSizes returns the v5 per-packet overhead, template size (always 0 —
// v5 has no template mechanism), and per-record size. Tick() uses these to
// compute protocol-correct batch capacity.
func (*NetFlow5Encoder) PacketSizes() (int, int, int) {
	return netFlow5HeaderLen, 0, netFlow5RecordLen
}

// MaxRecordSize returns 0 because NetFlow v5 records are fixed-size at 48
// bytes on the wire; Tick paginates by PacketSizes()'s recordSize in that case.
func (*NetFlow5Encoder) MaxRecordSize() int { return 0 }

// EncodePacket serialises a complete NetFlow v5 UDP payload into buf and
// returns the number of bytes written.
//
// Parameters:
//
//	domainID        — accepted for interface compatibility with other encoders,
//	                  but unused on the v5 wire: there is no ObservationDomainID
//	                  field in v5, and the encoder's one-shot warnings are
//	                  fleet-wide (see struct doc) so they do not name a device.
//	seqNo           — flow_sequence (per Cisco v5 semantics: cumulative count
//	                  of records exported, advanced by the caller using
//	                  SeqIncrement).
//	uptimeMs        — device system uptime in milliseconds at export time.
//	records         — flow records to include. Non-IPv4 src/dst records are
//	                  silently filtered; a one-shot warning logs the first skip.
//	includeTemplate — ignored under v5 (no template mechanism exists).
//	buf             — caller-supplied output buffer; must be >= 24 + count*48.
//
// Records beyond the 30th are truncated — the ticker re-queues the remainder
// on the next call. Returns (0, nil) when no records would be written.
func (e *NetFlow5Encoder) EncodePacket(
	_ uint32,
	seqNo uint32,
	uptimeMs uint32,
	records []FlowRecord,
	_ bool,
	buf []byte,
) (int, error) {
	filtered := make([]FlowRecord, 0, len(records))
	for _, r := range records {
		if r.SrcIP.To4() == nil || r.DstIP.To4() == nil {
			if e.ipv6WarnOnce.CompareAndSwap(false, true) {
				// Fleet-wide one-shot: the NetFlow5Encoder instance is shared
				// across all devices, so this warning fires at most once per
				// simulator lifetime. The device identity is deliberately not
				// included — it would just name whichever device lost the CAS
				// race on the first IPv6 record, not a unique offender.
				log.Printf("netflow5: skipping non-IPv4 flow record (v5 is IPv4-only); this warning fires once per simulator lifetime across all devices")
			}
			continue
		}
		filtered = append(filtered, r)
	}

	if len(filtered) == 0 {
		return 0, nil
	}

	if len(filtered) > netFlow5MaxRecords {
		filtered = filtered[:netFlow5MaxRecords]
	}

	needed := netFlow5HeaderLen + len(filtered)*netFlow5RecordLen
	if len(buf) < needed {
		return 0, fmt.Errorf("netflow5: buffer too small (%d bytes), need at least %d", len(buf), needed)
	}

	now := time.Now()
	unixSecs := uint32(now.Unix())
	unixNsecs := uint32(now.Nanosecond())

	pos := 0

	// Packet Header (24 bytes).
	binary.BigEndian.PutUint16(buf[pos:], netFlow5Version)
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:], uint16(len(filtered)))
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:], uptimeMs)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], unixSecs)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], unixNsecs)
	pos += 4
	binary.BigEndian.PutUint32(buf[pos:], seqNo)
	pos += 4
	buf[pos] = 0 // engine_type
	pos++
	buf[pos] = 0 // engine_id
	pos++
	binary.BigEndian.PutUint16(buf[pos:], 0) // sampling_interval
	pos += 2

	for _, r := range filtered {
		pos = e.encodeRecord(buf, pos, r)
	}

	return pos, nil
}

// encodeRecord writes one 48-byte v5 record in canonical field order.
// Returns the new position.
func (e *NetFlow5Encoder) encodeRecord(buf []byte, pos int, r FlowRecord) int {
	// srcaddr (4) — filter above guarantees To4() is non-nil.
	copy(buf[pos:], r.SrcIP.To4())
	pos += 4
	// dstaddr (4)
	copy(buf[pos:], r.DstIP.To4())
	pos += 4
	// nexthop (4) — non-IPv4 (or nil) nexthop coerces to 0.0.0.0.
	nh := r.NextHop.To4()
	if nh == nil {
		nh = []byte{0, 0, 0, 0}
	}
	copy(buf[pos:], nh)
	pos += 4
	// input ifIndex (2)
	binary.BigEndian.PutUint16(buf[pos:], r.InIface)
	pos += 2
	// output ifIndex (2)
	binary.BigEndian.PutUint16(buf[pos:], r.OutIface)
	pos += 2
	// dPkts (4)
	binary.BigEndian.PutUint32(buf[pos:], r.Packets)
	pos += 4
	// dOctets (4) — FlowRecord.Bytes is uint64; v5 is 32-bit. Clamp to avoid wrap.
	octets := r.Bytes
	if octets > 0xFFFFFFFF {
		octets = 0xFFFFFFFF
	}
	binary.BigEndian.PutUint32(buf[pos:], uint32(octets))
	pos += 4
	// first (4) — SysUptime ms at flow start
	binary.BigEndian.PutUint32(buf[pos:], r.StartMs)
	pos += 4
	// last (4) — SysUptime ms at last packet
	binary.BigEndian.PutUint32(buf[pos:], r.EndMs)
	pos += 4
	// srcport (2)
	binary.BigEndian.PutUint16(buf[pos:], r.SrcPort)
	pos += 2
	// dstport (2)
	binary.BigEndian.PutUint16(buf[pos:], r.DstPort)
	pos += 2
	// pad1 (1)
	buf[pos] = 0
	pos++
	// tcp_flags (1)
	buf[pos] = r.TCPFlags
	pos++
	// prot (1)
	buf[pos] = r.Protocol
	pos++
	// tos (1)
	buf[pos] = r.ToS
	pos++
	// src_as (2) — clamp to AS_TRANS (23456, RFC 6793 §2) if a future schema
	// widening lets > 16-bit ASNs reach this encoder. Today FlowRecord.SrcAS is
	// uint16 so this is defence-in-depth; the branch is unreachable under the
	// current schema.
	binary.BigEndian.PutUint16(buf[pos:], e.clampASN(uint32(r.SrcAS)))
	pos += 2
	// dst_as (2)
	binary.BigEndian.PutUint16(buf[pos:], e.clampASN(uint32(r.DstAS)))
	pos += 2
	// src_mask (1)
	buf[pos] = r.SrcMask
	pos++
	// dst_mask (1)
	buf[pos] = r.DstMask
	pos++
	// pad2 (2)
	binary.BigEndian.PutUint16(buf[pos:], 0)
	pos += 2
	return pos
}

// clampASN returns the 16-bit wire value for an ASN, substituting AS_TRANS
// (23456, per RFC 6793 §2) when the input exceeds 16 bits and emitting a
// one-shot log per simulator lifetime on the first clamp. The encoder
// instance is fleet-wide, so the warning does not identify a specific
// device — see the NetFlow5Encoder struct doc.
func (e *NetFlow5Encoder) clampASN(asn uint32) uint16 {
	if asn > 0xFFFF {
		if e.asnWarnOnce.CompareAndSwap(false, true) {
			log.Printf("netflow5: clamping 32-bit ASN %d to AS_TRANS (%d); this warning fires once per simulator lifetime across all devices", asn, netFlow5ASTrans)
		}
		return netFlow5ASTrans
	}
	return uint16(asn)
}
