/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/binary"
	"fmt"
	"math"
)

// UDP-notif (draft-ietf-netconf-udp-notif) framing. Layout follows NetGauze
// udp-notif-pkt wire/serialize.rs: byte 0 is version<<5 | S<<4 | MT, byte 1 the
// header length, bytes 2-3 the message length (header plus payload), then the
// observation domain id and message id, then options.
const (
	udpNotifMediaJSON  = 1 // application/yang-data+json
	udpNotifBaseHeader = 12
	udpNotifSegHeader  = udpNotifBaseHeader + 4 // segment option: type 1, length 4, number<<1|last
	// The captured VRP device sizes its first segment 9 bytes below the later
	// ones (1427 vs 1436 on the wire, max-segment-size 1436 is the whole UDP
	// payload including the header). The cause is unknown, the fixture pins it.
	udpNotifFirstSegShortfall = 9
)

// udpNotifFrame wraps payload in UDP-notif datagrams. segSize is the maximum
// UDP payload per datagram, header included. A payload that fits is returned as
// one unsegmented datagram. Otherwise every datagram carries the segment option.
// It panics when segSize leaves no room for payload, which is a caller bug.
func udpNotifFrame(publisherID, messageID uint32, payload []byte, segSize int) [][]byte {
	if segSize <= udpNotifSegHeader+udpNotifFirstSegShortfall {
		panic(fmt.Sprintf("udpNotifFrame: segSize %d leaves no room for payload", segSize))
	}
	if segSize > math.MaxUint16 {
		panic(fmt.Sprintf("udpNotifFrame: segSize %d overflows the 16-bit message length", segSize))
	}
	if udpNotifBaseHeader+len(payload) <= segSize {
		d := make([]byte, udpNotifBaseHeader, udpNotifBaseHeader+len(payload))
		putUdpNotifBase(d, udpNotifBaseHeader, publisherID, messageID, udpNotifBaseHeader+len(payload))
		return [][]byte{append(d, payload...)}
	}
	var out [][]byte
	room := segSize - udpNotifSegHeader - udpNotifFirstSegShortfall
	for n := 0; ; n++ {
		chunk := min(room, len(payload))
		last := chunk == len(payload)
		d := make([]byte, udpNotifSegHeader, udpNotifSegHeader+chunk)
		putUdpNotifBase(d, udpNotifSegHeader, publisherID, messageID, udpNotifSegHeader+chunk)
		d[12], d[13] = 1, 4
		opt := uint16(n) << 1
		if last {
			opt |= 1
		}
		binary.BigEndian.PutUint16(d[14:16], opt)
		out = append(out, append(d, payload[:chunk]...))
		payload = payload[chunk:]
		if last {
			return out
		}
		room = segSize - udpNotifSegHeader
	}
}

func putUdpNotifBase(d []byte, headerLen int, publisherID, messageID uint32, msgLen int) {
	d[0] = 1<<5 | udpNotifMediaJSON
	d[1] = byte(headerLen)
	binary.BigEndian.PutUint16(d[2:4], uint16(msgLen))
	binary.BigEndian.PutUint32(d[4:8], publisherID)
	binary.BigEndian.PutUint32(d[8:12], messageID)
}
