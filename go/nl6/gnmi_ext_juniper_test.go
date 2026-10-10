/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"

	"github.com/openconfig/gnmi/proto/gnmi_ext"
)

func TestJuniperHeaderRoundTrip(t *testing.T) {
	h := juniperHeader{
		SystemID: "vjunos-mx", ComponentID: 65535, SensorName: "sensor_1015_3_1",
		SubscribedPath: "/interfaces/interface/state/counters/", StreamedPath: "/interfaces/interface/state/counters/",
		Component: "xmlproxyd_TM_Thread_1", SequenceNumber: 42, ExportTimestamp: 1791558955621,
	}
	ext := juniperHeaderExtension(h)
	reg := ext.GetRegisteredExt()
	if reg == nil || reg.GetId() != gnmi_ext.ExtensionID(1) {
		t.Fatalf("extension not RegisteredExt id 1: %v", ext)
	}
	got, err := decodeJuniperHeader(reg.GetMsg())
	if err != nil {
		t.Fatal(err)
	}
	if got != h {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, h)
	}
}

func TestJuniperHeaderDecodeRejectsGarbage(t *testing.T) {
	if _, err := decodeJuniperHeader([]byte{0xff, 0xff}); err == nil {
		t.Fatal("garbage decoded")
	}
}
