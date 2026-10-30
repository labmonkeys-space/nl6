/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

func TestNetconfDialectTable(t *testing.T) {
	cat, ok := netconfDialectFor(&DeviceSimulator{resourceFile: "cisco_catalyst_9500.json"})
	if !ok || cat.Name != "iosxe" || !cat.SSH || cat.TLS || cat.NewSession == nil {
		t.Errorf("cisco_catalyst_9500 = %+v, %v; want iosxe over SSH only", cat, ok)
	}
	mx, ok := netconfDialectFor(&DeviceSimulator{resourceFile: "juniper_mx10004.json"})
	if !ok || mx.Name != "junos" || !mx.SSH || !mx.TLS || mx.NewSession == nil {
		t.Errorf("juniper_mx10004 = %+v, %v; want junos over SSH and TLS", mx, ok)
	}
	if _, ok := netconfDialectFor(&DeviceSimulator{resourceFile: "juniper_mx960.json"}); ok {
		t.Error("juniper_mx960 has a dialect")
	}
	if _, ok := netconfDialectFor(nil); ok {
		t.Error("nil device has a dialect")
	}
}
