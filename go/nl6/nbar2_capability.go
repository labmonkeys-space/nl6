/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"fmt"
	"log"
	"sync"
)

// NBAR2 capability is CURATED, one row per shipped type with a written
// reason, and never derived from the slug. A strings.HasPrefix(rf, "cisco_")
// shortcut would admit cisco_nexus_9500 (NX-OS) and cisco_crs_x and asr9k
// (IOS-XR), none of which has NBAR2. That is the failure ownVendorPENs is
// curated to avoid and the reason the vendor-arc guard matches on a
// sub-identifier boundary rather than a string prefix.
//
// TestNbar2CapabilityCompleteness requires every shipped type to appear in
// exactly one of the two maps, so a new Cisco type cannot default in or out.
// Operator-supplied custom types are in neither map and are treated as
// incapable: the compiled-in maps are unreachable to them, and a record
// format is ground-truth-bearing (#364), so absence is the safe default.

// nbar2CapableTypes maps a resource file to why the platform has NBAR2.
var nbar2CapableTypes = map[string]string{
	"cisco_ios.json":           "IOS/IOS-XE NBAR2 (Application Visibility and Control) is the platform the AVC evidence base is sourced from",
	"cisco_catalyst_9500.json": "IOS-XE 17.x Catalyst 9000 AVC; the 45003/12235 platform number is unconfirmed by any Cisco document read (testdata/cisco-avc/NOTES.md)",
}

// nbar2IncapableTypes maps every other shipped resource file to why it has
// no NBAR2. Cisco platforms are named by OS so the prefix trap is visible.
var nbar2IncapableTypes = map[string]string{
	"asr9k.json":                   "IOS-XR: no NBAR2",
	"cisco_crs_x.json":             "IOS-XR: no NBAR2",
	"cisco_nexus_9500.json":        "NX-OS: no NBAR2",
	"arista_7280r3.json":           "EOS: no Cisco AVC export",
	"juniper_mx240.json":           "Junos: no Cisco AVC export",
	"juniper_mx960.json":           "Junos: no Cisco AVC export",
	"nokia_7750_sr12.json":         "SR OS: no Cisco AVC export",
	"huawei_ne8000.json":           "VRP: no Cisco AVC export",
	"nec_ix3315.json":              "NEC IX: no Cisco AVC export",
	"extreme_vsp4450.json":         "VOSS: no Cisco AVC export",
	"dlink_dgs3630.json":           "D-Link: no Cisco AVC export",
	"palo_alto_pa3220.json":        "PAN-OS classifies App-ID, not Cisco AVC",
	"fortinet_fortigate_600e.json": "FortiOS: no Cisco AVC export",
	"sonicwall_nsa6700.json":       "SonicOS: no Cisco AVC export",
	"check_point_15600.json":       "Gaia: no Cisco AVC export",
	"dell_poweredge_r750.json":     "server: no flow classification engine",
	"hpe_proliant_dl380.json":      "server: no flow classification engine",
	"ibm_power_s922.json":          "server: no flow classification engine",
	"linux_server.json":            "server: no flow classification engine",
	"nvidia_dgx_a100.json":         "server: no flow classification engine",
	"nvidia_dgx_h100.json":         "server: no flow classification engine",
	"nvidia_hgx_h200.json":         "server: no flow classification engine",
	"netapp_ontap.json":            "storage: no flow classification engine",
	"pure_storage_flasharray.json": "storage: no flow classification engine",
	"dell_emc_unity.json":          "storage: no flow classification engine",
	"aws_s3_storage.json":          "storage: no flow classification engine",
	"ciena_waveserver5.json":       "layer-1 optical transport: exports no flow at all (flowIncapableTypes)",
}

// SupportsNbar2 reports whether a device type can emit NBAR2 AVC records.
// Map lookup only, never a name test.
func SupportsNbar2(resourceFile string) bool {
	_, ok := nbar2CapableTypes[resourceFileKey(resourceFile)]
	return ok
}

// nbar2IncapableRequest is the third sibling of flowIncapableRequest and
// opticalIncapableRequest. It fires only when the request asks for NBAR2
// and the ENTIRE resolved type set is incapable, returning the offending
// resource file for the 400. A mixed round-robin batch is accepted, and the
// incapable devices in it are degraded per degradeNbar2IfIncapable.
func nbar2IncapableRequest(req CreateDevicesRequest) (string, bool) {
	if req.Flow == nil || !req.Flow.Nbar2 {
		return "", false
	}
	if !req.RoundRobin {
		// A request naming no resource file is created as the default type
		// (defaultResourceFile), which is itself incapable. Resolving it here
		// keeps that request from a 201 whose every device silently degraded
		// (review finding on the first cut of this gate).
		rf := effectiveResourceFile(req.ResourceFile)
		if !SupportsNbar2(rf) {
			return rf, true
		}
		return "", false
	}
	types := roundRobinTypesForCategory(req.Category)
	for _, rf := range types {
		if SupportsNbar2(rf) {
			return "", false
		}
	}
	if len(types) == 0 {
		return "", false
	}
	return types[0], true
}

// nbar2IncapableMessage is the 400 body for an entirely incapable request.
func nbar2IncapableMessage(rf string) string {
	reason := nbar2IncapableTypes[rf]
	if reason == "" {
		reason = "not a shipped NBAR2-capable type"
	}
	return fmt.Sprintf("device type %q has no NBAR2 (%s): flow.nbar2 applies only to %s; remove \"nbar2\" from the flow block",
		rf, reason, nbar2CapableTypeList())
}

func nbar2CapableTypeList() string {
	return "cisco_ios and cisco_catalyst_9500"
}

// nbar2DegradeLogged gates the per-type degradation log to one line per type.
var nbar2DegradeLogged sync.Map

// degradeNbar2IfIncapable is the per-device half of the mixed-batch rule,
// called from BOTH device-creation paths (they have diverged before) just
// before the flow exporter is attached. An NBAR2-incapable but flow-capable
// device in an accepted batch KEEPS its flow block with nbar2 cleared and
// emits the plain IPFIX record (template 256). This is deliberately not
// flow's skip, which attaches no flow block at all: the device's flow
// config is otherwise valid, so the record format degrades while export
// continues. The two outcomes differ in byte identity and in what the
// ground-truth join sees, which is why this comment and the docs say so.
func degradeNbar2IfIncapable(device *DeviceSimulator, resourceFile string) {
	resourceFile = effectiveResourceFile(resourceFile)
	cfg := device.flowConfig
	if cfg == nil || !cfg.Nbar2 {
		return
	}
	if cfg.Nbar2 = nbar2FieldFor(resourceFile, cfg.Nbar2); cfg.Nbar2 {
		return
	}
	if _, seen := nbar2DegradeLogged.LoadOrStore(resourceFile, struct{}{}); !seen {
		log.Printf("flow export: device type %s has no NBAR2 (%s); its devices keep their flow block and emit plain IPFIX (template 256), not AVC (further devices of this type not logged)",
			resourceFile, nbar2IncapableTypes[resourceFile])
	}
}

// effectiveResourceFile maps the empty resource file a create request may
// carry to the type the device is actually built as, and a bare slug to the
// ".json" key the capability and reason maps use.
func effectiveResourceFile(rf string) string {
	if rf == "" {
		return defaultResourceFile
	}
	return resourceFileKey(rf)
}

// nbar2FieldFor is what a created device stores and GET /api/v1/devices
// echoes: the requested value on a capable type, false everywhere else, so
// an incapable type never advertises a knob that does nothing there (the
// opticalScenarioFieldFor rule). With omitempty, false is absent.
func nbar2FieldFor(resourceFile string, requested bool) bool {
	return requested && SupportsNbar2(resourceFile)
}

// validateNbar2Seed is the startup half of the nbar2 protocol rule, pure so
// the fatal path is testable. It reuses DeviceFlowConfig.Validate's message
// so the flag and the REST field fail the same way, and additionally refuses
// -flow-nbar2 with no collector, since nothing would export.
func validateNbar2Seed(nbar2 bool, collector, protocol string) error {
	if !nbar2 {
		return nil
	}
	if collector == "" {
		return fmt.Errorf("-flow-nbar2 requires -flow-collector; without a collector no device exports and the flag would be accepted and ignored")
	}
	probe := DeviceFlowConfig{Collector: collector, Protocol: protocol, Nbar2: true}
	probe.ApplyDefaults()
	if err := probe.Validate(); err != nil {
		return fmt.Errorf("-flow-nbar2: %w", err)
	}
	return nil
}
