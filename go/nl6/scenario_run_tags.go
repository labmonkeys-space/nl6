/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "fmt"

// scenario_run_tags.go — per-protocol run tagging (story 5.5, FR37). A run's
// traffic is isolated from background noise by each protocol's native lever;
// the report's metadata.run_tags records the mechanism + value so a receiver
// knows how to filter. This is "tag what exists": the no-PEN levers (v9 Source
// ID, IPFIX ODID, sFlow sub_agent_id, gNMI prefix Target) are already emitted
// by the encoders; PEN-dependent levers (syslog SD-PARAM, SNMP enterprise
// varbind) degrade to window + source-IP when no PEN is configured.

// run-tag mechanism identifiers (wire-lever names; stable report vocabulary).
const (
	tagSyslogSDParam     = "syslog_sd_param"
	tagSNMPEnterprise    = "snmp_enterprise_varbind"
	tagNetflow9SourceID  = "netflow9_source_id"
	tagIPFIXODID         = "ipfix_odid"
	tagSFlowSubAgentID   = "sflow_sub_agent_id"
	tagGNMISyntheticPath = "gnmi_synthetic_path"
	tagWindowSourceIP    = "window_source_ip"
)

// runTags describes how a run's traffic is tagged for one protocol (FR37).
// Value is the run identifier a receiver filters on (the scenario ID); for the
// numeric levers it is the logical run label to correlate with the device's
// configured field. Serialized as metadata.run_tags.
type runTags struct {
	Protocol    string `json:"protocol"`
	Mechanism   string `json:"mechanism"`
	Value       string `json:"value"`
	PEN         uint32 `json:"pen"`          // the PEN in effect; 0 = none configured
	PENRequired bool   `json:"pen_required"` // does the clean lever need a PEN?
	Degraded    bool   `json:"degraded"`     // true when a PEN-required lever fell back to window+source-IP
	Note        string `json:"note"`
}

// buildRunTags computes the run-tag descriptor for a scenario's protocol given
// the configured PEN (0 = none) and the run's scenario ID. PEN-dependent
// levers degrade to window+source-IP when pen == 0.
func buildRunTags(protocol string, pen uint32, scenarioID string) runTags {
	rt := runTags{Protocol: protocol, Value: scenarioID, PEN: pen}
	switch protocol {
	case "netflow9":
		rt.Mechanism = tagNetflow9SourceID
		rt.Note = "receiver isolates by the device's NetFlow v9 Source ID within [t0,t1)"
	case "ipfix":
		// ODID is a native IPFIX field — no PEN needed (enterprise IE, the
		// secondary lever, would need one, but ODID alone suffices).
		rt.Mechanism = tagIPFIXODID
		rt.Note = "receiver isolates by the device's IPFIX Observation Domain ID within [t0,t1)"
	case "sflow":
		rt.Mechanism = tagSFlowSubAgentID
		rt.Note = "receiver isolates by the device's sFlow sub_agent_id within [t0,t1)"
	case "gnmi-dialout":
		// Dial-out already stamps Notification.Prefix.Target = device IP; that
		// in-band identity is the synthetic-path lever.
		rt.Mechanism = tagGNMISyntheticPath
		rt.Note = "dial-out carries the device IP in Notification.Prefix.Target; isolate by target within [t0,t1)"
	case "netflow5":
		// No in-band lever exists; window + source-IP is the native isolation,
		// not a degradation.
		rt.Mechanism = tagWindowSourceIP
		rt.Value = ""
		rt.Note = "NetFlow v5 has no taggable field; isolate by participant source IPs within [t0,t1)"
	case "syslog":
		if pen == 0 {
			rt.Mechanism = tagWindowSourceIP
			rt.Value = ""
			rt.PENRequired = true
			rt.Degraded = true
			rt.Note = "no PEN configured (-scenario-pen); SD-PARAM lever unavailable, isolate by source IP + [t0,t1)"
		} else {
			rt.Mechanism = tagSyslogSDParam
			rt.PENRequired = true
			rt.Value = fmt.Sprintf("[nl6@%d runId=\"%s\"]", pen, scenarioID)
			rt.Note = "RFC 5424 structured-data element; receivers key on the runId SD-PARAM"
		}
	case "snmp-trap":
		if pen == 0 {
			rt.Mechanism = tagWindowSourceIP
			rt.Value = ""
			rt.PENRequired = true
			rt.Degraded = true
			rt.Note = "no PEN configured (-scenario-pen); enterprise-varbind lever unavailable, isolate by source IP + [t0,t1)"
		} else {
			rt.Mechanism = tagSNMPEnterprise
			rt.PENRequired = true
			rt.Note = fmt.Sprintf("enterprise varbind under PEN %d carrying the run identifier", pen)
		}
	default:
		rt.Mechanism = tagWindowSourceIP
		rt.Value = ""
		rt.Note = "no protocol-specific lever; isolate by participant source IPs within [t0,t1)"
	}
	return rt
}
