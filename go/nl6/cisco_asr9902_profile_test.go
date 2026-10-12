/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadCiscoAsr9902(t *testing.T) *DeviceResources {
	t.Helper()
	sm := &SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}
	res, err := sm.LoadSpecificResources("cisco_asr9902.json")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// sysObjectID and the chassis vendor type are ciscoASR9902 and
// cevChassisASR9902 (cisco/cisco-mibs c9ab98c0), not the values the asr9k profile serves.
func TestCiscoAsr9902_Identity(t *testing.T) {
	res := loadCiscoAsr9902(t)
	snmp := map[string]string{}
	for _, e := range res.SNMP {
		snmp[e.OID] = e.Response
	}
	if snmp["1.3.6.1.2.1.1.2.0"] != "1.3.6.1.4.1.9.1.3090" {
		t.Errorf("sysObjectID %q, want ciscoASR9902 1.3.6.1.4.1.9.1.3090", snmp["1.3.6.1.2.1.1.2.0"])
	}
	if snmp["1.3.6.1.2.1.47.1.1.1.1.3.1"] != "1.3.6.1.4.1.9.12.3.1.3.2432" {
		t.Errorf("entPhysicalVendorType.1 %q, want cevChassisASR9902", snmp["1.3.6.1.2.1.47.1.1.1.1.3.1"])
	}
	if d := snmp["1.3.6.1.2.1.1.1.0"]; !strings.Contains(d, "24.2.2") || !strings.Contains(d, "ASR9K") {
		t.Errorf("sysDescr %q, want the IOS-XR 24.2.2 ASR9K form", d)
	}
	if snmp["1.3.6.1.2.1.2.1.0"] != "50" {
		t.Errorf("ifNumber %q, want 50", snmp["1.3.6.1.2.1.2.1.0"])
	}
}

// show inventory, ENTITY-MIB and show interfaces brief describe one chassis.
// The gNMI leg is added with the catalogue (A3).
func TestCiscoAsr9902_SSHAgreesWithSNMP(t *testing.T) {
	res := loadCiscoAsr9902(t)
	ssh := map[string]string{}
	for _, e := range res.SSH {
		ssh[e.Command] = e.Response
	}
	inv, brief := ssh["show inventory"], ssh["show interfaces brief"]
	serials := map[string]bool{}
	for _, e := range res.SNMP {
		switch {
		case strings.HasPrefix(e.OID, "1.3.6.1.2.1.47.1.1.1.1.11.") && e.Response != "":
			serials[e.Response] = true
			if !strings.Contains(inv, "SN: "+e.Response) {
				t.Errorf("entPhysicalSerialNum %s not in show inventory", e.Response)
			}
		case strings.HasPrefix(e.OID, "1.3.6.1.2.1.2.2.1.2."):
			if !strings.Contains(brief, e.Response+" ") {
				t.Errorf("ifDescr %s not in show interfaces brief", e.Response)
			}
		}
	}
	for _, f := range strings.Fields(inv) {
		if strings.HasPrefix(f, "NL6") && !serials[f] {
			t.Errorf("show inventory serial %s is not an entPhysicalSerialNum", f)
		}
	}
	if len(serials) == 0 {
		t.Fatal("no entPhysicalSerialNum rows")
	}
}

// Nothing from the asr9k clone survives: no ASR 9010, no RSP, no bundle,
// no interface the ASR 9902 does not have.
func TestCiscoAsr9902_NoAsr9kLeftovers(t *testing.T) {
	files, err := filepath.Glob("resources/cisco_asr9902/*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("no profile files: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range []string{"ASR 9010", "ASR9010", "A9K-RSP", "RSP880", "Bundle-Ether", "0/2/0/", "1.3.6.1.4.1.9.12.3.1.3.1736", "1.3.6.1.4.1.9.12.3.1.3.1186"} {
			if strings.Contains(string(b), bad) {
				t.Errorf("%s still carries %q from asr9k", f, bad)
			}
		}
	}
}

// The hand-kept parts hold no row the generator owns.
func TestCiscoAsr9902_HandPartsLeaveTheGeneratorsRowsAlone(t *testing.T) {
	owned := []string{"1.3.6.1.2.1.2.1.", "1.3.6.1.2.1.2.2.", "1.3.6.1.2.1.31.1.1.", "1.3.6.1.2.1.47."}
	files, _ := filepath.Glob("resources/cisco_asr9902/cisco_asr9902_snmp_*.json")
	for _, f := range files {
		if strings.HasSuffix(f, "_snmp_chassis.json") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range owned {
			if strings.Contains(string(b), `"oid": "`+p) {
				t.Errorf("%s carries a row under %s, which cisco_asr9902_snmp_chassis.json owns", f, p)
			}
		}
	}
}

func TestCiscoAsr9902_SyslogOverlayLoads(t *testing.T) {
	universal, err := LoadEmbeddedSyslogCatalog()
	if err != nil {
		t.Fatal(err)
	}
	cats, err := ScanPerTypeSyslogCatalogs(universal, "resources")
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["cisco_asr9902"]
	if cat == nil {
		t.Fatal("no syslog overlay for cisco_asr9902")
	}
	down := cat.EntriesByRole("link-down")
	if len(down) != 2 {
		t.Fatalf("%d link-down entries, want the XR LINK and LINEPROTO pair", len(down))
	}
}

// The name-based classifiers must not fall through to "Other" and the
// generic Cisco label, which cisco_asr9902 does without its own clause.
func TestCiscoAsr9902_Classified(t *testing.T) {
	if got := getDeviceCategoryFromName("cisco_asr9902.json"); got != "Network Devices" {
		t.Errorf("category %q", got)
	}
	if got := getDeviceTypeFromName("cisco_asr9902.json"); got != "Cisco ASR 9902" {
		t.Errorf("type %q, want Cisco ASR 9902", got)
	}
	if deviceTypeLabels["cisco_asr9902"] != "Cisco ASR 9902" {
		t.Errorf("label %q", deviceTypeLabels["cisco_asr9902"])
	}
	if _, ok := deviceProfileMap["cisco_asr9902.json"]; !ok {
		t.Error("no device profile")
	}
}
