/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// ciscoMnemonicShape matches a Cisco system-message identifier of the form
// FACILITY-SEVERITY-MNEMONIC, where the facility may carry sub-facilities
// (PKT_INFRA-LINK-3-UPDOWN) and the digit is the message's severity.
var ciscoMnemonicShape = regexp.MustCompile(`^[A-Z][A-Z0-9_]*(-[A-Z][A-Z0-9_]*)*-([0-7])-[A-Z][A-Z0-9_]*$`)

// ciscoMnemonicSeverity returns the severity digit spelled in a Cisco
// msgId, and false for any other identifier.
func ciscoMnemonicSeverity(msgID string) (SyslogSeverity, bool) {
	m := ciscoMnemonicShape.FindStringSubmatch(msgID)
	if m == nil {
		return 0, false
	}
	n, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, false
	}
	return SyslogSeverity(n), true
}

// TestShippedCiscoMnemonicsCarryTheirSeverity walks every shipped syslog
// catalog and checks that an entry whose msgId spells a Cisco severity
// digit sends at that severity. The IOS link entries once followed the link
// direction instead (link-up at notice, line-protocol-down at error), so a
// collector filtering on PRI saw one message at two severities.
func TestShippedCiscoMnemonicsCarryTheirSeverity(t *testing.T) {
	files, err := filepath.Glob("resources/*/syslog.json")
	if err != nil {
		t.Fatal(err)
	}
	matched := map[string]bool{}
	for _, f := range files {
		cat, err := LoadSyslogCatalogFromFile(f)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		for _, e := range cat.Entries {
			want, ok := ciscoMnemonicSeverity(e.MsgID)
			if !ok {
				continue
			}
			matched[filepath.Base(filepath.Dir(f))+"/"+e.Name] = true
			if e.Severity != want {
				t.Errorf("%s: entry %q msgId %s is sent at severity %d, the mnemonic says %d",
					f, e.Name, e.MsgID, e.Severity, want)
			}
		}
	}
	// Positive control: the scan must have seen the entries this guard was
	// written for, so an empty glob or a changed layout cannot pass it.
	for _, name := range []string{
		"cisco_ios/cisco-link-updown-up", "cisco_ios/cisco-link-updown-down",
		"cisco_ios/cisco-lineproto-updown-up", "cisco_ios/cisco-lineproto-updown-down",
		"cisco_asr9902/xr-link-updown-up", "cisco_asr9902/xr-link-updown-down",
		"cisco_asr9902/xr-lineproto-updown-up", "cisco_asr9902/xr-lineproto-updown-down",
	} {
		if !matched[name] {
			t.Errorf("positive control: %s was not scanned", name)
		}
	}
}

// TestCiscoMnemonicSeverityShape pins what the guard's shape accepts.
func TestCiscoMnemonicSeverityShape(t *testing.T) {
	cases := []struct {
		msgID string
		want  SyslogSeverity
		ok    bool
	}{
		{"LINK-3-UPDOWN", 3, true},
		{"LINEPROTO-5-UPDOWN", 5, true},
		{"PKT_INFRA-LINK-3-UPDOWN", 3, true},
		{"SYS-5-CONFIG_I", 5, true},
		{"SNMP_TRAP_LINK_DOWN", 0, false},
		{"LINK-8-UPDOWN", 0, false},
		{"link-3-updown", 0, false},
		{"", 0, false},
	}
	for _, c := range cases {
		got, ok := ciscoMnemonicSeverity(c.msgID)
		if ok != c.ok || got != c.want {
			t.Errorf("%q: got (%d, %v), want (%d, %v)", c.msgID, got, ok, c.want, c.ok)
		}
	}
}
