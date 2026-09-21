/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"strings"
	"testing"
)

// The dry render sizes the host field WITH avcHostPrefix (nl6#679): an entry
// that fit an empty datagram before the prefix and misses it by fewer than
// six bytes after is disabled. The threshold is MEASURED by walking budgets
// through the production ApplySizeBudget, then compared with the arithmetic
// that includes the prefix, so an encoder that dropped the prefix (or a
// bound that stopped counting it) moves the measured threshold by six and
// fails here.
func TestNbar2DryRenderCountsHostPrefix(t *testing.T) {
	const hostLen = 20
	entry := `{"name":"h","engine":3,"selector":80,"proto":"tcp","dst_port":80,"hosts":[{"value":"` + strings.Repeat("h", hostLen) + `"}]}`
	minAdmitting := 0
	for budget := ipfixHeaderSize + ipfixDataSetHdrSize; budget < 400; budget++ {
		cat, err := parseNbar2Catalog(nbar2JSON("", entry), "p")
		if err != nil {
			t.Fatal(err)
		}
		if len(cat.ApplySizeBudget(budget, "p")) == 0 {
			minAdmitting = budget
			break
		}
	}
	if minAdmitting == 0 {
		t.Fatal("no budget under 400 bytes admits a 20-byte-host entry")
	}
	// Message header, data set header, the record (54-byte prefix,
	// applicationId, host field = 1 length byte + prefix + host, URI field = 1
	// length byte for an empty value), plus EncodeMeasured's 3-byte pad margin.
	want := ipfixHeaderSize + ipfixDataSetHdrSize + ipfixRecordSize + 4 + ipfixVarLenSize(len(avcHostPrefix)+hostLen) + ipfixVarLenSize(0) + 3
	if minAdmitting != want {
		t.Fatalf("smallest admitting budget = %d, want %d (the host field must be sized WITH the %d-byte prefix)", minAdmitting, want, len(avcHostPrefix))
	}
	// The budget that admitted the bare-host record before nl6#679 now
	// disables the entry, and the startup line names the six-byte gap.
	cat, _ := parseNbar2Catalog(nbar2JSON("", entry), "p")
	disabled := cat.ApplySizeBudget(minAdmitting-len(avcHostPrefix), "p")
	if len(disabled) != 1 || !strings.Contains(disabled[0], "p/h (") || !strings.Contains(disabled[0], "over the") {
		t.Fatalf("at the pre-prefix budget: disabled = %v, want the entry named with its size and gap", disabled)
	}
	if !strings.Contains(disabled[0], "by 3 B") {
		// size - budget: the 3-byte pad margin is headroom, not record bytes,
		// so the reported gap is 6 - 3.
		t.Fatalf("gap line = %q, want the six-byte shortfall net of the pad margin (by 3 B)", disabled[0])
	}
}
