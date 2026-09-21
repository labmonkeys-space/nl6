/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"errors"
	"log"
	"net"
	"strings"
	"testing"
	"time"
)

// The three low-severity findings from the PR #672 review, each pinned.

// Applications() dereferenced the catalog while App, Len and MaxRecordSize
// were nil-safe, so an encoder over a nil catalog survived every flow tick
// and panicked inside Tick on the first template refresh, from the
// application-table loop.
func TestIPFIXAVCEncoderNilCatalogSurvivesTemplateRefresh(t *testing.T) {
	ln, _ := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	enc := NewIPFIXAVCEncoder(nil)
	if got := enc.Applications(); got != nil {
		t.Fatalf("Applications() on a nil catalog = %v, want nil", got)
	}
	if want := ipfixRecordSize + 4 + ipfixVarLenSize(len(avcHostPrefix)) + 1; enc.MaxRecordSize() != want {
		t.Fatalf("MaxRecordSize() on a nil catalog = %d, want %d (prefix + applicationId + prefix-only host field + empty URI field)", enc.MaxRecordSize(), want)
	}
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.61"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	// lastTempl zero: this tick is a template refresh and runs the
	// application-table loop.
	tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
}

// MaxRecordSize is computed once at construction; the value must equal what
// a fresh walk of the catalog produces, on a catalog whose worst case is
// neither the first nor the last entry.
func TestIPFIXAVCMaxRecordSizeIsPrecomputed(t *testing.T) {
	cat := newAVCCatalog([]avcApplication{
		{ID: avcApplicationID(13, 80), Name: "http", Hosts: []string{"a.example"}, URIs: []string{"/"}},
		{ID: avcApplicationID(13, 443), Name: "ssl", Hosts: []string{strings.Repeat("h", 300)}, URIs: []string{strings.Repeat("u", 260)}},
		{ID: avcApplicationID(3, 53), Name: "dns"},
	})
	enc := NewIPFIXAVCEncoder(cat)
	want := ipfixRecordSize + 4 + ipfixVarLenSize(len(avcHostPrefix)+300) + ipfixVarLenSize(263)
	if enc.MaxRecordSize() != want {
		t.Fatalf("MaxRecordSize = %d, want %d", enc.MaxRecordSize(), want)
	}
	if enc.MaxRecordSize() != avcWorstCaseRecordSize(cat) {
		t.Fatalf("precomputed %d disagrees with a fresh walk %d", enc.MaxRecordSize(), avcWorstCaseRecordSize(cat))
	}
}

// failAfterEncoder wraps the AVC encoder and returns a genuine encoder error
// once `fail` is set, so a test can drive the drop path and then the
// encode-error path on ONE exporter.
type failAfterEncoder struct {
	*IPFIXAVCEncoder
	fail bool
}

var errInjectedEncode = errors.New("injected encoder failure")

func (f *failAfterEncoder) EncodeMeasured(domainID, seqNo, uptimeMs uint32, records []FlowRecord, includeTemplate bool, buf []byte) (int, int, int, error) {
	if f.fail {
		return 0, 0, 0, errInjectedEncode
	}
	return f.IPFIXAVCEncoder.EncodeMeasured(domainID, seqNo, uptimeMs, records, includeTemplate, buf)
}

// The oversized-record drop and a genuine encoder error each get their own
// once-gated line. Sharing one gate let the first drop consume the line, so
// a later real encoder error, which stops emission for the device, was never
// logged.
func TestIPFIXAVCDropLogDoesNotConsumeEncodeErrorLog(t *testing.T) {
	ln, _ := testUDPListener(t)
	defer ln.Close()
	conn := testSender(t)
	defer conn.Close()
	addr := ln.LocalAddr().(*net.UDPAddr)

	var sink bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&sink)
	t.Cleanup(func() { log.SetOutput(prev) })

	cat := newAVCCatalog([]avcApplication{{ID: avcApplicationID(13, 80), Name: "http",
		Hosts: []string{"ok.example", strings.Repeat("z", 1500)}}})
	enc := &failAfterEncoder{IPFIXAVCEncoder: NewIPFIXAVCEncoder(cat)}
	prof := *mtuTestProfile()
	prof.ConcurrentFlows = 0
	fe := newTestFlowExporter(testDevice("10.1.2.62"), &prof, 10*time.Minute, 5*time.Minute, 10*time.Minute)
	fe.lastTempl = time.Now()
	past := time.Now().Add(-time.Hour)

	// Tick 1: one oversized record and one that fits; the drop line fires.
	fe.cache.Add(avcRecord(1, 2, 0, 49152), past)
	fe.cache.Add(avcRecord(1, 1, 0, 49153), past)
	if s := tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool()); s.SendFailures != 1 {
		t.Fatalf("tick 1 stats = %+v, want one drop", s)
	}
	// Tick 2: a second oversized record (suppressed) then a genuine error.
	fe.cache.Add(avcRecord(1, 2, 0, 49154), past)
	tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())
	enc.fail = true
	fe.cache.Add(avcRecord(1, 1, 0, 49155), past)
	tickWithEncoder(fe, time.Now(), enc, conn, addr, testPool())

	out := sink.String()
	if n := strings.Count(out, "exceeds the datagram budget"); n != 1 {
		t.Fatalf("drop line logged %d times, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, errInjectedEncode.Error()); n != 1 {
		t.Fatalf("encode-error line logged %d times, want 1 (the drop must not consume its gate):\n%s", n, out)
	}
}
