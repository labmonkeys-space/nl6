/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func netconfTLSDo(t *testing.T, h http.HandlerFunc, method, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/api/v1/netconf/tls", strings.NewReader(body))
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

func TestNetconfTLSAPIRoundTrip(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	if rec := netconfTLSDo(t, netconfTLSGetHandler, "GET", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), "null") {
		t.Fatalf("empty GET = %d %s", rec.Code, rec.Body.String())
	}
	caPEM, _ := newTestCAPEM(t)
	body := `{"ca_pem":` + jsonString(caPEM) + `,"identities":{"` + strings.ToLower(probeClientFingerprint[3:]) + `":"alice"},"default_username":"bob"}`
	if rec := netconfTLSDo(t, netconfTLSPutHandler, "PUT", body); rec.Code != 200 {
		t.Fatalf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	rec := netconfTLSDo(t, netconfTLSGetHandler, "GET", "")
	out := rec.Body.String()
	if !strings.Contains(out, probeClientFingerprint) || !strings.Contains(out, "alice") || !strings.Contains(out, "BEGIN CERTIFICATE") || !strings.Contains(out, "bob") {
		t.Errorf("GET did not echo the table: %s", out)
	}
	if strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("key material in body: %s", out)
	}
	if got := mgr.netconfTLSIdentity.Load().Identities[probeClientFingerprint]; got != "alice" {
		t.Errorf("stored table not normalised: %v", mgr.netconfTLSIdentity.Load().Identities)
	}
}

func TestNetconfTLSAPIRefusesBadPEM(t *testing.T) {
	mgr := useNetconfTestManager(t, true)
	keyOnly := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}))
	rec := netconfTLSDo(t, netconfTLSPutHandler, "PUT", `{"ca_pem":`+jsonString(keyOnly)+`}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("PUT = %d %s", rec.Code, rec.Body.String())
	}
	if rec := netconfTLSDo(t, netconfTLSPutHandler, "PUT", `{"bogus":1}`); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown field = %d", rec.Code)
	}
	if mgr.netconfTLSIdentity.Load().CAPEM != "" {
		t.Error("table changed by a refused PUT")
	}
	off := useNetconfTestManager(t, false)
	_ = off
	if rec := netconfTLSDo(t, netconfTLSGetHandler, "GET", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET with subsystem off = %d", rec.Code)
	}
	if rec := netconfTLSDo(t, netconfTLSPutHandler, "PUT", `{}`); rec.Code != http.StatusNotFound {
		t.Errorf("PUT with subsystem off = %d", rec.Code)
	}
}

func TestTLSCAEndpoint(t *testing.T) {
	mgr := useNetconfTestManager(t, false)
	req := httptest.NewRequest("GET", "/api/v1/tls/ca", nil)
	rec := httptest.NewRecorder()
	tlsCAHandler(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("no shared cert = %d", rec.Code)
	}
	mgr.generateSharedTLSCert()
	rec = httptest.NewRecorder()
	tlsCAHandler(rec, req)
	if rec.Code != 200 || rec.Header().Get("Content-Type") != "application/x-pem-file" {
		t.Fatalf("GET = %d %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	blk, rest := pem.Decode(rec.Body.Bytes())
	if blk == nil || blk.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("body is not one certificate: %q", rec.Body.String())
	}
	ca, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(mgr.sharedTLSCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.CheckSignatureFrom(ca); err != nil {
		t.Errorf("served CA did not sign the shared cert: %v", err)
	}
}
