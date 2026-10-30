/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// netconfTLSBodyLimit is larger than the other REST bodies because a CA
// bundle can hold several certificates.
const netconfTLSBodyLimit = 64 << 10

func writeNetconfTLSIdentity(w http.ResponseWriter, id *NetconfTLSIdentity) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(id)
}

// netconfTLSGetHandler serves GET /api/v1/netconf/tls.
func netconfTLSGetHandler(w http.ResponseWriter, _ *http.Request) {
	if !manager.netconfSubsystemActive.Load() {
		sendErrorResponse(w, "NETCONF subsystem is not enabled", http.StatusNotFound)
		return
	}
	writeNetconfTLSIdentity(w, manager.netconfTLSIdentity.Load())
}

// netconfTLSPutHandler serves PUT /api/v1/netconf/tls. It replaces the whole
// table, so an omitted field clears it.
func netconfTLSPutHandler(w http.ResponseWriter, r *http.Request) {
	if !manager.netconfSubsystemActive.Load() {
		sendErrorResponse(w, "NETCONF subsystem is not enabled", http.StatusNotFound)
		return
	}
	var req NetconfTLSIdentity
	r.Body = http.MaxBytesReader(w, r.Body, netconfTLSBodyLimit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dec.More() {
		sendErrorResponse(w, "Invalid JSON: unexpected content after the request object", http.StatusBadRequest)
		return
	}
	if err := req.Validate(); err != nil {
		sendErrorResponse(w, err.Error(), http.StatusBadRequest)
		return
	}
	id := req.normalised()
	manager.netconfTLSIdentity.Store(id)
	writeNetconfTLSIdentity(w, id)
}

// tlsCAHandler serves GET /api/v1/tls/ca: the CA that signed the shared
// server certificate, so a client can trust it.
func tlsCAHandler(w http.ResponseWriter, _ *http.Request) {
	if len(manager.sharedTLSCAPEM) == 0 {
		sendErrorResponse(w, "no shared TLS certificate", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(manager.sharedTLSCAPEM)
}

// buildNetconfTLSIdentity assembles the startup identity from the three
// -netconf-tls-* identity flags. It returns nil when none is set.
func buildNetconfTLSIdentity(enabled bool, caPath string, pairs []string, defaultUser string) (*NetconfTLSIdentity, error) {
	if caPath == "" && len(pairs) == 0 && defaultUser == "" {
		return nil, nil
	}
	if !enabled {
		return nil, fmt.Errorf("-netconf-tls-client-ca, -netconf-tls-client-identity and -netconf-tls-default-username require -netconf-enable")
	}
	id := &NetconfTLSIdentity{Identities: map[string]string{}, DefaultUsername: defaultUser}
	if caPath != "" {
		pem, err := loadTLSCAFile(caPath, "-netconf-tls-client-ca")
		if err != nil {
			return nil, err
		}
		id.CAPEM = pem
	}
	for _, p := range pairs {
		fp, user, ok := strings.Cut(p, "=")
		if !ok || fp == "" || user == "" {
			return nil, fmt.Errorf("-netconf-tls-client-identity %q: want fingerprint=username", p)
		}
		norm, err := normaliseTLSFingerprint(fp)
		if err != nil {
			return nil, fmt.Errorf("-netconf-tls-client-identity: %w", err)
		}
		id.Identities[norm] = user
	}
	if err := id.Validate(); err != nil {
		return nil, err
	}
	return id, nil
}
