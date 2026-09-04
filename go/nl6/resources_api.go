/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"sync"
)

// ReloadResourcesRequest is the optional body of POST /api/v1/resources/reload.
// No body, or an object without resource_file, evicts every cached profile.
//
// A POINTER, so an explicit `"resource_file": ""` is distinguishable from an
// absent key: the empty string would otherwise silently mean "all", and a
// client that built the body from an empty variable would evict the whole
// cache while believing it named one type.
type ReloadResourcesRequest struct {
	ResourceFile *string `json:"resource_file"`
}

// logFirstReloadConflict once-gates the 409 log line. A client retrying every
// Retry-After for the whole of a 30k-device batch would otherwise write a line
// per retry; the other refusals are rare and are logged every time.
var logFirstReloadConflict sync.Once

// reloadResourcesHandler implements POST /api/v1/resources/reload (nl6#519).
//
// The endpoint EVICTS cached device profiles; it never rewrites one. A device
// created before the call keeps serving the set it was built from, a device
// created after it serves the file as it is now, and the response says which
// keys were evicted and how many devices still hold the old set per key.
//
// Same shape as fidelityToggleHandler: a bounded body, DisallowUnknownFields
// so a typo'd key is a 400, and a trailing second object rejected rather than
// silently dropped. The one difference is that the body is OPTIONAL — a bare
// POST means "all", so io.EOF on the decode is the empty request, not an error.
func reloadResourcesHandler(w http.ResponseWriter, r *http.Request) {
	var req ReloadResourcesRequest
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		// An over-long body is not malformed JSON; say what it is.
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			sendErrorResponse(w, "request body exceeds the 4 KiB limit for this endpoint", http.StatusRequestEntityTooLarge)
			return
		}
		sendErrorResponse(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if dec.More() {
		sendErrorResponse(w, "Invalid JSON: unexpected content after the request object",
			http.StatusBadRequest)
		return
	}

	resourceFile := ""
	if req.ResourceFile != nil {
		if *req.ResourceFile == "" {
			sendErrorResponse(w, `"resource_file" is empty; omit the field to evict every cached profile, `+
				`or name one as <device-type>.json`, http.StatusBadRequest)
			return
		}
		resourceFile = *req.ResourceFile
	}

	report, err := manager.ReloadResources(resourceFile)
	if err != nil {
		// 404 is this endpoint's own answer; the other three (409 for a running
		// batch, 400 for a bad or unshipped name, 500 otherwise) are the
		// device-creation mapping, reused so the two surfaces cannot disagree
		// on a sentinel. Every refusal is logged; the 409 once, since it is the
		// one a client retries in a loop.
		if errors.Is(err, errResourceNotCached) {
			log.Printf("resources reload: rejected with 404: %v", err)
			sendErrorResponse(w, err.Error(), http.StatusNotFound)
			return
		}
		msg, status := createDevicesErrorResponse(err)
		if status == http.StatusConflict {
			logFirstReloadConflict.Do(func() {
				log.Printf("resources reload: rejected with %d (logged once per process): %v", status, err)
			})
			w.Header().Set("Retry-After", createConflictRetryAfterSeconds)
		} else {
			log.Printf("resources reload: rejected with %d: %v", status, err)
		}
		sendErrorResponse(w, msg, status)
		return
	}
	sendDataResponse(w, report)
}
