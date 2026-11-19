/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// client talks to the nl6 REST API.
type client struct {
	base string
	http *http.Client
}

// requestTimeout bounds one small JSON call, so a host that accepts a
// connection but never answers cannot hang the caller.
const requestTimeout = 10 * time.Second

func newClient(base string) client {
	return newClientTimeout(base, requestTimeout)
}

func newClientTimeout(base string, timeout time.Duration) client {
	return client{base: base, http: &http.Client{Timeout: timeout}}
}

// envelope is the {"success","message","data"} wrapper most endpoints use.
type envelope struct {
	Success bool            `json:"success"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data"`
}

// get decodes the envelope of a GET and returns its data member.
func (c client) get(path string) (json.RawMessage, error) {
	resp, err := c.http.Get(c.base + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("GET %s: read response: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s: %s", path, resp.Status, bytes.TrimSpace(body))
	}
	var env envelope
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("GET %s: bad response: %w", path, err)
	}
	return env.Data, nil
}

// version answers GET /api/v1/version, which is a bare {"version": "..."}
// without the envelope.
func (c client) version() (string, error) {
	resp, err := c.http.Get(c.base + "/api/v1/version")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GET /api/v1/version: %s", resp.Status)
	}
	var v struct {
		Version string `json:"version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return "", fmt.Errorf("GET /api/v1/version: bad response: %w", err)
	}
	return v.Version, nil
}

// status reports whether the creation gate is held (a batch or a profile
// reload) and how many devices exist.
func (c client) status() (batchInProgress bool, total int, err error) {
	data, err := c.get("/api/v1/status")
	if err != nil {
		return false, 0, err
	}
	var s struct {
		CreateBatchInProgress    bool `json:"create_batch_in_progress"`
		ResourceReloadInProgress bool `json:"resource_reload_in_progress"`
		TotalDevices             int  `json:"total_devices"`
	}
	if err := json.Unmarshal(data, &s); err != nil {
		return false, 0, fmt.Errorf("GET /api/v1/status: bad data: %w", err)
	}
	return s.CreateBatchInProgress || s.ResourceReloadInProgress, s.TotalDevices, nil
}

// createBatchBy posts one batch. A 409 means another batch holds the gate, so
// it waits Retry-After seconds and tries again until deadline, which the
// caller shares with other steps. budget is the whole of it, for the messages.
func (c client) createBatchBy(batch json.RawMessage, deadline time.Time, budget time.Duration) error {
	// A create call blocks until the whole batch ends, so it gets what is left
	// of the budget instead of the short per-request timeout.
	slow := *c.http
	for {
		slow.Timeout = time.Until(deadline)
		if slow.Timeout <= 0 { // 0 would mean no timeout at all
			return fmt.Errorf("create devices: not done after %s", budget)
		}
		resp, err := slow.Post(c.base+"/api/v1/devices", "application/json", bytes.NewReader(batch))
		if err != nil {
			// A batch that outlives the budget ends in the client timeout,
			// which names neither the budget nor the step.
			if time.Until(deadline) <= 0 {
				return fmt.Errorf("create devices: not done after %s: %w", budget, err)
			}
			return err
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("create devices: read response: %w", err)
		}
		switch {
		case resp.StatusCode == http.StatusConflict:
			wait := 5
			if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n >= 0 {
				wait = n
			}
			// No retry that could not start inside the budget.
			if time.Until(deadline) <= time.Duration(wait)*time.Second {
				return fmt.Errorf("create devices: still refused with 409 after %s: %s", budget, bytes.TrimSpace(body))
			}
			time.Sleep(time.Duration(wait) * time.Second)
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			return nil
		default:
			var env envelope
			msg := string(bytes.TrimSpace(body))
			if json.Unmarshal(body, &env) == nil && env.Message != "" {
				msg = env.Message
			}
			return fmt.Errorf("create devices: %s: %s", resp.Status, msg)
		}
	}
}

// deviceIPs lists the IPs of all devices, sorted.
func (c client) deviceIPs() ([]string, error) {
	data, err := c.get("/api/v1/devices")
	if err != nil {
		return nil, err
	}
	var devs []struct {
		IP string `json:"ip"`
	}
	if err := json.Unmarshal(data, &devs); err != nil {
		return nil, fmt.Errorf("GET /api/v1/devices: bad data: %w", err)
	}
	ips := make([]string, 0, len(devs))
	for _, d := range devs {
		ips = append(ips, d.IP)
	}
	sort.Strings(ips)
	return ips, nil
}

// scenarioConfig is the body of POST /api/v1/scenarios.
type scenarioConfig struct {
	Participants       []string `json:"participants"`
	Protocol           string   `json:"protocol"`
	Rate               float64  `json:"rate"`
	Window             string   `json:"window"`
	Seed               int64    `json:"seed,omitempty"` // nl6 reads a missing seed as 0
	ExpectParticipants int      `json:"expect_participants"`
}

type exclusion struct {
	Device          string `json:"device"`
	Reason          string `json:"reason"`
	RemediationHint string `json:"remediation_hint"`
}

type readiness struct {
	ParticipantsArmed int         `json:"participants_armed"`
	ExcludedTotal     int         `json:"excluded_total"`
	Excluded          []exclusion `json:"excluded"`
}

// scenario sends one scenario request and returns the raw body. The scenario
// endpoints return objects directly and report errors as {"error": "..."}.
func (c client) scenario(method, path string, body []byte) ([]byte, error) {
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		msg := string(bytes.TrimSpace(b))
		var e struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(b, &e) == nil && e.Error != "" {
			msg = e.Error
		}
		return nil, fmt.Errorf("%s %s: %s: %s", method, path, resp.Status, msg)
	}
	return b, nil
}

func (c client) submit(cfg scenarioConfig) (string, error) {
	body, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	b, err := c.scenario(http.MethodPost, "/api/v1/scenarios", body)
	if err != nil {
		return "", err
	}
	var r struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.ID == "" {
		return "", fmt.Errorf("submit scenario: bad response %q", b)
	}
	return r.ID, nil
}

func (c client) arm(id string) (readiness, error) {
	var r readiness
	b, err := c.scenario(http.MethodPost, "/api/v1/scenarios/"+id+"/arm", nil)
	if err != nil {
		return r, err
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return r, fmt.Errorf("arm scenario: bad response: %w", err)
	}
	return r, nil
}

func (c client) start(id string) error {
	_, err := c.scenario(http.MethodPost, "/api/v1/scenarios/"+id+"/start", nil)
	return err
}

func (c client) phase(id string) (string, error) {
	b, err := c.scenario(http.MethodGet, "/api/v1/scenarios/"+id, nil)
	if err != nil {
		return "", err
	}
	var r struct {
		Phase string `json:"phase"`
	}
	if err := json.Unmarshal(b, &r); err != nil || r.Phase == "" {
		return "", fmt.Errorf("scenario status: bad response %q", b)
	}
	return r.Phase, nil
}

// finalizeBudget bounds one stop call. nl6 reports phase "stopped" as soon as
// the window closes and answers a stop only after it finalized the scenario,
// which it bounds at 60s (finalizeBudget in go/nl6). The rest is slack.
const finalizeBudget = 75 * time.Second

// stop finalizes the scenario (idempotent after auto-close) and returns the
// raw report. It waits for the finalize, so it gets its own budget instead of
// the short per-request timeout.
func (c client) stop(id string) ([]byte, error) {
	slow := *c.http
	slow.Timeout = max(finalizeBudget, slow.Timeout)
	c.http = &slow
	return c.scenario(http.MethodPost, "/api/v1/scenarios/"+id+"/stop", nil)
}

func (c client) remove(id string) error {
	_, err := c.scenario(http.MethodDelete, "/api/v1/scenarios/"+id, nil)
	return err
}
