/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

type runOptions struct {
	Protocol string
	Rate     float64
	Window   time.Duration
	Seed     int64
	Timeout  time.Duration                                      // budget of one API call, default requestTimeout
	Report   string                                             // default <state dir>/report.json
	Grace    time.Duration                                      // extra wait after the window, default 60s
	Poll     time.Duration                                      // default 1s
	inspect  func(pid int, comm string, start uint64) procState // nil means inspectProc (tests)
}

// run drives one scenario window and saves its report.
func run(dir string, o runOptions, out io.Writer) error {
	if o.Report == "" {
		o.Report = filepath.Join(dir, "report.json")
	}
	// The state comes first. Without a fixture run must not touch the report
	// path: after down it still holds the report of the finished cycle.
	s, err := loadState(dir)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("no running fixture, run nl6-ci up first")
	}
	if err != nil {
		return err
	}
	// The report of an earlier run goes next. A run that fails before it
	// writes its own would leave it for check, which would verify and pass it.
	if err := os.Remove(o.Report); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove the earlier report: %w", err)
	}
	// Probe the report path now. An unwritable one would otherwise show only
	// after the whole window.
	if err := writeFile(o.Report, nil); err != nil {
		return fmt.Errorf("the report path is not writable: %w", err)
	}
	if err := os.Remove(o.Report); err != nil {
		return fmt.Errorf("the report path is not writable: %w", err)
	}
	if o.Grace == 0 {
		o.Grace = 60 * time.Second
	}
	if o.Poll == 0 {
		o.Poll = time.Second
	}
	if o.inspect == nil {
		o.inspect = inspectProc
	}
	if o.Timeout == 0 {
		o.Timeout = requestTimeout
	}
	c := newClientTimeout(s.API, o.Timeout)
	ips, err := c.deviceIPs()
	if err != nil {
		return fmt.Errorf("list devices: %w", err)
	}
	if len(ips) == 0 {
		return errors.New("the fixture has no devices")
	}
	if len(ips) != s.Devices {
		return fmt.Errorf("the fixture has %d devices, up created %d", len(ips), s.Devices)
	}
	id, err := c.submit(scenarioConfig{
		Participants:       ips,
		Protocol:           o.Protocol,
		Rate:               o.Rate,
		Window:             o.Window.String(),
		Seed:               o.Seed,
		ExpectParticipants: len(ips),
	})
	if err != nil {
		return fmt.Errorf("submit scenario: %w", err)
	}
	ready, err := c.arm(id)
	if err != nil {
		_ = c.remove(id) // best-effort cleanup, the original error is returned
		return fmt.Errorf("arm scenario %s: %w", id, err)
	}
	if ready.ExcludedTotal > 0 {
		for _, e := range ready.Excluded {
			_, _ = fmt.Fprintf(out, "run: excluded %s: %s. %s\n", e.Device, e.Reason, e.RemediationHint)
		}
		_ = c.remove(id) // best-effort cleanup, the original error is returned
		return fmt.Errorf("%d of %d devices were excluded from scenario %s", ready.ExcludedTotal, len(ips), id)
	}
	if err := c.start(id); err != nil {
		_ = c.remove(id) // best-effort cleanup, the original error is returned
		return fmt.Errorf("start scenario %s: %w", id, err)
	}
	deadline := time.Now().Add(o.Window + o.Grace)
	for {
		p, err := c.phase(id)
		// A failed poll ends the run only when nl6 is gone. A busy nl6 that
		// missed one answer gets the rest of the window.
		if err != nil && o.inspect(s.PID, procComm(s.NL6), s.StartTicks) != procOurs {
			return failWindow(out, s.Log, fmt.Sprintf("nl6 (pid %d) is gone: %v", s.PID, err))
		}
		if err == nil && (p == "stopped" || p == "aborted") {
			break
		}
		if time.Now().After(deadline) {
			// An nl6 that does not answer gets no stop: the call would wait
			// out the whole finalize budget.
			if err != nil {
				return failWindow(out, s.Log, fmt.Sprintf("no status after %s: %v", o.Window+o.Grace, err))
			}
			_, _ = c.stop(id) // best-effort, so the devices are free for the next run
			return failWindow(out, s.Log, fmt.Sprintf("still %q after %s", p, o.Window+o.Grace))
		}
		time.Sleep(o.Poll)
	}
	report, err := c.stop(id)
	if err != nil {
		return fmt.Errorf("fetch report for %s: %w", id, err)
	}
	// The report is saved before it is verified, so a refused report stays
	// available for diagnosis. check verifies it again and refuses it too.
	if err := writeFile(o.Report, report); err != nil {
		return err
	}
	if err := verifyReport(report, len(ips), s.Started); err != nil {
		return fmt.Errorf("%w (report %s)", err, o.Report)
	}
	var r struct {
		Summary struct {
			Sent uint64 `json:"sent"`
		} `json:"summary"`
	}
	_ = json.Unmarshal(report, &r) // verifyReport already parsed this report
	_, _ = fmt.Fprintf(out, "run: sent %d records from %d devices, report %s\n", r.Summary.Sent, len(ips), o.Report)
	return nil
}

func failWindow(out io.Writer, logPath, why string) error {
	_, _ = fmt.Fprintf(out, "run: nl6 log (tail) %s:\n%s", logPath, tailFile(logPath, logTail))
	return fmt.Errorf("nl6 did not finish the window: %s", why)
}

// verifyReport refuses a report that would let a broken run look green.
// wantDevices 0 means the device count is unknown and is not compared.
// started is when up started the fixture. The zero time means unknown, and
// the window start is not compared.
func verifyReport(report []byte, wantDevices int, started time.Time) error {
	var r struct {
		Summary struct {
			Phase    string `json:"phase"`
			Metadata struct {
				T0              string   `json:"t0"`
				DrainStragglers int64    `json:"drain_stragglers"`
				IncompleteJoins []string `json:"incomplete_joins"`
			} `json:"metadata"`
			ParticipantsArmed int    `json:"participants_armed"`
			Sent              uint64 `json:"sent"` // unsigned as in nl6, so a negative count fails to decode
		} `json:"summary"`
		Counters []struct {
			SourceIP string `json:"source_ip"`
			Sent     uint64 `json:"sent"`
		} `json:"counters"`
	}
	if err := json.Unmarshal(report, &r); err != nil {
		return fmt.Errorf("not an nl6 scenario report: %w", err)
	}
	if r.Summary.Phase == "aborted" {
		return errors.New("scenario aborted")
	}
	if r.Summary.Phase != "stopped" {
		return fmt.Errorf("report phase is %q, want stopped", r.Summary.Phase)
	}
	// Scenario ids restart with every nl6, so the window start is what ties a
	// report to this fixture. A report without one cannot be from it.
	if !started.IsZero() {
		t0, err := time.Parse(time.RFC3339, r.Summary.Metadata.T0)
		if err != nil || t0.Before(started.Truncate(time.Second)) {
			return fmt.Errorf("the report is not from this fixture: its window started at %q, the fixture at %s. Run nl6-ci run first",
				r.Summary.Metadata.T0, started.UTC().Format(time.RFC3339))
		}
	}
	// nl6 sets these only when its finalize ran out of budget. The report was
	// then taken while sends were still moving, so its counters are a lower
	// bound and an exact reconcile against them proves nothing.
	if m := r.Summary.Metadata; m.DrainStragglers != 0 || len(m.IncompleteJoins) > 0 {
		return fmt.Errorf("nl6 cut its finalize short (drain_stragglers %d, incomplete_joins %v), so the counters are a lower bound. Run nl6-ci run again",
			m.DrainStragglers, m.IncompleteJoins)
	}
	if wantDevices > 0 && r.Summary.ParticipantsArmed != wantDevices {
		return fmt.Errorf("%d devices took part, the fixture has %d", r.Summary.ParticipantsArmed, wantDevices)
	}
	if r.Summary.Sent == 0 {
		return errors.New("nothing was sent")
	}
	// Without counter rows nl6-reconcile joins nothing and passes.
	if len(r.Counters) == 0 {
		return errors.New("the report has no counters")
	}
	// nl6 writes one row per armed device. Fewer rows mean a cut report.
	if len(r.Counters) != r.Summary.ParticipantsArmed {
		return fmt.Errorf("the report has %d counter rows for %d devices", len(r.Counters), r.Summary.ParticipantsArmed)
	}
	// A device with zero sent is refused, so a silent device cannot pass. A
	// healthy device sends nothing too when the window is shorter than its own
	// export interval: gNMI dial-out samples every 10s and a flow exporter
	// ticks every 5s by default, whatever the rate. That is a false red, never
	// a false green, so the rule stays and the message names both causes. A
	// rate_profile (a Poisson draw) would add a third: see nl6#1053.
	for _, c := range r.Counters {
		if c.Sent == 0 {
			return fmt.Errorf("device %s sent nothing. Either the device is faulty, or the window is shorter than its export interval", c.SourceIP)
		}
	}
	return nil
}
