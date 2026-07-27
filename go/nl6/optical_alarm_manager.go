/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"log"
	"net"
)

// optical_alarm_manager.go — turns an SD/SF threshold crossing into a Ciena
// notification (#347, tasks 6.7-6.8). The detection half is optical_alarm.go;
// this is the publication half.
//
// It mirrors wireStateNotify's discipline exactly, because the hazards are the
// same: snapshot the exporters under the device read lock, then fire OUTSIDE
// it so a UDP send never holds a device lock, and rely on each exporter's
// `closing` guard to make the snapshot-then-fire window safe against a
// concurrent teardown.
//
// The one structural difference from the link-state wiring is the role model.
// A link transition picks one of two roles because linkDown and linkUp are
// distinct notifications. An optical transition picks one of FOUR, because
// Ciena publishes raise and clear as the same notification type with different
// varbind values — see the role constants in trap_catalog.go.

// StartOpticalAlarmSubsystem builds the shared evaluator, wires its notify hook
// to the trap and syslog exporters, and starts the single evaluator goroutine.
// Started UNCONDITIONALLY, before any device exists — like every other
// subsystem — so devices created later (auto-start batch, REST) enrol as they
// come up. A packet-only fleet costs one idle goroutine parked on an empty
// heap.
//
// Stop happens in manager.Shutdown alongside the peer subsystems; there is no
// runtime restart path (it would need attach-path lock discipline that does
// not exist yet).
func (sm *SimulatorManager) StartOpticalAlarmSubsystem(ctx context.Context) {
	ev := NewOpticalAlarmEvaluator(OpticalAlarmEvaluatorOptions{
		Notify: sm.publishOpticalAlarm,
	})

	// Published BEFORE any device is enrolled, and unconditionally, matching
	// every other subsystem here.
	//
	// The first cut enrolled from a snapshot of devicesByIP and returned
	// without publishing when that was empty. At the point subsystems start,
	// it always is -- the auto-start batch is created afterwards, partly from
	// a background goroutine -- so the evaluator was never published, and
	// RegisterOpticalDevice then no-oped forever. An all-optical fleet raised
	// nothing at all.
	//
	// Stored under sm.mu because device-creation goroutines read it via
	// RegisterOpticalDevice.
	sm.mu.Lock()
	sm.opticalAlarms = ev
	sm.mu.Unlock()

	go ev.Run(ctx)
	log.Printf("Optical alarm subsystem: ready (SD at %.2f dB, SF at %.2f dB, hysteresis %.1f dB, "+
		"soak %s) — awaiting optical devices",
		opticalSDThresholdDB(), opticalSFThresholdDB(), opticalAlarmHysteresisDB, opticalAlarmSoak)

	// Enrol anything that already exists (a restart path, or a caller that
	// starts subsystems late). Normally a no-op.
	sm.mu.RLock()
	devs := make([]*DeviceSimulator, 0, len(sm.devicesByIP))
	for _, dev := range sm.devicesByIP {
		devs = append(devs, dev)
	}
	sm.mu.RUnlock()
	for _, dev := range devs {
		sm.RegisterOpticalDevice(dev)
	}
}

// publishOpticalAlarm is the evaluator's notify hook: one transition in, a
// trap and a syslog line out.
func (sm *SimulatorManager) publishOpticalAlarm(evt OpticalAlarmEvent) {
	role := opticalRoleFor(evt.Condition, evt.Raised)
	ip := evt.DeviceIP.String()

	sm.mu.RLock()
	dev := sm.devicesByIP[ip]
	sm.mu.RUnlock()
	if dev == nil {
		return
	}

	// Snapshot under the device lock, fire outside it. Same reasoning as
	// wireStateNotify: a UDP send must never hold a device lock, and a
	// concurrently-closing exporter's fire is a no-op via its closing guard.
	dev.mu.RLock()
	tx := dev.trapExporter
	sx := dev.syslogExporter
	dev.mu.RUnlock()

	// ifIndex -1 means "resolve from the exporter's own ifIndexFn". Optical
	// channels are keyed by component name, not ifIndex, so there is no
	// meaningful index to pin here; the component travels in the varbinds and
	// the message body instead.
	const noIfIndex = -1

	if tx != nil {
		if cat := sm.CatalogFor(ip); cat != nil {
			for _, entry := range cat.EntriesByRole(role) {
				// State-driven fires bypass the Poisson global cap on initial
				// transmit (task 6.8, existing Tier C convention): an alarm is
				// an event, not steady-state chatter, and dropping it to a
				// rate limiter would lose the very transition a collector is
				// waiting for.
				tx.fireWithSource(entry, opticalOverrides(evt), sourceStateDriven, noIfIndex)
			}
		}
	}
	if sx != nil {
		if cat := sm.SyslogCatalogFor(ip); cat != nil {
			for _, entry := range cat.EntriesByRole(role) {
				_ = sx.fireWithSource(entry, opticalOverrides(evt), sourceStateDriven, noIfIndex)
			}
		}
	}
}

// opticalOverrides supplies the per-fire template values an optical alarm
// carries. `IfName` is reused as the component slot because it is the
// vocabulary's existing "which port is this about" field, and a collector
// reading the Instance varbind wants the channel name there — inventing a
// tenth template field for the same idea would fragment the vocabulary.
func opticalOverrides(evt OpticalAlarmEvent) map[string]string {
	return map[string]string{
		"IfName": evt.Component,
		// There is no meaningful ifIndex for an OCH channel; without this
		// override the exporter's ifIndexFn picks a random interface, so any
		// future catalog entry using {{.IfIndex}} would emit a plausible but
		// wrong index instead of an obviously-absent 0.
		"IfIndex": "0",
		// The measurement that triggered the transition, for the Description
		// varbind / message body. Self-delimiting (leading " ("): {{.Detail}}
		// must render cleanly when an on-demand fire supplies no override.
		"Detail": fmt.Sprintf(" (OSNR %.2f dB)", evt.OSNRdB),
	}
}

// RegisterOpticalDevice enrolls a newly created device's channels, so a device
// created after startup still raises alarms. No-op when the subsystem is not
// running or the device has no optical engine.
func (sm *SimulatorManager) RegisterOpticalDevice(dev *DeviceSimulator) {
	if dev == nil || dev.metricsCycler == nil {
		return
	}
	sm.mu.RLock()
	ev := sm.opticalAlarms
	sm.mu.RUnlock()
	if ev == nil {
		return
	}
	if oc := dev.metricsCycler.OpticalCyclerOf(); oc != nil {
		ev.Register(dev.IP, oc)
	}
}

// DeregisterOpticalDevice drops a deleted device's channels from the evaluator.
func (sm *SimulatorManager) DeregisterOpticalDevice(ip net.IP) {
	sm.mu.RLock()
	ev := sm.opticalAlarms
	sm.mu.RUnlock()
	if ev == nil {
		return
	}
	ev.Deregister(ip)
}
