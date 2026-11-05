/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// yangPushAggregate holds a collector's counters from deleted devices, so the
// status totals stay monotonic across device churn.
type yangPushAggregate struct {
	messagesSent       atomic.Uint64
	segmentsSent       atomic.Uint64
	sendFailures       atomic.Uint64
	stateEventsDropped atomic.Uint64
	fidelitySuppressed atomic.Uint64
}

// YangPushStatus is the JSON body of GET /api/v1/yangpush/status.
type YangPushStatus struct {
	SubsystemActive  bool                      `json:"subsystem_active"`
	DevicesExporting int                       `json:"devices_exporting"`
	Collectors       []YangPushCollectorStatus `json:"collectors"`
}

// YangPushCollectorStatus is one collector row.
type YangPushCollectorStatus struct {
	Collector          string `json:"collector"`
	Devices            int    `json:"devices"`
	MessagesSent       uint64 `json:"messages_sent"`
	SegmentsSent       uint64 `json:"segments_sent"`
	SendFailures       uint64 `json:"send_failures"`
	StateEventsDropped uint64 `json:"state_events_dropped"`
	FidelitySuppressed uint64 `json:"fidelity_suppressed"`
}

// StartYangPushSubsystem marks YANG-Push active so per-device exporters may
// attach. Always on, like gNMI dial-out.
func (sm *SimulatorManager) StartYangPushSubsystem() error {
	if sm.yangPushSubsystemActive.Load() {
		return fmt.Errorf("yang_push: subsystem already started")
	}
	sm.yangPushSubsystemActive.Store(true)
	log.Printf("YANG-Push subsystem enabled (per-device opt-in, huawei_ne8000)")
	return nil
}

// StopYangPush closes every device's exporter. Shutdown only, like
// StopGnmiDialout.
func (sm *SimulatorManager) StopYangPush() {
	if !sm.yangPushSubsystemActive.Load() {
		return
	}
	sm.mu.RLock()
	devices := make([]*DeviceSimulator, 0, len(sm.devices))
	for _, d := range sm.devices {
		devices = append(devices, d)
	}
	sm.mu.RUnlock()
	for _, d := range devices {
		d.mu.Lock()
		if d.yangPushExporter != nil {
			_ = d.yangPushExporter.Close()
			sm.persistYangPushCounters(d.yangPushExporter)
			d.yangPushExporter = nil
		}
		d.mu.Unlock()
	}
	sm.yangPushSubsystemActive.Store(false)
}

// startDeviceYangPushExporter opens and starts the exporter for a device with
// yangPushConfig set. On error the caller nils the config, as for dial-out.
func (sm *SimulatorManager) startDeviceYangPushExporter(d *DeviceSimulator) error {
	if d == nil || d.yangPushConfig == nil {
		return nil
	}
	if !sm.yangPushSubsystemActive.Load() {
		return fmt.Errorf("yang_push: subsystem not started; call StartYangPushSubsystem first")
	}
	e, err := NewYangPushExporter(d, d.yangPushConfig, time.Now)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.yangPushExporter = e
	d.mu.Unlock()
	e.Start()
	return nil
}

// persistYangPushCounters folds a closed exporter's counters into its
// collector's aggregate. Call it after Close so no in-flight send is lost.
// Single-shot per exporter.
func (sm *SimulatorManager) persistYangPushCounters(e *YangPushExporter) {
	if e == nil || e.collector == "" {
		return
	}
	e.countersPersisted.Do(func() {
		v, _ := sm.yangPushAggregates.LoadOrStore(e.collector, &yangPushAggregate{})
		agg := v.(*yangPushAggregate)
		agg.messagesSent.Add(e.messagesSent.Load())
		agg.segmentsSent.Add(e.segmentsSent.Load())
		agg.sendFailures.Add(e.sendFailures.Load())
		agg.stateEventsDropped.Add(e.stateEventsDropped.Load())
		agg.fidelitySuppressed.Add(e.fidelitySuppressed.Load())
	})
}

// GetYangPushStatus sums live exporters per collector and folds in the
// aggregates of deleted devices.
func (sm *SimulatorManager) GetYangPushStatus() YangPushStatus {
	rows := map[string]*YangPushCollectorStatus{}
	row := func(c string) *YangPushCollectorStatus {
		r, ok := rows[c]
		if !ok {
			r = &YangPushCollectorStatus{Collector: c}
			rows[c] = r
		}
		return r
	}
	sm.mu.RLock()
	for _, d := range sm.devices {
		d.mu.RLock()
		e := d.yangPushExporter
		d.mu.RUnlock()
		if e == nil {
			continue
		}
		r := row(e.collector)
		r.Devices++
		r.MessagesSent += e.messagesSent.Load()
		r.SegmentsSent += e.segmentsSent.Load()
		r.SendFailures += e.sendFailures.Load()
		r.StateEventsDropped += e.stateEventsDropped.Load()
		r.FidelitySuppressed += e.fidelitySuppressed.Load()
	}
	sm.mu.RUnlock()
	sm.yangPushAggregates.Range(func(k, v any) bool {
		agg := v.(*yangPushAggregate)
		r := row(k.(string))
		r.MessagesSent += agg.messagesSent.Load()
		r.SegmentsSent += agg.segmentsSent.Load()
		r.SendFailures += agg.sendFailures.Load()
		r.StateEventsDropped += agg.stateEventsDropped.Load()
		r.FidelitySuppressed += agg.fidelitySuppressed.Load()
		return true
	})
	st := YangPushStatus{SubsystemActive: sm.yangPushSubsystemActive.Load(), Collectors: make([]YangPushCollectorStatus, 0, len(rows))}
	for _, r := range rows {
		st.Collectors = append(st.Collectors, *r)
		st.DevicesExporting += r.Devices
	}
	slices.SortFunc(st.Collectors, func(a, b YangPushCollectorStatus) int { return strings.Compare(a.Collector, b.Collector) })
	return st
}

// yangPushStatusHandler serves GET /api/v1/yangpush/status.
func yangPushStatusHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(manager.GetYangPushStatus())
}
