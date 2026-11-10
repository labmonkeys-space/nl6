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
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// yangpush_interop_test.go is the check with detection power for YANG-Push
// over UDP-notif. Every other yangpush test decodes nl6's bytes with nl6's own
// code. This one runs REAL huawei_ne8000 devices against a REAL NetCalyx
// v0.4.0 collector, started by `make test-interop-yangpush` (examples/
// netcalyx/compose.yml, host network, Kafka JSON output on Redpanda) and reads
// what NetCalyx's own log and Kafka output say it decoded.
//
// Gated on NL6_YANGPUSH_INTEROP=1 like the IPFIX gate: env unset skips, env set
// with the stack unreachable FAILS, because a silent skip asserts nothing.
// The target also needs a Linux host, because the devices need TUN and a
// network namespace. The test talks to a separately started nl6 over REST.
//
// Environment (the Makefile sets all of them):
//
//	NL6_YANGPUSH_API        nl6 REST base, for example http://127.0.0.1:8080
//	NL6_YANGPUSH_COLLECTOR  host:port the devices send to (10.254.0.1:10000)
//	NL6_YANGPUSH_WAIT       how long to let the subscriptions run (default 150s)
const (
	yangPushInteropEnvGate    = "NL6_YANGPUSH_INTEROP"
	yangPushInteropTopic      = "telemetry-message-json"
	yangPushInteropNetCalyx   = "nl6-yangpush-netcalyx"
	yangPushInteropRedpanda   = "nl6-yangpush-redpanda"
	yangPushInteropDeviceIP   = "10.42.0.1"
	yangPushInteropDeviceN    = 3
	yangPushInteropOnChangeID = 10
)

var yangPushInteropDevices = []string{"10.42.0.1", "10.42.0.2", "10.42.0.3"}

// yangPushInteropMsg is one Kafka record, decoded as far as the assertions go.
type yangPushInteropMsg struct {
	Message struct {
		Meta struct {
			Collected string `json:"collection-timestamp"`
			Export    string `json:"export-address"`
			Sub       struct {
				ID int `json:"id"`
			} `json:"ietf-yang-push-telemetry-message:yang-push-subscription"`
		} `json:"telemetry-message-metadata"`
		Payload json.RawMessage `json:"payload"`
	} `json:"ietf-telemetry-message:message"`
	raw string
}

func yangPushInteropRun(t *testing.T, name string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out.String())
	}
	return out.String()
}

func yangPushInteropMessages(t *testing.T) []yangPushInteropMsg {
	t.Helper()
	out := yangPushInteropRun(t, "docker", "exec", yangPushInteropRedpanda,
		"rpk", "topic", "consume", yangPushInteropTopic, "--offset", ":end", "--read-committed",
		"--format", "%v\\n")
	var msgs []yangPushInteropMsg
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var m yangPushInteropMsg
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			t.Fatalf("Kafka record is not JSON: %v\n%s", err, line)
		}
		// NetCalyx listens on [::], so an IPv4 device shows as ::ffff:a.b.c.d.
		m.Message.Meta.Export = strings.TrimPrefix(m.Message.Meta.Export, "::ffff:")
		m.raw = line
		msgs = append(msgs, m)
	}
	return msgs
}

// yangPushInteropMetrics reads the OpenTelemetry Collector's Prometheus text
// and sums each series by name, dropping labels and the _total suffix. A name
// is absent when NetCalyx has not exported it.
func yangPushInteropMetrics(t *testing.T) map[string]float64 {
	t.Helper()
	resp, err := http.Get("http://127.0.0.1:8889/metrics")
	if err != nil {
		t.Fatalf("GET OpenTelemetry Collector metrics: %v", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	// Label values can hold "}" (NetCalyx puts the subscription target in a
	// label), so take the name up to the first "{" or space and the value
	// after the last space. The exporter writes no timestamps.
	out := map[string]float64{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		end := strings.IndexAny(line, "{ ")
		sp := strings.LastIndex(line, " ")
		if end <= 0 || sp < end {
			continue
		}
		v, err := strconv.ParseFloat(line[sp+1:], 64)
		if err != nil {
			continue
		}
		out[strings.TrimSuffix(line[:end], "_total")] += v
	}
	return out
}

func yangPushInteropPost(t *testing.T, url, body string) string {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		t.Fatalf("POST %s: %s\n%s", url, resp.Status, b)
	}
	return string(b)
}

func TestYangPushInterop(t *testing.T) {
	if os.Getenv(yangPushInteropEnvGate) != "1" {
		t.Skipf("%s=1 not set (use `make test-interop-yangpush`, Linux and docker needed)", yangPushInteropEnvGate)
	}
	api := os.Getenv("NL6_YANGPUSH_API")
	collector := os.Getenv("NL6_YANGPUSH_COLLECTOR")
	if api == "" || collector == "" {
		t.Fatal("NL6_YANGPUSH_API and NL6_YANGPUSH_COLLECTOR must be set; run `make test-interop-yangpush`")
	}
	wait := 150 * time.Second
	if v := os.Getenv("NL6_YANGPUSH_WAIT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("NL6_YANGPUSH_WAIT: %v", err)
		}
		wait = d
	}

	yangPushInteropPost(t, api+"/api/v1/devices", fmt.Sprintf(
		`{"start_ip":%q,"device_count":%d,"resource_file":"huawei_ne8000.json","yang_push":{"collector":%q}}`,
		yangPushInteropDeviceIP, yangPushInteropDeviceN, collector))
	t.Logf("3 huawei_ne8000 devices created, letting the subscriptions run for %s", wait)
	time.Sleep(wait)

	// 1. NetCalyx fetched the YANG library from every device.
	logs := yangPushInteropRun(t, "docker", "logs", yangPushInteropNetCalyx)
	for _, ip := range yangPushInteropDevices {
		found := false
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "YANG Library fetched from device") && strings.Contains(line, ip) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NetCalyx never logged `YANG Library fetched from device` for %s", ip)
		}
	}

	// 1b. NetCalyx's own counters, read through the OpenTelemetry Collector's
	// Prometheus endpoint: no decode, validation or fetch failure, and some
	// decoded and validated messages. NetCalyx exports every 10 s, so the 150 s
	// run is long enough for the series to exist. Names are NetCalyx v0.4.0's
	// (crates/yang-push validation/stats.rs, crates/udp-notif-service actor.rs,
	// crates/collector yang_push caching) with dots and dashes mapped to
	// underscores by the Prometheus exporter. `validation.dropped` carries a
	// reason label (decode error, buffer full, validation failed, ...); the
	// sum over every reason must be 0.
	metrics := yangPushInteropMetrics(t)
	for _, name := range []string{
		"netcalyx_yang_push_validation_dropped",
		"netcalyx_yang_push_validation_yang_context_failed",
		"netcalyx_yang_push_validation_yang_context_empty",
		"netcalyx_collector_yang_push_caching_device_fetch_response_failed",
		"netcalyx_udp_notif_decoder_malformed",
		"netcalyx_udp_notif_reassembly_max_segments_exceeded",
	} {
		if v := metrics[name]; v != 0 {
			t.Errorf("NetCalyx counter %s = %v, want 0", name, v)
		}
	}
	// Proof of validation: the library was fetched from a device, a libyang
	// context was built from it, and messages passed schema validation.
	// NetCalyx counts `validation.validated` directly; `validation.skipped`
	// (forwarded without validation) is logged for the record.
	for _, name := range []string{
		"netcalyx_collector_yang_push_caching_device_fetch_response_succeeded",
		"netcalyx_yang_push_validation_yang_context_loaded",
		"netcalyx_yang_push_validation_validated",
	} {
		if v, ok := metrics[name]; !ok || v <= 0 {
			t.Errorf("NetCalyx counter %s = %v (present %v), want > 0", name, v, ok)
		}
	}
	t.Logf("NetCalyx validated %v messages (sent %v, skipped %v)",
		metrics["netcalyx_yang_push_validation_validated"],
		metrics["netcalyx_yang_push_validation_sent"], metrics["netcalyx_yang_push_validation_skipped"])

	// 2. Kafka holds messages for subscriptions 8, 9 and 10 from every device.
	msgs := yangPushInteropMessages(t)
	seen := map[string]bool{}
	for _, m := range msgs {
		seen[fmt.Sprintf("%s/%d", m.Message.Meta.Export, m.Message.Meta.Sub.ID)] = true
	}
	for _, ip := range yangPushInteropDevices {
		for _, id := range []int{8, 9, 10} {
			if !seen[fmt.Sprintf("%s/%d", ip, id)] {
				t.Errorf("no Kafka message for device %s subscription %d (%d messages total)", ip, id, len(msgs))
			}
		}
	}

	// 3. Segmentation reached NetCalyx intact. A subscription 8 payload larger
	// than one segment can only have arrived through reassembly. The payload
	// JSON is smaller than the wire message, so the size is a lower bound.
	big := 0
	for _, m := range msgs {
		if m.Message.Meta.Sub.ID == 8 && len(m.Message.Payload) > 1436 {
			big++
		}
	}
	if big == 0 {
		t.Errorf("no subscription 8 Kafka record has a payload above 1436 bytes, so no reassembled message was seen")
	}
	// Secondary check from nl6's side, summed over every collector row.
	resp, err := http.Get(api + "/api/v1/yangpush/status")
	if err != nil {
		t.Fatalf("GET yangpush/status: %v", err)
	}
	var st YangPushStatus
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err := json.Unmarshal(body, &st); err != nil || len(st.Collectors) == 0 {
		t.Fatalf("yangpush/status: %v\n%s", err, body)
	}
	var sent, segs, fails uint64
	for _, c := range st.Collectors {
		sent += c.MessagesSent
		segs += c.SegmentsSent
		fails += c.SendFailures
	}
	t.Logf("status: messages_sent=%d segments_sent=%d send_failures=%d, %d reassembled sub 8 records", sent, segs, fails, big)
	if segs <= sent {
		t.Errorf("segments_sent=%d is not above messages_sent=%d", segs, sent)
	}
	if fails != 0 {
		t.Errorf("send_failures=%d", fails)
	}

	// 4. An interface going down arrives on subscription 10 within 5 s.
	// Bring ifIndex 3 up first so the DOWN is a real transition.
	oper := api + "/api/v1/devices/" + yangPushInteropDevices[0] + "/interfaces/3/oper-status"
	yangPushInteropPost(t, oper, `{"status":"UP"}`)
	time.Sleep(2 * time.Second)
	t0 := time.Now().UTC().Add(-time.Second)
	yangPushInteropPost(t, oper, `{"status":"DOWN"}`)
	time.Sleep(5 * time.Second)
	hit := false
	for _, m := range yangPushInteropMessages(t) {
		if m.Message.Meta.Sub.ID != yangPushInteropOnChangeID || m.Message.Meta.Export != yangPushInteropDevices[0] {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, m.Message.Meta.Collected)
		if err != nil || ts.Before(t0) {
			continue
		}
		if strings.Contains(string(m.Message.Payload), `"oper-status":"down"`) {
			hit = true
			break
		}
	}
	if !hit {
		t.Errorf("no subscription 10 message with oper-status down within 5 s of the POST for %s ifIndex 3", yangPushInteropDevices[0])
	}
}
