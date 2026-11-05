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
	"strings"
	"testing"
	"time"
)

// yangpush_interop_test.go is the check with detection power for YANG-Push
// over UDP-notif. Every other yangpush test decodes nl6's bytes with nl6's own
// code. This one runs REAL huawei_ne8000 devices against a REAL NetGauze
// v0.13.0 collector, started by `make test-interop-yangpush` (examples/
// netgauze/compose.yml, host network, Kafka JSON output on Redpanda) and reads
// what NetGauze's own log and Kafka output say it decoded.
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
	yangPushInteropNetGauze   = "nl6-yangpush-netgauze"
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
		"rpk", "topic", "consume", yangPushInteropTopic, "--offset", "start", "--read-committed",
		"--format", "%v\\n", "--num", "100000", "--timeout", "10s")
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
		m.raw = line
		msgs = append(msgs, m)
	}
	return msgs
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

	// 1. NetGauze fetched the YANG library from every device and logged no
	// warning or error. Validation failures surface as WARN or ERROR lines.
	logs := yangPushInteropRun(t, "docker", "logs", yangPushInteropNetGauze)
	for _, ip := range yangPushInteropDevices {
		found := false
		for _, line := range strings.Split(logs, "\n") {
			if strings.Contains(line, "YANG Library fetched from device") && strings.Contains(line, ip) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("NetGauze never logged `YANG Library fetched from device` for %s", ip)
		}
	}
	for _, line := range strings.Split(logs, "\n") {
		// The OTLP exporter has no endpoint in this stack and complains about it.
		if (strings.Contains(line, " WARN ") || strings.Contains(line, " ERROR ")) &&
			!strings.Contains(line, "opentelemetry") && !strings.Contains(line, "OpenTelemetry") {
			t.Errorf("NetGauze logged a problem: %s", line)
		}
	}

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

	// 3. Segmentation reached NetGauze intact. nl6 counts more segments than
	// messages, and the reassembled messages decoded above.
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
	c := st.Collectors[0]
	t.Logf("status: messages_sent=%d segments_sent=%d send_failures=%d", c.MessagesSent, c.SegmentsSent, c.SendFailures)
	if c.SegmentsSent <= c.MessagesSent {
		t.Errorf("segments_sent=%d is not above messages_sent=%d: nothing was segmented", c.SegmentsSent, c.MessagesSent)
	}
	if c.SendFailures != 0 {
		t.Errorf("send_failures=%d", c.SendFailures)
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
