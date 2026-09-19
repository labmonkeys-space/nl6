/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestNbar2CapabilityCompleteness is the NBAR2 twin of
// TestFlowCapabilityCompleteness: every shipped type is in exactly one of
// nbar2CapableTypes and nbar2IncapableTypes, each row with a reason, and a
// type in neither or both fails BY NAME. Lives in CI rather than at load for
// the reason the flow test states: the maps are compiled in and unreachable
// to an operator's custom type.
func TestNbar2CapabilityCompleteness(t *testing.T) {
	entries, err := os.ReadDir("resources")
	if err != nil {
		t.Fatalf("read resources dir: %v", err)
	}
	types := 0
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), "_") {
			continue
		}
		types++
		rf := e.Name() + ".json"
		capReason, capable := nbar2CapableTypes[rf]
		incReason, incapable := nbar2IncapableTypes[rf]
		switch {
		case capable && incapable:
			t.Errorf("%s is in BOTH nbar2CapableTypes and nbar2IncapableTypes; pick one", rf)
		case !capable && !incapable:
			t.Errorf("%s is in NEITHER nbar2CapableTypes nor nbar2IncapableTypes. Decide its NBAR2 story "+
				"with a written reason: only IOS/IOS-XE platforms have NBAR2, and a prefix test on the slug "+
				"is not a decision (cisco_nexus_9500 runs NX-OS)", rf)
		case capable && capReason == "":
			t.Errorf("%s: nbar2CapableTypes row has no reason", rf)
		case incapable && incReason == "":
			t.Errorf("%s: nbar2IncapableTypes row has no reason", rf)
		}
	}
	if types == 0 {
		t.Fatal("enumerated zero device types; the resources layout changed and this test is checking nothing")
	}
	for rf := range nbar2CapableTypes {
		if _, err := os.Stat("resources/" + strings.TrimSuffix(rf, ".json")); err != nil {
			t.Errorf("nbar2CapableTypes names %s, which is not a shipped type", rf)
		}
	}
	for rf := range nbar2IncapableTypes {
		if _, err := os.Stat("resources/" + strings.TrimSuffix(rf, ".json")); err != nil {
			t.Errorf("nbar2IncapableTypes names %s, which is not a shipped type", rf)
		}
	}
}

// The prefix trap: three cisco_* types must NOT be capable, and the two that
// are must be exactly the curated pair. Replacing the map lookup with a
// strings.HasPrefix shortcut fails here by name.
func TestNbar2CapabilityIsNotAPrefixTest(t *testing.T) {
	for _, rf := range []string{"cisco_nexus_9500.json", "cisco_crs_x.json", "asr9k.json"} {
		if SupportsNbar2(rf) {
			t.Errorf("%s reports NBAR2 capable; it runs %s", rf, nbar2IncapableTypes[rf])
		}
	}
	for _, rf := range []string{"cisco_ios.json", "cisco_catalyst_9500.json"} {
		if !SupportsNbar2(rf) {
			t.Errorf("%s must be NBAR2 capable", rf)
		}
	}
	if SupportsNbar2("cisco_custom_operator_type.json") {
		t.Error("an unlisted type must be incapable, not admitted by its prefix")
	}
	if !nbar2FieldFor("cisco_ios.json", true) || nbar2FieldFor("juniper_mx240.json", true) || nbar2FieldFor("cisco_ios.json", false) {
		t.Error("nbar2FieldFor must be the requested value on a capable type and false everywhere else")
	}
}

func nbar2Req(rf string, rr bool, category string) CreateDevicesRequest {
	return CreateDevicesRequest{ResourceFile: rf, RoundRobin: rr, Category: category,
		Flow: &DeviceFlowConfig{Collector: "127.0.0.1:4739", Protocol: "ipfix", Nbar2: true}}
}

// TestNbar2IncapableRequest mirrors TestFlowIncapableRequest and
// TestOpticalIncapableRequest, with the two NBAR2-specific arms: a request
// without nbar2 is never refused here, and a mixed round-robin batch is
// accepted because its capable devices emit AVC.
func TestNbar2IncapableRequest(t *testing.T) {
	tests := []struct {
		name   string
		req    CreateDevicesRequest
		reject bool
	}{
		{"explicit incapable type", nbar2Req("juniper_mx240.json", false, ""), true},
		{"explicit capable type", nbar2Req("cisco_ios.json", false, ""), false},
		{"explicit NX-OS type", nbar2Req("cisco_nexus_9500.json", false, ""), true},
		{"category round robin with no capable type", nbar2Req("", true, "GPU Servers"), true},
		{"category round robin with a capable type", nbar2Req("", true, "Network Devices"), false},
		{"mixed round robin is allowed", nbar2Req("", true, ""), false},
		{"no flow block", CreateDevicesRequest{ResourceFile: "juniper_mx240.json"}, false},
		{"flow block without nbar2", CreateDevicesRequest{ResourceFile: "juniper_mx240.json", Flow: &DeviceFlowConfig{Collector: "x:1", Protocol: "ipfix"}}, false},
		// No resource file and no round robin creates the DEFAULT type,
		// asr9k (IOS-XR), which has no NBAR2: refused, naming it, rather than
		// a 201 whose every device silently degraded.
		{"neither round robin nor a resource file resolves to the incapable default", CreateDevicesRequest{Flow: &DeviceFlowConfig{Nbar2: true}}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rf, got := nbar2IncapableRequest(tc.req)
			if got != tc.reject {
				t.Fatalf("nbar2IncapableRequest = %v (%q), want %v", got, rf, tc.reject)
			}
			if got && rf == "" {
				t.Error("rejection must name the offending resource file")
			}
		})
	}
}

// Handler level: an entirely incapable request is a 400 naming the type and
// the OS reason, evaluated after the flow gate so a flow-incapable type stays
// a flow rejection that never mentions NBAR2. Neither path touches the
// manager (the web_create_devices_scenario_test.go convention).
func TestCreateDevicesHandler_Nbar2Rejections(t *testing.T) {
	post := func(req CreateDevicesRequest) (int, string) {
		body, _ := json.Marshal(req)
		r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		w := httptest.NewRecorder()
		createDevicesHandler(w, r)
		var resp APIResponse
		_ = json.Unmarshal(w.Body.Bytes(), &resp)
		return w.Code, resp.Message
	}
	req := nbar2Req("juniper_mx240.json", false, "")
	req.StartIP, req.DeviceCount, req.Netmask = "10.0.0.1", 1, "24"
	if code, msg := post(req); code != http.StatusBadRequest || !strings.Contains(msg, `"juniper_mx240.json" has no NBAR2 (Junos`) {
		t.Fatalf("incapable type: %d %q", code, msg)
	}
	req.ResourceFile = ""
	if code, msg := post(req); code != http.StatusBadRequest || !strings.Contains(msg, `"asr9k.json" has no NBAR2 (IOS-XR`) {
		t.Fatalf("default type: %d %q", code, msg)
	}
	req.Flow.Protocol = "netflow9"
	req.ResourceFile = "cisco_ios.json"
	if code, msg := post(req); code != http.StatusBadRequest || !strings.Contains(msg, "nbar2 requires protocol ipfix") {
		t.Fatalf("wrong protocol: %d %q", code, msg)
	}
	req.Flow.Protocol = "ipfix"
	req.ResourceFile = "ciena_waveserver5.json"
	if code, msg := post(req); code != http.StatusBadRequest || !strings.Contains(msg, "does not support flow export") || strings.Contains(msg, "NBAR2") {
		t.Fatalf("flow-incapable type must stay a flow rejection: %d %q", code, msg)
	}
}

func TestDeviceFlowConfigValidateNbar2(t *testing.T) {
	for _, proto := range []string{"netflow9", "netflow5", "sflow", ""} {
		c := DeviceFlowConfig{Collector: "127.0.0.1:2055", Protocol: proto, Nbar2: true}
		c.ApplyDefaults()
		if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "nbar2 requires protocol ipfix") {
			t.Errorf("protocol %q with nbar2: err = %v, want the ipfix rule naming ipfix", proto, err)
		}
	}
	c := DeviceFlowConfig{Collector: "127.0.0.1:4739", Protocol: "IPFIX", Nbar2: true, OptionsInterfaceTable: "if-scoped"}
	c.ApplyDefaults()
	if err := c.Validate(); err != nil || c.Protocol != "ipfix" {
		t.Fatalf("ipfix with nbar2 and an option table must validate: %v (%q)", err, c.Protocol)
	}
	var echoed map[string]any
	b, _ := json.Marshal(DeviceFlowConfig{Collector: "127.0.0.1:4739", Protocol: "ipfix"})
	_ = json.Unmarshal(b, &echoed)
	if _, present := echoed["nbar2"]; present {
		t.Fatal("nbar2:false must be omitted from the JSON echo")
	}
}

// The seed flag fails the same way the REST field does, plus the
// no-collector arm. Fatal at startup is log.Fatalf on this error.
func TestValidateNbar2Seed(t *testing.T) {
	if err := validateNbar2Seed(false, "", "netflow9"); err != nil {
		t.Fatalf("flag off must never fail: %v", err)
	}
	if err := validateNbar2Seed(true, "", "ipfix"); err == nil || !strings.Contains(err.Error(), "requires -flow-collector") {
		t.Fatalf("no collector: %v", err)
	}
	if err := validateNbar2Seed(true, "127.0.0.1:2055", "netflow9"); err == nil || !strings.Contains(err.Error(), "nbar2 requires protocol ipfix") {
		t.Fatalf("default protocol: %v", err)
	}
	if err := validateNbar2Seed(true, "127.0.0.1:4739", "ipfix"); err != nil {
		t.Fatalf("ipfix: %v", err)
	}
}

// degradeNbar2IfIncapable: an incapable type keeps its flow block with
// nbar2 cleared, logs once per type, and a capable type is untouched. Both
// device-creation paths call it before attach; TestNbar2BothCreationPathsDegrade
// pins the wiring.
func TestDegradeNbar2IfIncapable(t *testing.T) {
	var sink bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&sink)
	t.Cleanup(func() { log.SetOutput(prev) })
	nbar2DegradeLogged.Delete("juniper_mx240.json")

	mk := func() *DeviceSimulator {
		return &DeviceSimulator{flowConfig: &DeviceFlowConfig{Collector: "x:4739", Protocol: "ipfix", Nbar2: true}}
	}
	d1, d2, d3, d4 := mk(), mk(), mk(), mk()
	nbar2DegradeLogged.Delete(defaultResourceFile)
	degradeNbar2IfIncapable(d4, "") // the default type, named in the log
	if d4.flowConfig.Nbar2 || !strings.Contains(sink.String(), "device type asr9k.json has no NBAR2 (IOS-XR") {
		t.Fatalf("empty resource file must degrade as the default type and name it:\n%s", sink.String())
	}
	degradeNbar2IfIncapable(d1, "juniper_mx240.json")
	degradeNbar2IfIncapable(d2, "juniper_mx240.json")
	degradeNbar2IfIncapable(d3, "cisco_ios.json")
	if d1.flowConfig == nil || d1.flowConfig.Nbar2 || d2.flowConfig.Nbar2 {
		t.Fatal("incapable devices must keep the flow block with nbar2 cleared")
	}
	if !d3.flowConfig.Nbar2 {
		t.Fatal("a capable device must keep nbar2")
	}
	if n := strings.Count(sink.String(), "juniper_mx240.json has no NBAR2 (Junos"); n != 1 {
		t.Fatalf("degradation logged %d times for one type, want 1:\n%s", n, sink.String())
	}
	if !strings.Contains(sink.String(), "emit plain IPFIX (template 256)") {
		t.Fatal("the log must say the device emits plain IPFIX, which is not flow's skip")
	}
}

// Both creation paths in device.go must degrade before they attach. A batch
// driven to completion needs root and a TUN device, so the wiring is pinned
// at the source: each attachFlowExporter call site in device.go is preceded
// by a degradeNbar2IfIncapable call in the same block.
func TestNbar2BothCreationPathsDegrade(t *testing.T) {
	src, err := os.ReadFile("device.go")
	if err != nil {
		t.Fatal(err)
	}
	attach := strings.Count(string(src), "sm.attachFlowExporter(device, flowProfile)")
	degrade := strings.Count(string(src), "degradeNbar2IfIncapable(device, ")
	if attach != 2 || degrade != 2 {
		t.Fatalf("device.go has %d attachFlowExporter call sites and %d degradeNbar2IfIncapable calls; both paths need both (they have diverged before)", attach, degrade)
	}
	for _, block := range strings.SplitAfter(string(src), "sm.attachFlowExporter(device, flowProfile)")[:2] {
		tail := block[max(0, len(block)-600):]
		if !strings.Contains(tail, "degradeNbar2IfIncapable(device, ") {
			t.Error("an attachFlowExporter call site is not preceded by degradeNbar2IfIncapable within the same block")
		}
	}
}

// attachNbar2Device builds a manager with the shipped catalogs and attaches
// a flow exporter to a device of resourceFile with nbar2 set.
func attachNbar2Device(t *testing.T, sm *SimulatorManager, ip, resourceFile string, nbar2 bool) *DeviceSimulator {
	t.Helper()
	d := &DeviceSimulator{IP: net.ParseIP(ip).To4(), resourceFile: resourceFile,
		flowConfig: &DeviceFlowConfig{Collector: "127.0.0.1:4739", Protocol: "ipfix", Nbar2: nbar2}}
	d.flowConfig.ApplyDefaults()
	if err := sm.attachFlowExporter(d, GetFlowProfile(resourceFile)); err != nil {
		t.Fatalf("attach %s: %v", ip, err)
	}
	return d
}

func nbar2TestManager(t *testing.T) *SimulatorManager {
	t.Helper()
	sm := newTestSimulatorManager()
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{PayloadBudget: maxFlowPayloadIPv4}); err != nil {
		t.Fatal(err)
	}
	return sm
}

// Two devices of one type share ONE encoder pointer, built at catalog load;
// the exporter carries the catalog; the protocol string and the pool key
// stay "ipfix"; a plain IPFIX device of the same type takes the plain
// encoder and no catalog.
func TestNbar2AttachSharesEncoderPerType(t *testing.T) {
	sm := nbar2TestManager(t)
	a := attachNbar2Device(t, sm, "10.9.0.1", "cisco_ios.json", true)
	b := attachNbar2Device(t, sm, "10.9.0.2", "cisco_ios.json", true)
	c := attachNbar2Device(t, sm, "10.9.0.3", "cisco_catalyst_9500.json", true)
	p := attachNbar2Device(t, sm, "10.9.0.4", "cisco_ios.json", false)
	defer func() {
		for _, d := range []*DeviceSimulator{a, b, c, p} {
			d.flowExporter.Close()
		}
	}()
	want := sm.Nbar2CatalogFor("cisco_ios.json").Encoder()
	if a.flowExporter.encoder != want || b.flowExporter.encoder != want {
		t.Fatal("two cisco_ios devices must share the catalog's one encoder")
	}
	if c.flowExporter.encoder == want || c.flowExporter.encoder != sm.Nbar2CatalogFor("cisco_catalyst_9500.json").Encoder() {
		t.Fatal("cisco_catalyst_9500 has its own overlay and therefore its own encoder")
	}
	if a.flowExporter.nbar2 == nil || a.flowExporter.nbar2 != b.flowExporter.nbar2 {
		t.Fatal("the exporter must carry the shared catalog")
	}
	if _, plain := p.flowExporter.encoder.(IPFIXEncoder); !plain || p.flowExporter.nbar2 != nil {
		t.Fatalf("a plain ipfix device took %T with catalog %v", p.flowExporter.encoder, p.flowExporter.nbar2)
	}
	if a.flowExporter.protocol != "ipfix" || p.flowExporter.protocol != "ipfix" {
		t.Fatalf("protocol strings %q / %q, want ipfix for both (the collector tells them apart by template id)", a.flowExporter.protocol, p.flowExporter.protocol)
	}
}

// An NBAR2 device emits AVC records on template 258 whose applicationId,
// protocol and port come from the catalog, plus the application table on
// 259; the status endpoint shows one ipfix row for AVC and plain devices
// together and reports the resolved catalogs.
func TestNbar2DeviceEmitsCatalogDrivenAVC(t *testing.T) {
	sm := nbar2TestManager(t)
	d := attachNbar2Device(t, sm, "10.9.1.1", "cisco_ios.json", true)
	p := attachNbar2Device(t, sm, "10.9.1.2", "cisco_ios.json", false)
	defer d.flowExporter.Close()
	defer p.flowExporter.Close()
	sm.devices[d.IP.String()] = d
	sm.devices[p.IP.String()] = p

	var datagrams [][]byte
	d.flowExporter.writeOverride = func(pdu []byte) error {
		datagrams = append(datagrams, append([]byte(nil), pdu...))
		return nil
	}
	conn := testSender(t)
	defer conn.Close()
	start := time.Now().Add(-2 * time.Minute)
	d.flowExporter.startTime = start
	d.flowExporter.cache = NewFlowCache(time.Millisecond, time.Millisecond, 512)
	for i := 0; i < 3; i++ {
		d.flowExporter.Tick(start.Add(time.Duration(i+1)*10*time.Second), conn, testPool())
	}
	cat := sm.Nbar2CatalogFor("cisco_ios.json")
	byID := map[uint32]*nbar2Entry{}
	for _, e := range cat.Entries {
		byID[e.ID] = e
	}
	records, tables := 0, 0
	for _, pdu := range datagrams {
		pkt := decodeIPFIXPacket(t, pdu)
		if _, ok := pkt.RawSets[ipfixAppTableTemplateID]; ok {
			tables++
		}
		for _, r := range decodeIPFIXAVCRecords(t, pkt.RawSets[ipfixAVCTemplateID]) {
			records++
			e := byID[r.AppID]
			if e == nil {
				t.Fatalf("record carries applicationId %#x, not in the cisco_ios catalog", r.AppID)
			}
			if r.Base.Protocol != e.Proto || r.Base.DstPort != e.DstPort {
				t.Fatalf("record %s: proto %d port %d, catalog says %d/%d", e.Name, r.Base.Protocol, r.Base.DstPort, e.Proto, e.DstPort)
			}
		}
	}
	if records == 0 || tables == 0 {
		t.Fatalf("emitted %d AVC records and %d application tables over three ticks, want both > 0", records, tables)
	}

	st := sm.GetFlowStatus()
	if len(st.Collectors) != 1 || st.Collectors[0].Protocol != "ipfix" || st.Collectors[0].Devices != 2 {
		t.Fatalf("status collectors = %+v, want one ipfix row with 2 devices", st.Collectors)
	}
	if st.Nbar2CatalogsByType[universalCatalogKey].Source != "embedded" ||
		st.Nbar2CatalogsByType["cisco_ios"].Source != "file:resources/cisco_ios/nbar2.json" ||
		st.Nbar2CatalogsByType["cisco_ios"].Entries != len(cat.Entries) {
		t.Fatalf("nbar2_catalogs_by_type = %+v", st.Nbar2CatalogsByType)
	}
	if st := (&SimulatorManager{}).GetFlowStatus(); st.Nbar2CatalogsByType != nil {
		t.Fatal("no catalog loaded must report no key")
	}
}

// Attach refuses an NBAR2 device whose resolved catalog has no usable entry,
// and a manager whose loader never ran.
func TestNbar2AttachRefusesUnusableCatalog(t *testing.T) {
	sm := newTestSimulatorManager()
	d := &DeviceSimulator{IP: net.ParseIP("10.9.2.1").To4(), resourceFile: "cisco_ios.json",
		flowConfig: &DeviceFlowConfig{Collector: "127.0.0.1:4739", Protocol: "ipfix", Nbar2: true}}
	if err := sm.attachFlowExporter(d, GetFlowProfile("cisco_ios.json")); err == nil || !strings.Contains(err.Error(), "no NBAR2 catalog is loaded") {
		t.Fatalf("no catalog: %v", err)
	}
	path := t.TempDir() + "/big.json"
	if err := os.WriteFile(path, nbar2JSON("", `{"name":"big","engine":6,"selector":1,"proto":"tcp","dst_port":80,"hosts":[{"value":"`+strings.Repeat("h", 600)+`"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := sm.StartNbar2Catalogs(Nbar2CatalogConfig{CatalogPath: path, PayloadBudget: 548}); err != nil {
		t.Fatal(err)
	}
	err := sm.attachFlowExporter(d, GetFlowProfile("cisco_ios.json"))
	if err == nil || !strings.Contains(err.Error(), "every entry of the catalog for cisco_ios is oversized") {
		t.Fatalf("all oversized: %v", err)
	}
	if d.flowExporter != nil {
		t.Fatal("a refused attach must leave no exporter")
	}
}

// Two exporters ticking concurrently on one shared encoder: run under
// -race (make test-race) this reports any shared mutable state in the
// encoder; without -race it is a smoke test.
func TestNbar2SharedEncoderIsRaceFree(t *testing.T) {
	sm := nbar2TestManager(t)
	a := attachNbar2Device(t, sm, "10.9.3.1", "cisco_ios.json", true)
	b := attachNbar2Device(t, sm, "10.9.3.2", "cisco_ios.json", true)
	defer a.flowExporter.Close()
	defer b.flowExporter.Close()
	for _, d := range []*DeviceSimulator{a, b} {
		d.flowExporter.writeOverride = func([]byte) error { return nil }
		d.flowExporter.cache = NewFlowCache(time.Millisecond, time.Millisecond, 512)
	}
	conn := testSender(t)
	defer conn.Close()
	var wg sync.WaitGroup
	for _, d := range []*DeviceSimulator{a, b} {
		wg.Add(1)
		go func(fe *FlowExporter) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				fe.Tick(time.Now().Add(time.Duration(i)*time.Second), conn, testPool())
			}
		}(d.flowExporter)
	}
	wg.Wait()
}
