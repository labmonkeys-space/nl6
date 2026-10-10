/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type shapeFixture struct {
	Subtree   string   `json:"subtree"`
	Prefixes  []string `json:"prefixes"`
	Extension string   `json:"extension"`
	Leaves    []struct {
		Path string `json:"path"`
		Kind string `json:"kind"`
	} `json:"leaves"`
}

// fixtureSubscriptions maps fixture file stems to the path gnmic
// subscribed to when the capture was taken.
var fixtureSubscriptions = map[string]string{
	"if-counters":         "/interfaces/interface/state/counters",
	"if-state":            "/interfaces/interface/state",
	"subif":               "/interfaces/interface/subinterfaces/subinterface/state",
	"components":          "/components/component/state",
	"component-temp":      "/components/component/state/temperature",
	"component-props":     "/components/component/properties/property/state",
	"cpu":                 "/components/component/cpu/utilization/state",
	"sys-cpu":             "/system/cpus/cpu/state",
	"sys-mem":             "/system/memory/state",
	"system":              "/system/state",
	"native-packet-usage": "juniper:/junos/system/linecard/packet/usage/",
}

// fixtureAliasRendered maps fixtures captured through a native sensor
// alias to the path Junos rendered them under. Those fixtures are also
// subscribed with an empty origin, as collectors often do.
var fixtureAliasRendered = map[string]string{
	"native-packet-usage": "/components/component/properties/property/state/value",
}

var keyValueRe = regexp.MustCompile(`\[([a-z-]+)=[^\]]*\]`)

func wildcardKeys(p string) string { return keyValueRe.ReplaceAllString(p, "[$1=*]") }

func stripKeys(p string) string { return keyValueRe.ReplaceAllString(p, "") }

// Junos property keys are identity, not instance: keep them.
func wildcardKeysKeepProperty(p string) string {
	parts := strings.Split(p, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, "property[") {
			parts[i] = wildcardKeys(part)
		}
	}
	return strings.Join(parts, "/")
}

// underPath reports whether leaf (keys stripped) lies at or below sub.
func underPath(leaf, sub string) bool {
	l, s := stripKeys(leaf), strings.TrimSuffix(stripKeys(sub), "/")
	return l == s || strings.HasPrefix(l, s+"/")
}

// fixtureOrigin is the origin of a fixture's prefixes ("openconfig" or
// "juniper"); every fixture uses a single origin.
func fixtureOrigin(fx shapeFixture) string {
	if len(fx.Prefixes) == 0 {
		return ""
	}
	o, _, _ := strings.Cut(fx.Prefixes[0], ":")
	return o
}

func readShapeFixtures(t *testing.T) map[string]shapeFixture {
	t.Helper()
	files, _ := filepath.Glob("testdata/gnmi/juniper_mx10004/*.json")
	if len(files) == 0 {
		t.Fatal("no fixtures")
	}
	out := map[string]shapeFixture{}
	for _, f := range files {
		var fx shapeFixture
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &fx); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out[strings.TrimSuffix(filepath.Base(f), ".json")] = fx
	}
	return out
}

// mx10004TestSysName is the sysName startMX10004Server gives the device.
const mx10004TestSysName = "mx10004-test"

func startMX10004Server(t *testing.T) (addr string, cleanup func()) {
	t.Helper()
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["juniper_mx10004"]
	if cat == nil {
		t.Fatal("embedded juniper_mx10004 catalogue missing")
	}
	var dev *DeviceSimulator
	_, dev, addr, cleanup = startTestGnmiServerWithCatalog(t, cat)
	dev.cachedSysName.Store(mx10004TestSysName)
	return addr, cleanup
}

// TestMX10004ShapeMatchesCapture compares what nl6 serves per captured
// subscription with the vJunos capture. Junos picks different leaf
// subsets of one subtree per subscription, while nl6 serves the whole
// catalogue subtree, so the expected set is the union of every
// fixture's leaves (same origin) under the subscription path.
func TestMX10004ShapeMatchesCapture(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	fixtures := readShapeFixtures(t)
	unionLeaves := map[string]map[string]bool{} // origin -> leaf path
	unionPrefixes := map[string]bool{}
	for _, fx := range fixtures {
		o := fixtureOrigin(fx)
		if unionLeaves[o] == nil {
			unionLeaves[o] = map[string]bool{}
		}
		for _, l := range fx.Leaves {
			unionLeaves[o][l.Path] = true
		}
		for _, p := range fx.Prefixes {
			unionPrefixes[p] = true
		}
	}
	stems := make([]string, 0, len(fixtures))
	for stem := range fixtures {
		stems = append(stems, stem)
	}
	sort.Strings(stems)
	for _, stem := range stems {
		fx := fixtures[stem]
		sub, ok := fixtureSubscriptions[stem]
		if !ok {
			t.Fatalf("no subscription mapping for fixture %s", stem)
		}
		t.Run(stem, func(t *testing.T) {
			origin, p := "", sub
			if i := strings.Index(sub, ":/"); i > 0 {
				origin, p = sub[:i], sub[i+1:]
			}
			rendered, isAlias := fixtureAliasRendered[stem]
			if !isAlias {
				rendered = p
			}
			origins := []string{origin}
			if isAlias {
				origins = append(origins, "")
			}
			fxKinds := map[string]string{}
			for _, l := range fx.Leaves {
				fxKinds[l.Path] = l.Kind
			}
			wantLeaves := map[string]bool{}
			for l := range unionLeaves[fixtureOrigin(fx)] {
				if underPath(l, rendered) {
					wantLeaves[l] = true
				}
			}
			for _, run := range origins {
				for _, enc := range []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON} {
					resps, err := subscribeOnceOrigin(t, addr, enc, run, p)
					if err != nil {
						t.Fatalf("origin %q %v: %v", run, enc, err)
					}
					gotLeaves := map[string]string{}
					gotPrefixes := map[string]bool{}
					for _, r := range resps {
						n := r.GetUpdate()
						if n == nil {
							continue
						}
						pfx := pathToString(n.GetPrefix())
						gotPrefixes[n.GetPrefix().GetOrigin()+":"+wildcardKeysKeepProperty(pfx)] = true
						if fx.Extension == "juniper-header" {
							if len(r.GetExtension()) != 1 {
								t.Fatalf("notification without Juniper header: %v", r)
							}
							h, err := decodeJuniperHeader(r.GetExtension()[0].GetRegisteredExt().GetMsg())
							if err != nil || h.SystemID != mx10004TestSysName {
								t.Fatalf("header decode: %+v %v; want system_id %q", h, err, mx10004TestSysName)
							}
							if h.SubscribedPath != strings.TrimSuffix(p, "/") || (isAlias && h.StreamedPath != pfx) {
								t.Fatalf("header paths: subscribed %q streamed %q; want %q and the prefix %q", h.SubscribedPath, h.StreamedPath, p, pfx)
							}
						}
						for _, u := range n.GetUpdate() {
							full := strings.TrimSuffix(pfx, "/") + "/" + strings.TrimPrefix(pathToString(u.GetPath()), "/")
							gotLeaves[wildcardKeysKeepProperty(full)] = typedValueKind(u.GetVal(), enc)
						}
					}
					var missing, extra, wrongKind []string
					for l := range wantLeaves {
						gk, ok := gotLeaves[l]
						switch {
						case !ok:
							missing = append(missing, l)
						case enc == gnmipb.Encoding_PROTO && fxKinds[l] != "" && gk != fxKinds[l]:
							wrongKind = append(wrongKind, l+" got "+gk+" want "+fxKinds[l])
						}
					}
					for l := range gotLeaves {
						if !wantLeaves[l] {
							extra = append(extra, l)
						}
					}
					sort.Strings(missing)
					sort.Strings(extra)
					sort.Strings(wrongKind)
					if len(missing)+len(extra)+len(wrongKind) > 0 {
						t.Fatalf("origin %q %v shape mismatch\nmissing: %v\nextra: %v\nkind: %v", run, enc, missing, extra, wrongKind)
					}
					for gp := range gotPrefixes {
						if !unionPrefixes[gp] {
							t.Fatalf("prefix form %q not in any fixture", gp)
						}
					}
				}
			}
		})
	}
}

func typedValueKind(tv *gnmipb.TypedValue, enc gnmipb.Encoding) string {
	if enc == gnmipb.Encoding_JSON {
		return "json"
	}
	switch tv.GetValue().(type) {
	case *gnmipb.TypedValue_UintVal:
		return "uint"
	case *gnmipb.TypedValue_IntVal:
		return "int"
	case *gnmipb.TypedValue_StringVal:
		return "string"
	case *gnmipb.TypedValue_BoolVal:
		return "bool"
	case *gnmipb.TypedValue_DoubleVal:
		return "double"
	}
	return "other"
}

func subscribeOnceOrigin(t *testing.T, addr string, enc gnmipb.Encoding, origin, path string) ([]*gnmipb.SubscribeResponse, error) {
	t.Helper()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := pathFromString(t, path)
	p.Origin = origin
	if err := stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_ONCE, Encoding: enc, Subscription: []*gnmipb.Subscription{{Path: p}},
	}}}); err != nil {
		t.Fatal(err)
	}
	var out []*gnmipb.SubscribeResponse
	for {
		resp, err := stream.Recv()
		if err != nil {
			return out, err
		}
		out = append(out, resp)
		if resp.GetSyncResponse() {
			return out, nil
		}
	}
}

func TestMX10004RefusesJSONIETFLikeJunos(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	_, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "", "/system/state")
	if status.Code(err) != codes.Unimplemented || !strings.Contains(err.Error(), "Encoding 4 not supported, Only PROTO/JSON encoding supported") {
		t.Fatalf("got %v", err)
	}
}

// TestMX10004Manifest pins the served leaf set to the catalogue, the
// way TestOpticalPathManifest pins the optical surface.
func TestMX10004Manifest(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cats["juniper_mx10004"])
	served := r.AllLeafPaths()
	fromFixtures := map[string]bool{}
	for _, fx := range readShapeFixtures(t) {
		for _, l := range fx.Leaves {
			// The catalogue expands property names per component, so
			// AllLeafPaths reports them as property[name=*].
			fromFixtures[l.Path] = true
			fromFixtures[wildcardKeys(l.Path)] = true
		}
	}
	for _, p := range served {
		if !fromFixtures[p] && !strings.Contains(p, "/bgp/") {
			t.Errorf("served leaf %s has no capture behind it", p)
		}
	}
	if len(served) < 150 {
		t.Fatalf("only %d leaves served", len(served))
	}
}

// TestMX10004CountersAgreeWithSNMP: the gNMI in-octets for TestIf1
// equals ifHCInOctets.1 from the same cycler at the same instant, an
// hour after the cycler started. The SNMP side uses the cycler's own
// start, so a resolver with a different epoch fails. The boot-time
// leaf shares that epoch.
func TestMX10004CountersAgreeWithSNMP(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	dev := newTestGnmiDevice(t, 2)
	ic := dev.metricsCycler.ifCounters.Load()
	// The gNMI server comes up after the device; keep the gap visible.
	time.Sleep(5 * time.Millisecond)
	r := newCatalogResolver(dev, cats["juniper_mx10004"])
	now := ic.startTime.Add(time.Hour)
	got, err := r.Resolve(pathFromString(t, "/interfaces/interface[name=TestIf1]/state/counters/in-octets"), now)
	if err != nil || len(got) != 1 || len(got[0].Updates) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	want := ic.GetDynamicAt(ifXTablePrefix+"6.1", time.Hour.Seconds())
	if gotV := got[0].Updates[0].Value.(uint64); strconv.FormatUint(gotV, 10) != want {
		t.Fatalf("gNMI %d != SNMP %s", gotV, want)
	}
	boot, err := r.Resolve(pathFromString(t, "/system/state/last-configuration-timestamp"), now)
	if err != nil || len(boot) != 1 || len(boot[0].Updates) != 1 {
		t.Fatalf("%v %v", boot, err)
	}
	d := int64(boot[0].Updates[0].Value.(uint64)) - ic.startTime.UnixNano()
	if d < -int64(time.Microsecond) || d > int64(time.Microsecond) {
		t.Fatalf("boot timestamp is %v off the cycler start", time.Duration(d))
	}
}

// TestMX10004ServesBGPNeighbors: the captures carry no BGP subtree, so
// this pins the neighbour leaves directly: all eight per neighbour.
func TestMX10004ServesBGPNeighbors(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor")
	if err != nil {
		t.Fatal(err)
	}
	perNeighbor := map[string]map[string]bool{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		addr := n.GetPrefix().GetElem()[len(n.GetPrefix().GetElem())-1].GetKey()["neighbor-address"]
		if perNeighbor[addr] == nil {
			perNeighbor[addr] = map[string]bool{}
		}
		for _, u := range n.GetUpdate() {
			perNeighbor[addr][pathToString(u.GetPath())] = true
		}
	}
	for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
		if len(perNeighbor[a]) != 8 {
			t.Errorf("neighbor %s: %d leaves, want 8: %v", a, len(perNeighbor[a]), perNeighbor[a])
		}
	}
}

// TestMX10004HostnameMatchesHeader: system/state/hostname carries the
// device sysName, the same value as the Juniper header's system_id.
func TestMX10004HostnameMatchesHeader(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/system/state/hostname")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		h, err := decodeJuniperHeader(r.GetExtension()[0].GetRegisteredExt().GetMsg())
		if err != nil {
			t.Fatal(err)
		}
		for _, u := range n.GetUpdate() {
			if pathToString(u.GetPath()) != "/system/state/hostname" {
				continue
			}
			found = true
			if got := u.GetVal().GetStringVal(); got != h.SystemID || got != mx10004TestSysName {
				t.Errorf("hostname %q, header system_id %q, want both %q", got, h.SystemID, mx10004TestSysName)
			}
		}
	}
	if !found {
		t.Fatal("no hostname leaf served")
	}
}

// TestMX10004TemperatureOnlyOnSensorComponents: the capture streams a
// temperature for FPC0 and Routing Engine0 only, so the temperature
// subscription yields exactly the components flagged `temperature`,
// one notification each, as many as the fixture recorded.
func TestMX10004TemperatureOnlyOnSensorComponents(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, c := range cats["juniper_mx10004"].components("temperature") {
		want[c.Name] = true
	}
	var raw struct {
		Notifications int `json:"notifications"`
	}
	b, err := os.ReadFile("testdata/gnmi/juniper_mx10004/component-temp.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", fixtureSubscriptions["component-temp"])
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	notifs := 0
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		notifs++
		got[n.GetPrefix().GetElem()[1].GetKey()["name"]] = true
	}
	if len(got) != len(want) || notifs != raw.Notifications {
		t.Fatalf("temperature served on %v (%d notifications); want %v (%d in the fixture)", got, notifs, want, raw.Notifications)
	}
	for name := range want {
		if !got[name] {
			t.Errorf("no temperature for %s", name)
		}
	}
}

// TestMX10004ComponentsOneNotificationPerEntry counts notifications,
// which the shape tests above do not: they compare leaf sets, and
// passed while FPC0 and Routing Engine0 each arrived twice under one
// prefix (nl6#765), once from the inventory subtree and once from a
// temperature-only subtree on the same entry path. The capture shows
// one notification per component with temperature inside it.
func TestMX10004ComponentsOneNotificationPerEntry(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/components")
	if err != nil {
		t.Fatal(err)
	}
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	inventory := map[string]bool{}
	for _, c := range cats["juniper_mx10004"].Components {
		inventory[c.Name] = true
	}
	leavesByPrefix := map[string][]string{}
	var perComponent int // notifications whose prefix names an inventory component
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		if el := n.GetPrefix().GetElem(); n.GetPrefix().GetOrigin() == "openconfig" && len(el) == 2 && inventory[el[1].GetKey()["name"]] {
			perComponent++
		}
		key := n.GetPrefix().GetOrigin() + ":" + pathToString(n.GetPrefix())
		if _, dup := leavesByPrefix[key]; dup {
			t.Errorf("prefix %s rendered twice", key)
		}
		for _, u := range n.GetUpdate() {
			leavesByPrefix[key] = append(leavesByPrefix[key], pathToString(u.GetPath()))
		}
	}
	if want := len(inventory); perComponent != want {
		t.Errorf("component notifications = %d, want %d (one per inventory component)", perComponent, want)
	}
	hasTemp := func(comp string) bool {
		for _, l := range leavesByPrefix["openconfig:/components/component[name="+comp+"]"] {
			if l == "/state/temperature/instant" {
				return true
			}
		}
		return false
	}
	for _, comp := range []string{"FPC0", "Routing Engine0"} {
		if !hasTemp(comp) {
			t.Errorf("%s: no state/temperature/instant in its notification", comp)
		}
	}
	if hasTemp("Chassis") {
		t.Errorf("Chassis: carries a temperature leaf it has no sensor for")
	}
}
