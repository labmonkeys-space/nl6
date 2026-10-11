/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
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
		Path   string `json:"path"`
		Kind   string `json:"kind"`
		Always bool   `json:"always"` // sent with every notification of its entry, path coverage aside
	} `json:"leaves"`
	// Absent lists leaves another fixture of the same origin recorded
	// that this (hardware) fixture says are not sent; they are removed
	// from the expected union so an observation fixture stays intact.
	Absent []string `json:"absent"`
	// Exact says leaves is the whole set the subscription renders, so
	// the test expects exactly it instead of the union under the
	// rendered path (the subinterface counters sensor, nl6#787).
	Exact bool `json:"exact"`
}

// fixtureSubscriptions maps fixture file stems to the path gnmic
// subscribed to when the capture was taken.
var fixtureSubscriptions = map[string]string{
	"if-counters":             "/interfaces/interface/state/counters",
	"if-state":                "/interfaces/interface/state",
	"subif":                   "/interfaces/interface/subinterfaces/subinterface/state",
	"components":              "/components/component/state",
	"component-temp":          "/components/component/state/temperature",
	"components-hardware":     "/components/component/state",
	"component-temp-hardware": "/components/component/state/temperature",
	"transceiver-hardware":    "/components/component/transceiver/state/",
	"wavelength-hardware":     "/components/component/properties/property[name=wavelength]/state/",
	"subif-hardware":          "/interfaces/interface/subinterfaces/subinterface/state/counters",
	"if-counters-hardware":    "/interfaces/interface/state/counters",
	"bgp-neighbor-hardware":   "/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/",
	"bgp-peer-group-hardware": "/network-instances/network-instance/protocols/protocol/bgp/peer-groups/peer-group/",
	"component-props":         "/components/component/properties/property/state",
	"cpu":                     "/components/component/cpu/utilization/state",
	"sys-cpu":                 "/system/cpus/cpu/state",
	"sys-mem":                 "/system/memory/state",
	"system":                  "/system/state",
	"native-packet-usage":     "juniper:/junos/system/linecard/packet/usage/",
	"native-fabric-hardware":  "Native:/junos/system/linecard/fabric/",
	// A -yang fixture is read from the YANG model, not captured: it pins
	// nl6's shape, not agreement with hardware (nl6#767).
	"native-fpc-env-yang": "juniper:/junos/system/linecard/environment/",
}

// fixtureAliasRendered maps fixtures captured through a native sensor
// alias to the path Junos rendered them under. Those fixtures are also
// subscribed with an empty origin, as collectors often do.
var fixtureAliasRendered = map[string]string{
	"native-packet-usage": "/components/component/properties/property/state/value",
	// The transceiver path is an alias across four subtrees (nl6#790); the
	// fixture is exact, so this pins the alias header form only.
	"transceiver-hardware": "/components/component",
	// The subinterface counters path is a subtree alias (nl6#773)
	// scoped to the counters and init-time (nl6#787); the fixture is
	// exact, so this only names where the leaves render.
	"subif-hardware": "/interfaces/interface/subinterfaces/subinterface",
	// The fabric sensor renders under a path that is neither the
	// subscription path nor the YANG tree (nl6#767). It renders under
	// two prefixes, class-stats keyed by priority for line-card edges
	// and keyless for switch fabric edges (nl6#785); this one entry
	// covers both only because underPath strips keys.
	"native-fabric-hardware": "/junos/fabric-statistics/fabric-message/edges[dst-pfe=*][dst-slot=*][dst-type=*][src-pfe=*][src-slot=*][src-type=*]/class-stats[priority=*]/transmit-counts",
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
	// The catalogue reads MTU and speed from the device's IF-MIB rows. Only
	// those columns are added, so the test device keeps its interface names.
	res, err := (&SimulatorManager{resourcesCache: make(map[string]*DeviceResources)}).LoadSpecificResources("juniper_mx10004.json")
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if dev.resources == nil {
		dev.resources = &DeviceResources{}
	}
	if dev.resources.oidIndex == nil {
		dev.resources.oidIndex = &sync.Map{}
	}
	res.oidIndex.Range(func(k, v any) bool {
		if oid := k.(string); strings.HasPrefix(oid, ifTablePrefix+"4.") || strings.HasPrefix(oid, ifXTablePrefix+"15.") {
			dev.resources.oidIndex.Store(oid, v)
		}
		return true
	})
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
	alwaysLeaves := map[string]map[string]bool{}
	unionPrefixes := map[string]bool{} // origin:path, for requests with no origin or a canonical one
	unionPaths := map[string]bool{}    // path only, for aliased requests, answered with no origin (nl6#788)
	for _, fx := range fixtures {
		o := fixtureOrigin(fx)
		if unionLeaves[o] == nil {
			unionLeaves[o] = map[string]bool{}
			alwaysLeaves[o] = map[string]bool{}
		}
		for _, l := range fx.Leaves {
			unionLeaves[o][l.Path] = true
			if l.Always {
				alwaysLeaves[o][l.Path] = true
			}
		}
		for _, p := range fx.Prefixes {
			unionPrefixes[p] = true
			_, path, _ := strings.Cut(p, ":")
			unionPaths[path] = true
		}
	}
	for _, fx := range fixtures {
		for _, a := range fx.Absent {
			delete(unionLeaves[fixtureOrigin(fx)], a)
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
			// A keyed subscription path (property[name=wavelength]) narrows
			// the expected leaves to the ones carrying that key; the
			// matcher itself strips keys.
			keyed := keyValueRe.FindString(rendered)
			wantLeaves := map[string]bool{}
			for l := range unionLeaves[fixtureOrigin(fx)] {
				if underPath(l, rendered) && (keyed == "" || strings.Contains(l, keyed)) {
					wantLeaves[l] = true
				}
			}
			// An always-leaf is expected whenever the subscription covers
			// another leaf of the same entry, the way the sensor sends it;
			// a subscription that only reaches a deeper list (the
			// subinterfaces under an interface) does not pull it in.
			entryOf := func(l string) string { return l[:strings.LastIndex(l, "]/")+1] }
			touchedEntries := map[string]bool{}
			for l := range wantLeaves {
				touchedEntries[entryOf(l)] = true
			}
			for l := range alwaysLeaves[fixtureOrigin(fx)] {
				if touchedEntries[entryOf(l)] && unionLeaves[fixtureOrigin(fx)][l] {
					wantLeaves[l] = true
				}
			}
			if fx.Exact {
				wantLeaves = map[string]bool{}
				for _, l := range fx.Leaves {
					wantLeaves[l.Path] = true
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
					aliased := run != "" && run != "openconfig" && run != "juniper"
					for gp := range gotPrefixes {
						o, path, _ := strings.Cut(gp, ":")
						if aliased && (o != "" || !unionPaths[path]) || !aliased && !unionPrefixes[gp] {
							t.Fatalf("origin %q: prefix form %q not in any fixture (an aliased request gets an empty origin)", run, gp)
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
	case *gnmipb.TypedValue_DecimalVal:
		return "decimal"
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
		if !fromFixtures[p] {
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
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	// The entry's always-leaves (name, init-time, ...) ride along with
	// the one requested counter (nl6#775), so find it by path.
	var inOctets any
	for _, u := range got[0].Updates {
		if pathToString(u.Path) == "/state/counters/in-octets" {
			inOctets = u.Value
		}
	}
	want := ic.GetDynamicAt(ifXTablePrefix+"6.1", time.Hour.Seconds())
	if gotV, _ := inOctets.(uint64); strconv.FormatUint(gotV, 10) != want {
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
	afiSafis := 0
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		last := n.GetPrefix().GetElem()[len(n.GetPrefix().GetElem())-1]
		if last.GetName() != "neighbor" {
			afiSafis++ // the afi-safi entries below the neighbour (nl6#774)
			continue
		}
		addr := last.GetKey()["neighbor-address"]
		if perNeighbor[addr] == nil {
			perNeighbor[addr] = map[string]bool{}
		}
		for _, u := range n.GetUpdate() {
			perNeighbor[addr][pathToString(u.GetPath())] = true
		}
	}
	for _, a := range []string{"203.0.113.1", "203.0.113.2"} {
		if len(perNeighbor[a]) != 9 || !perNeighbor[a]["/state/peer-group"] {
			t.Errorf("neighbor %s: %d leaves, want 9 with peer-group: %v", a, len(perNeighbor[a]), perNeighbor[a])
		}
	}
	if afiSafis != 4 {
		t.Errorf("afi-safi notifications under the neighbour subscription = %d, want 2 neighbours x 2 families", afiSafis)
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

// TestMX10004TemperatureOnlyOnSensorComponents: the temperature
// subscription yields exactly the components flagged `temperature`,
// one notification each.
func TestMX10004TemperatureOnlyOnSensorComponents(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, c := range cats["juniper_mx10004"].components("temperature", "") {
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
	// One notification per sensor-bearing component. The fixture's
	// notification count is the vJunos capture (two sensors); the
	// catalogue now carries the hardware's sensor tree (nl6#772), so
	// the count is checked against the catalogue and the fixture count
	// is only required to be covered.
	if len(got) != len(want) || notifs != len(want) || len(want) < raw.Notifications {
		t.Fatalf("temperature served on %d components in %d notifications; want %d (fixture recorded %d)", len(got), notifs, len(want), raw.Notifications)
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
	// The transceiver sensor's oper-status shape is alias-only (nl6#790):
	// path coverage must not add a .../state notification per port.
	for _, p := range []string{"/components", "/components/component/state"} {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", p)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range resps {
			if el := r.GetUpdate().GetPrefix().GetElem(); len(el) == 3 && el[2].GetName() == "state" {
				t.Fatalf("%s: alias-only prefix %s rendered by path coverage", p, pathToString(r.GetUpdate().GetPrefix()))
			}
		}
	}
}

// TestMX10004AcceptsModuleNameAndNativeOrigins: Junos accepts the YANG
// module name as origin and `Native` for junos sensors, which is what
// an operator types (nl6#770). The aliased request must return the
// same notifications as the canonical origin, prefix paths included,
// with an empty prefix origin, as the router sends (nl6#788).
func TestMX10004AcceptsModuleNameAndNativeOrigins(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	digest := func(resps []*gnmipb.SubscribeResponse) []string {
		var out []string
		for _, r := range resps {
			n := r.GetUpdate()
			if n == nil {
				continue
			}
			var paths []string
			for _, u := range n.GetUpdate() {
				paths = append(paths, pathToString(u.GetPath()))
			}
			sort.Strings(paths)
			// Origin left out: an aliased request gets an empty prefix
			// origin (nl6#788), checked below and in TestMX10004PrefixOrigin.
			out = append(out, pathToString(n.GetPrefix())+" "+strings.Join(paths, ","))
		}
		sort.Strings(out)
		return out
	}
	for _, tc := range []struct{ alias, canonical, path string }{
		{"openconfig-interfaces", "openconfig", "/interfaces/interface/state/counters"},
		{"openconfig-platform", "openconfig", "/components/component/state"},
		{"openconfig-system", "openconfig", "/system/state"},
		{"openconfig-network-instance", "openconfig", "/network-instances/network-instance/protocols/protocol/bgp/neighbors/neighbor/state"},
		{"Native", "juniper", "/junos/system/linecard/packet/usage/"},
	} {
		t.Run(tc.alias, func(t *testing.T) {
			want, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, tc.canonical, tc.path)
			if err != nil {
				t.Fatalf("canonical: %v", err)
			}
			got, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, tc.alias, tc.path)
			if err != nil {
				t.Fatalf("alias %s: %v", tc.alias, err)
			}
			if dw, dg := digest(want), digest(got); strings.Join(dw, "\n") != strings.Join(dg, "\n") {
				for i := range dw {
					if i >= len(dg) || dw[i] != dg[i] {
						t.Fatalf("alias %s: notification %d differs\ncanonical: %s\nalias:     %s", tc.alias, i, dw[i], strings.Join(dg[i:min(i+1, len(dg))], ""))
					}
				}
				t.Fatalf("alias %s: %d notifications, canonical %d", tc.alias, len(dg), len(dw))
			}
			if len(digest(got)) == 0 {
				t.Fatal("no notifications")
			}
			for _, r := range got {
				if o := r.GetUpdate().GetPrefix().GetOrigin(); r.GetUpdate() != nil && o != "" {
					t.Fatalf("alias %s: prefix origin %q, want empty", tc.alias, o)
				}
			}
		})
	}
	if _, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "cisco-iosxr", "/interfaces"); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown origin: got %v, want NotFound", err)
	}
	// A path the catalogue does not own falls through to the legacy
	// resolver, which must see the canonical origin too: the error names
	// the path, never the alias spelling.
	_, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "openconfig-interfaces", "/interfaces/interface/state/counters/in-unknown-protos")
	if err == nil || strings.Contains(err.Error(), "openconfig-interfaces") {
		t.Fatalf("uncovered path under an alias: %v (must not refuse the origin spelling)", err)
	}
	// Get takes the same aliases.
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	gp := pathFromString(t, "/system/state/hostname")
	gp.Origin = "openconfig-system"
	resp, err := gnmipb.NewGNMIClient(conn).Get(ctx, &gnmipb.GetRequest{Encoding: gnmipb.Encoding_PROTO, Path: []*gnmipb.Path{gp}})
	if err != nil || len(resp.GetNotification()) == 0 || resp.GetNotification()[0].GetPrefix().GetOrigin() != "" {
		t.Fatalf("Get under module-name origin: err=%v resp=%v", err, resp)
	}
}

// TestMX10004PrefixOrigin pins nl6#788: a module-name or Native request
// gets an empty prefix origin, a property subscription echoes the module
// name, and a request with no origin or a canonical one keeps the
// canonical origin, as the vJunos capture shows.
func TestMX10004PrefixOrigin(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	const overTemp = "/components/component/properties/property[name=over-temperature]/state/"
	for _, tc := range []struct{ origin, path, wantOrigin, wantPrefix string }{
		{"openconfig-system", "/system/cpus/cpu/state", "", "/system/cpus/cpu[index="},
		{"openconfig-platform", overTemp, "openconfig-platform", "/components/component["},
		{"Native", "/junos/system/linecard/fabric", "", "/junos/fabric-statistics/"},
		{"", "/system/cpus/cpu/state", "openconfig", "/system/cpus/cpu[index="},
		{"openconfig", "/system/cpus/cpu/state", "openconfig", "/system/cpus/cpu[index="},
		{"", overTemp, "openconfig", "/components/component["},
		{"juniper", "/junos/system/linecard/packet/usage/", "juniper", "/components/component["},
		{"Native", "/junos/system/linecard/packet/usage/", "", "/components/component["},
	} {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, tc.origin, tc.path)
		if err != nil {
			t.Fatalf("%s:%s: %v", tc.origin, tc.path, err)
		}
		n := 0
		for _, r := range resps {
			u := r.GetUpdate()
			if u == nil {
				continue
			}
			n++
			if o, pfx := u.GetPrefix().GetOrigin(), pathToString(u.GetPrefix()); o != tc.wantOrigin || !strings.HasPrefix(pfx, tc.wantPrefix) {
				t.Fatalf("%s:%s: prefix %s:%s, want origin %q and %s...", tc.origin, tc.path, o, pfx, tc.wantOrigin, tc.wantPrefix)
			}
		}
		if n == 0 {
			t.Fatalf("%s:%s: no notifications", tc.origin, tc.path)
		}
	}
	// gNMI puts the origin on the request prefix when one is used; the
	// joined path takes it.
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, tc := range []struct{ origin, want string }{{"openconfig-system", ""}, {"openconfig", "openconfig"}} {
		pfx := pathFromString(t, "/system")
		pfx.Origin = tc.origin
		resp, err := gnmipb.NewGNMIClient(conn).Get(ctx, &gnmipb.GetRequest{Encoding: gnmipb.Encoding_PROTO, Prefix: pfx, Path: []*gnmipb.Path{pathFromString(t, "/cpus/cpu/state")}})
		if err != nil || len(resp.GetNotification()) == 0 {
			t.Fatalf("Get with prefix origin %q: %v", tc.origin, err)
		}
		for _, n := range resp.GetNotification() {
			if n.GetPrefix().GetOrigin() != tc.want {
				t.Fatalf("Get with prefix origin %q: response prefix origin %q, want %q", tc.origin, n.GetPrefix().GetOrigin(), tc.want)
			}
		}
	}
}

// TestMX10004ComponentInventory pins nl6#772 and nl6#789: the hardware's
// component cardinality, classes and names, and the full temperature record on a
// sensor, with temperature leaves as Decimal64 precision 1.
func TestMX10004ComponentInventory(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/components/component/state")
	if err != nil {
		t.Fatal(err)
	}
	leaves := map[string]map[string]*gnmipb.TypedValue{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil || len(n.GetPrefix().GetElem()) != 2 {
			continue
		}
		name := n.GetPrefix().GetElem()[1].GetKey()["name"]
		leaves[name] = map[string]*gnmipb.TypedValue{}
		for _, u := range n.GetUpdate() {
			leaves[name][pathToString(u.GetPath())] = u.GetVal()
		}
	}
	if len(leaves) < 250 {
		t.Fatalf("%d components, want at least 250", len(leaves))
	}
	for _, class := range []string{"CB0:INTAKE_A_TEMP_SENSOR", "ROUTING_ENGINE0:CPU", "FPC0:PIC1:PORT23", "FPC0:PIC0:PORT0:Xcvr0", "FPC0:EA0_HMC0_LOGIC_DIE", "FPC0:CPU_TEMP_SENSOR", "FPD Board", "PEM1:TEMP_SENSOR_1", "FTC1", "Fan Tray 1 Fan 11", "SFB5", "SFB5:ZF0_INTERNAL_REMOTE_0", "FPC1:PIC5:PORT3:Xcvr0", "FPC1:EA3_HMC1_DRAM_BOTM", "FPC1:CPU"} {
		if leaves[class] == nil {
			t.Errorf("component %s missing", class)
		}
	}
	// nl6#789: the router's component names. Every FPC sensor outside
	// the EA HMC family ends in _TEMP_SENSOR, there is no MIC, and each
	// SFB has ZF0_INTERNAL_REMOTE_0 to _6.
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	fpcSensors := 0
	for _, c := range cats["juniper_mx10004"].Components {
		if c.Type == "SENSOR" && strings.HasPrefix(c.Parent, "FPC") && !strings.Contains(c.Name, "_HMC") {
			fpcSensors++
			if !strings.HasSuffix(c.Name, "_TEMP_SENSOR") || strings.Contains(c.Name, "-") {
				t.Errorf("FPC sensor %s; the router names them FPCn:<NAME>_TEMP_SENSOR", c.Name)
			}
		}
	}
	if fpcSensors < 12 {
		t.Errorf("%d FPC sensors outside the HMC family, want at least 12", fpcSensors)
	}
	for _, s := range []string{"EXHAUST_A", "EXHAUST_B", "EXHAUST_C", "INTAKE_A", "INTAKE_B", "PEXSW", "PMB", "CPU"} {
		if leaves["FPC0:"+s+"_TEMP_SENSOR"] == nil {
			t.Errorf("FPC0:%s_TEMP_SENSOR missing", s)
		}
	}
	remotes := map[string]int{}
	for n := range leaves {
		if strings.HasPrefix(n, "FPC") && strings.Contains(n, ":MIC") {
			t.Errorf("MIC component %s served; the router reports none", n)
		}
		if sfb, rest, ok := strings.Cut(n, ":ZF0_INTERNAL_REMOTE_"); ok {
			if i, err := strconv.Atoi(rest); err != nil || i < 0 || i > 6 {
				t.Errorf("unexpected remote sensor %s", n)
			}
			remotes[sfb]++
		}
	}
	for i := 0; i < 6; i++ {
		if sfb := "SFB" + strconv.Itoa(i); remotes[sfb] != 7 {
			t.Errorf("%s has %d ZF0_INTERNAL_REMOTE sensors, want 7", sfb, remotes[sfb])
		}
	}
	sensor := leaves["SFB0:PCIE_SWITCH_TEMP"]
	for _, leaf := range []string{"/state/firmware-version", "/state/temperature/alarm-status", "/state/temperature/alarm-threshold", "/state/temperature/interval", "/state/temperature/max-time", "/state/temperature/min-time"} {
		if sensor[leaf] == nil {
			t.Errorf("sensor lacks %s", leaf)
		}
	}
	for _, leaf := range []string{"instant", "avg", "min", "max"} {
		d := sensor["/state/temperature/"+leaf].GetDecimalVal() //nolint:staticcheck // gNMI deprecates Decimal64; Junos still sends it (nl6#772)
		if d == nil || d.GetPrecision() != 1 {
			t.Errorf("temperature/%s = %v, want Decimal64 precision 1", leaf, sensor["/state/temperature/"+leaf])
		}
	}
	if fan := leaves["Fan Tray 0 Fan 0"]; fan["/state/temperature/instant"] != nil {
		t.Errorf("a fan carries a temperature it has no sensor for")
	}
}

// TestMX10004OverTemperatureCarriers pins nl6#789: over-temperature
// rides every PIC, Routing Engine and SFB and nothing else. The
// expected set is derived from the inventory, so the static key list in
// the bindings cannot drift from it unnoticed.
func TestMX10004OverTemperatureCarriers(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, c := range cats["juniper_mx10004"].Components {
		isPIC := strings.HasPrefix(c.Name, "FPC") && strings.Count(c.Name, ":") == 1 && strings.Contains(c.Name, ":PIC")
		if isPIC || strings.HasPrefix(c.Name, "Routing Engine") || c.Type == "FABRIC" {
			want[c.Name] = true
		}
	}
	if len(want) < 10 {
		t.Fatalf("inventory yields %d carriers, want at least 10 (2 PICs, 2 Routing Engines, 6 SFBs)", len(want))
	}
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/components/component/properties/property[name=over-temperature]/state/")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		e := n.GetPrefix().GetElem()
		if len(e) != 4 || e[3].GetKey()["name"] != "over-temperature" {
			t.Fatalf("unexpected prefix %s", pathToString(n.GetPrefix()))
		}
		got[e[1].GetKey()["name"]]++
	}
	for c := range want {
		if got[c] != 1 {
			t.Errorf("%s: %d over-temperature notifications, want 1", c, got[c])
		}
	}
	for c := range got {
		if !want[c] {
			t.Errorf("%s carries over-temperature; the router sends it only on PICs, Routing Engines and SFBs", c)
		}
	}
}

// TestMX10004Transceivers pins nl6#771 and nl6#790: every transceiver
// component renders the static, analog and oper-status hardware shapes,
// every port the oper-status shape, analog leaves as doubles, the
// wavelength property sits on every port, and a packet type without a
// catalogue refuses the transceiver path by naming the path.
func TestMX10004Transceivers(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/components/component/transceiver/state/")
	if err != nil {
		t.Fatal(err)
	}
	shapes := map[string]map[string]int{} // component -> prefix tail -> updates
	seen := map[string]int{}              // component/tail -> notifications (one entry, one notification)
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		el := n.GetPrefix().GetElem()
		if len(el) < 2 || len(el) > 3 {
			t.Fatalf("prefix %s: want component[name=*] with an optional transceiver or state tail", pathToString(n.GetPrefix()))
		}
		name := el[1].GetKey()["name"]
		tail := ""
		if len(el) == 3 {
			tail = el[2].GetName()
		}
		if shapes[name] == nil {
			shapes[name] = map[string]int{}
		}
		seen[name+"/"+tail]++
		shapes[name][tail] += len(n.GetUpdate())
		if tail == "transceiver" {
			for _, u := range n.GetUpdate() {
				if _, ok := u.GetVal().GetValue().(*gnmipb.TypedValue_DoubleVal); strings.HasSuffix(pathToString(u.GetPath()), "/instant") && !ok {
					t.Errorf("%s %s is %v, want a double", name, pathToString(u.GetPath()), u.GetVal())
				}
			}
		}
		if tail == "state" && (len(n.GetUpdate()) != 1 || pathToString(n.GetUpdate()[0].GetPath()) != "/oper-status") {
			t.Errorf("%s state notification carries %v, want oper-status alone", name, n.GetUpdate())
		}
	}
	transceivers, ports := 0, 0
	for name := range shapes {
		if strings.Contains(name, ":Xcvr") {
			transceivers++
		} else {
			ports++
		}
	}
	if transceivers != 72 || ports != 72 {
		t.Fatalf("%d transceivers and %d ports, want 72 each", transceivers, ports)
	}
	for k, c := range seen {
		if c != 1 {
			t.Errorf("%s rendered %d times under one prefix", k, c)
		}
	}
	for name, sh := range shapes {
		if !strings.Contains(name, ":Xcvr") {
			if sh["state"] != 1 || len(sh) != 1 {
				t.Errorf("port %s shapes = %v, want oper-status alone", name, sh)
			}
			continue
		}
		if sh[""] != 13 || sh["transceiver"] != 4 || sh["state"] != 1 || len(sh) != 3 {
			t.Errorf("%s shapes = %v, want 13 static, 4 analog and oper-status", name, sh)
		}
	}
	resps, err = subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/components/component/properties/property[name=wavelength]/state/")
	if err != nil {
		t.Fatal(err)
	}
	ports = 0
	for _, r := range resps {
		if n := r.GetUpdate(); n != nil {
			ports++
			if len(n.GetUpdate()) != 2 {
				t.Errorf("wavelength on %s: %d leaves, want configurable and value", pathToString(n.GetPrefix()), len(n.GetUpdate()))
			}
		}
	}
	if ports != 72 {
		t.Errorf("wavelength on %d components, want 72 ports", ports)
	}
	// A packet type without a catalogue: the error names the path.
	_, _, paddr, pcleanup := startTestGnmiServerWithCatalog(t, nil)
	defer pcleanup()
	_, err = subscribeOnceOrigin(t, paddr, gnmipb.Encoding_PROTO, "", "/components/component/transceiver/state/")
	if status.Code(err) != codes.NotFound || strings.Contains(err.Error(), "serves no optical") || !strings.Contains(err.Error(), "matches no entry") {
		t.Fatalf("packet type: %v, want NotFound naming the path", err)
	}
}

// TestMX10004ServesBGPAfiSafis pins nl6#774: one notification per
// neighbour and family with the 28 afi-safi leaves, one per peer-group
// and family with the 27 peer-group leaves, and prefix counters that
// move between two resolves.
func TestMX10004ServesBGPAfiSafis(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	const bgp = "/network-instances/network-instance/protocols/protocol/bgp/"
	collect := func(path string) map[string]map[string]*gnmipb.TypedValue {
		resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", path)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]map[string]*gnmipb.TypedValue{}
		for _, r := range resps {
			n := r.GetUpdate()
			if n == nil {
				continue
			}
			key := pathToString(n.GetPrefix())
			if _, dup := out[key]; dup {
				t.Errorf("%s rendered twice", key)
			}
			out[key] = map[string]*gnmipb.TypedValue{}
			for _, u := range n.GetUpdate() {
				out[key][pathToString(u.GetPath())] = u.GetVal()
			}
		}
		return out
	}
	nb := collect(bgp + "neighbors/neighbor/afi-safis/afi-safi/")
	if len(nb) != 4 {
		t.Fatalf("neighbour afi-safi entries = %d, want 2 neighbours x 2 families", len(nb))
	}
	for prefix, leaves := range nb {
		switch {
		case strings.Contains(prefix, "[afi-safi-name=IPV4_UNICAST]"):
			if len(leaves) != 28 || leaves["/state/prefixes/received"] == nil || leaves["/ipv4-unicast/prefix-limit/state/max-prefixes"] == nil || leaves["/ipv6-unicast/prefix-limit/state/max-prefixes"] != nil {
				t.Errorf("%s: %d leaves, want 28 with ipv4-unicast containers only", prefix, len(leaves))
			}
		case strings.Contains(prefix, "[afi-safi-name=IPV6_UNICAST]"):
			if len(leaves) != 27 || leaves["/ipv6-unicast/prefix-limit/state/max-prefixes"] == nil || leaves["/ipv4-unicast/state/extended-next-hop-encoding"] != nil {
				t.Errorf("%s: %d leaves, want 27 with ipv6-unicast containers only", prefix, len(leaves))
			}
		default:
			t.Errorf("%s: family key missing", prefix)
		}
	}
	const rendered = "/network-instances/network-instance[name=DEFAULT]/protocols/protocol[identifier=BGP][name=DEFAULT]/bgp"
	groups := collect(bgp + "peer-groups/peer-group/state")
	if g := groups[rendered+"/peer-groups/peer-group[peer-group-name=IBGP-CORE]"]; len(groups) != 2 || g == nil || g["/state/peer-type"].GetStringVal() != "INTERNAL" || g["/state/peer-as"].GetUintVal() != g["/state/local-as"].GetUintVal() {
		t.Errorf("peer-group state = %v; IBGP-CORE must be INTERNAL with peer-as == local-as", groups)
	}
	pg := collect(bgp + "peer-groups/peer-group/afi-safis/afi-safi/")
	if len(pg) != 4 {
		t.Fatalf("peer-group afi-safi entries = %d, want 2 groups x 2 families", len(pg))
	}
	for prefix, leaves := range pg {
		want := 21
		if strings.Contains(prefix, "IPV6_UNICAST") {
			want = 20
		}
		if len(leaves) != want || leaves["/state/total-paths"] == nil || leaves["/state/total-prefixes"] == nil {
			t.Errorf("%s: %d leaves, want %d with total-paths and total-prefixes", prefix, len(leaves), want)
		}
	}
	// The transit group carries both neighbours: its prefix total is at
	// least the members' received sum; the core group has no members.
	sum := uint64(0)
	for prefix, leaves := range nb {
		if strings.Contains(prefix, "IPV4_UNICAST") {
			sum += leaves["/state/prefixes/received"].GetUintVal()
		}
	}
	transit := pg[rendered+"/peer-groups/peer-group[peer-group-name=EBGP-TRANSIT]/afi-safis/afi-safi[afi-safi-name=IPV4_UNICAST]"]
	if transit == nil || transit["/state/total-prefixes"].GetUintVal() < sum {
		t.Errorf("EBGP-TRANSIT total-prefixes %v below the members' received sum %d", transit["/state/total-prefixes"], sum)
	}
	// Counters move: a second resolve an hour later reads higher.
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 1), cats["juniper_mx10004"])
	// pathFromString parses one key per element, so the protocol element stays wildcard.
	p := pathFromString(t, "/network-instances/network-instance[name=DEFAULT]/protocols/protocol/bgp/neighbors/neighbor[neighbor-address=203.0.113.1]/afi-safis/afi-safi[afi-safi-name=IPV4_UNICAST]/state/prefixes/received")
	first, err := r.Resolve(p, time.Now())
	if err != nil || len(first) != 1 || len(first[0].Updates) != 1 {
		t.Fatalf("first resolve: %v %v", err, first)
	}
	second, err := r.Resolve(p, time.Now().Add(time.Hour))
	if err != nil || len(second) != 1 || len(second[0].Updates) != 1 {
		t.Fatalf("second resolve: %v %v", err, second)
	}
	v1, ok1 := first[0].Updates[0].Value.(uint32)
	v2, ok2 := second[0].Updates[0].Value.(uint32)
	if !ok1 || !ok2 || v2 <= v1 {
		t.Fatalf("prefixes/received did not advance: %v -> %v", first[0].Updates[0].Value, second[0].Updates[0].Value)
	}
}

// TestMX10004SubinterfaceFamilyCounters pins nl6#773: every subinterface
// notification carries the eight state counters, the sixteen family
// counters and init-time, and every family counter is non-decreasing.
func TestMX10004SubinterfaceFamilyCounters(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	r := newCatalogResolver(newTestGnmiDevice(t, 2), cats["juniper_mx10004"])
	// The issue's acceptance path: a subscription to the counters
	// container renders the whole subinterface through the subtree alias.
	p := pathFromString(t, "/interfaces/interface/subinterfaces/subinterface/state/counters")
	now := time.Now()
	first, err := r.Resolve(p, now)
	if err != nil || len(first) != 2 {
		t.Fatalf("resolve: %v, %d notifications (want one per interface)", err, len(first))
	}
	later, err := r.Resolve(p, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range first {
		vals := map[string]uint64{}
		counters := 0
		for _, u := range n.Updates {
			ps := pathToString(u.Path)
			if v, ok := u.Value.(uint64); ok {
				vals[ps] = v
			}
			if strings.Contains(ps, "/counters/") || ps == "/init-time" {
				counters++
			}
		}
		if counters != 25 {
			t.Errorf("%s: %d counter leaves, want 25", pathToString(n.Prefix), counters)
		}
		for _, u := range later[i].Updates {
			ps := pathToString(u.Path)
			if !strings.HasPrefix(ps, "/ipv4/") && !strings.HasPrefix(ps, "/ipv6/") {
				continue
			}
			if v, ok := u.Value.(uint64); !ok || v < vals[ps] {
				t.Errorf("%s %s went from %d to %v", pathToString(n.Prefix), ps, vals[ps], u.Value)
			}
		}
	}
}

// TestMX10004InterfaceCounterLeafSet pins nl6#775: every out-queue
// notification carries exactly the five leaves the router sends, and
// the interface entry serves name, init-time, high-speed and
// parent-ae-name.
func TestMX10004InterfaceCounterLeafSet(t *testing.T) {
	addr, cleanup := startMX10004Server(t)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/interfaces/interface/state/counters")
	if err != nil {
		t.Fatal(err)
	}
	queues := 0
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil || !strings.Contains(pathToString(n.GetPrefix()), "/out-queue[") {
			continue
		}
		queues++
		got := map[string]bool{}
		for _, u := range n.GetUpdate() {
			got[pathToString(u.GetPath())] = true
		}
		want := []string{"/queue-number", "/queued-bytes", "/queued-pkts", "/hp-red-drop-pkts", "/lp-red-drop-pkts"}
		if len(got) != len(want) {
			t.Errorf("%s: %v, want exactly %v", pathToString(n.GetPrefix()), got, want)
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s: missing %s", pathToString(n.GetPrefix()), w)
			}
		}
	}
	if queues == 0 {
		t.Fatal("no out-queue notifications")
	}
	// The same counters subscription carries the sensor's identity
	// leaves (always-leaves) and nothing else beside the counters.
	checked := 0
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil || len(n.GetPrefix().GetElem()) != 2 {
			continue
		}
		checked++
		got := map[string]bool{}
		for _, u := range n.GetUpdate() {
			got[pathToString(u.GetPath())] = true
		}
		for _, w := range []string{"/name", "/init-time", "/state/high-speed", "/state/parent-ae-name"} {
			if !got[w] {
				t.Errorf("%s: missing %s under the counters subscription", pathToString(n.GetPrefix()), w)
			}
		}
		if got["/state/admin-status"] || got["/state/mtu"] {
			t.Errorf("%s: counters subscription carries whole-entry state leaves", pathToString(n.GetPrefix()))
		}
	}
	if checked == 0 {
		t.Fatal("no interface notifications")
	}
}

// TestMX10004SpeedMTUAndOpticsComeFromTheDevice: gNMI reads speed and MTU
// from the device's IF-MIB rows and the optic type from each component.
func TestMX10004SpeedMTUAndOpticsComeFromTheDevice(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile("resources/juniper_mx10004/gnmi.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"ifmib:ifHighSpeed"`, `"ifmib:ifMtu"`, `"inventory:form_factor"`, `"inventory:ethernet_pmd"`, `"inventory:wavelength"`} {
		if !bytes.Contains(raw, []byte(s)) {
			t.Errorf("the MX10004 catalogue does not bind %s", s)
		}
	}
	for _, s := range []string{`"const:10000"`, `"const:1514"`, `"const:SFP_PLUS"`, `"const:850"`} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("the MX10004 catalogue still binds %s", s)
		}
	}
	for _, c := range cats["juniper_mx10004"].Components {
		if c.Type == "TRANSCEIVER" && (c.FormFactor == "" || c.EthernetPMD == "") {
			t.Errorf("transceiver %s has no optic type", c.Name)
		}
		if c.Type == "PORT" && c.Wavelength == "" {
			t.Errorf("port %s has no wavelength", c.Name)
		}
	}
}
