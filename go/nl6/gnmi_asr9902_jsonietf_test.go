/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// asr9902Catalog returns the shipped cisco_asr9902 catalogue, or a
// shallow copy with json_ietf_layout set to layout when layout is not
// empty.
func asr9902Catalog(t *testing.T, layout string) *gnmiCatalog {
	t.Helper()
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	cat := cats["cisco_asr9902"]
	if cat == nil {
		t.Fatal("embedded cisco_asr9902 catalogue missing")
	}
	if layout == "" {
		return cat
	}
	cp := *cat
	cp.Notification.JSONIETFLayout = layout
	return &cp
}

func getOrigin(t *testing.T, addr string, enc gnmipb.Encoding, origin, path string) (*gnmipb.GetResponse, error) {
	t.Helper()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	p := pathFromString(t, path)
	p.Origin = origin
	return gnmipb.NewGNMIClient(conn).Get(ctx, &gnmipb.GetRequest{Path: []*gnmipb.Path{p}, Encoding: enc})
}

// onlyUpdate requires one notification with an empty prefix holding
// one update, and returns that update's decoded object.
func onlyUpdate(t *testing.T, resp *gnmipb.GetResponse) (*gnmipb.Update, map[string]any) {
	t.Helper()
	if len(resp.GetNotification()) != 1 || len(resp.GetNotification()[0].GetUpdate()) != 1 {
		t.Fatalf("want one notification with one update, got %v", resp)
	}
	n := resp.GetNotification()[0]
	if n.GetPrefix() != nil {
		t.Errorf("prefix %v, want none", n.GetPrefix())
	}
	u := n.GetUpdate()[0]
	var v map[string]any
	if err := json.Unmarshal(u.GetVal().GetJsonIetfVal(), &v); err != nil {
		t.Fatalf("value %q is not a JSON object: %v", u.GetVal().GetJsonIetfVal(), err)
	}
	return u, v
}

func TestASR9902JSONIETFGetComponentEntry(t *testing.T) {
	cat := asr9902Catalog(t, "")
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cat, 2)
	defer cleanup()
	name := cat.Components[0].Name
	req := "/components/component[name=" + name + "]/state"
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "", req)
	if err != nil {
		t.Fatal(err)
	}
	u, v := onlyUpdate(t, resp)
	if got := u.GetPath().GetOrigin() + ":" + pathToString(u.GetPath()); got != "openconfig-platform:"+req {
		t.Errorf("update path %s, want openconfig-platform:%s", got, req)
	}
	if v["name"] != name {
		t.Errorf("state name %v, want %s", v["name"], name)
	}
}

func TestASR9902JSONIETFGetWholeComponentList(t *testing.T) {
	cat := asr9902Catalog(t, "")
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, cat, 2)
	defer cleanup()
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "", "/components")
	if err != nil {
		t.Fatal(err)
	}
	u, v := onlyUpdate(t, resp)
	if got := u.GetPath().GetOrigin() + ":" + pathToString(u.GetPath()); got != "openconfig-platform:/components" {
		t.Errorf("update path %s", got)
	}
	list, ok := v["component"].([]any)
	if !ok || len(list) != len(cat.Components) {
		t.Fatalf("component is %T with %d entries, want an array of %d", v["component"], len(list), len(cat.Components))
	}
	for i, e := range list {
		entry := e.(map[string]any)
		if entry["name"] != cat.Components[i].Name {
			t.Errorf("entry %d name %v, want %s", i, entry["name"], cat.Components[i].Name)
		}
		if _, ok := entry["state"].(map[string]any); !ok {
			t.Errorf("entry %d has no state object", i)
		}
	}
}

// The counters alias crosses the interface list without a key, so each
// interface gets its own update, carrier-transitions merged in from the
// shallower subtree.
func TestASR9902JSONIETFGetCountersAcrossInterfaces(t *testing.T) {
	const ifCount = 3
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), ifCount)
	defer cleanup()
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "openconfig-interfaces", "/interfaces/interface/state/counters")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.GetNotification()) != 1 {
		t.Fatalf("%d notifications, want 1", len(resp.GetNotification()))
	}
	n := resp.GetNotification()[0]
	if n.GetPrefix() != nil || len(n.GetUpdate()) != ifCount {
		t.Fatalf("prefix %v and %d updates, want none and %d", n.GetPrefix(), len(n.GetUpdate()), ifCount)
	}
	for _, u := range n.GetUpdate() {
		p := u.GetPath()
		if p.GetOrigin() != "openconfig-interfaces" || p.GetElem()[1].GetKey()["name"] == "" || !strings.HasSuffix(pathToString(p), "/state/counters") {
			t.Errorf("update path %s:%s", p.GetOrigin(), pathToString(p))
		}
		var v map[string]any
		if err := json.Unmarshal(u.GetVal().GetJsonIetfVal(), &v); err != nil {
			t.Fatal(err)
		}
		for _, leaf := range []string{"carrier-transitions", "in-octets"} {
			if _, ok := v[leaf].(string); !ok {
				t.Errorf("%s: %s is %T, want a quoted 64-bit string", pathToString(p), leaf, v[leaf])
			}
		}
	}
}

// The catalogue owns only the counters alias among interface paths;
// /interfaces/interface/state stays on the shared resolver and per leaf.
func TestASR9902JSONIETFInterfacesStayPerLeaf(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 2)
	defer cleanup()
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "openconfig-interfaces", "/interfaces/interface/state")
	if err != nil {
		t.Fatal(err)
	}
	ups := 0
	for _, n := range resp.GetNotification() {
		for _, u := range n.GetUpdate() {
			ups++
			if v := bytes.TrimSpace(u.GetVal().GetJsonIetfVal()); len(v) == 0 || v[0] == '{' || v[0] == '[' {
				t.Fatalf("%s carries %s, want a scalar", pathToString(u.GetPath()), v)
			}
		}
	}
	if ups < 2 {
		t.Fatalf("%d updates, want one per leaf", ups)
	}
}

// listKeys names the key of each list a folded value can hold, to
// rebuild leaf paths from a folded value.
var listKeys = map[string]string{"component": "name", "interface": "name", "cpu": "index", "subinterface": "index"}

// flattenFolded adds every leaf of a folded value at base to out as
// path => JSON class.
func flattenFolded(t *testing.T, base string, v any, out map[string]string) {
	t.Helper()
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if list, ok := child.([]any); ok {
				key := listKeys[k]
				for _, e := range list {
					entry := e.(map[string]any)
					rest := map[string]any{}
					for ek, ev := range entry {
						if ek != key {
							rest[ek] = ev
						}
					}
					flattenFolded(t, base+"/"+k+"["+key+"="+jsonKey(entry[key])+"]", rest, out)
				}
				continue
			}
			flattenFolded(t, base+"/"+k, child, out)
		}
	default:
		out[base] = jsonClass(x)
	}
}

// jsonKey spells a repeated list key as the path does: a string as is,
// a number without exponent form.
func jsonKey(v any) string {
	switch x := v.(type) {
	case json.Number:
		return x.String()
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

func jsonClass(v any) string {
	switch v.(type) {
	case string:
		return "string"
	case json.Number:
		return "number"
	case bool:
		return "bool"
	}
	return "other"
}

func decodeJSONIETF(t *testing.T, b []byte) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// leavesOf answers path with one server per layout and returns each
// layout's leaves as path => JSON class.
func leavesOf(t *testing.T, layout, origin, path string) map[string]string {
	t.Helper()
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, layout), 2)
	defer cleanup()
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, origin, path)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, n := range resp.GetNotification() {
		for _, u := range n.GetUpdate() {
			v := decodeJSONIETF(t, u.GetVal().GetJsonIetfVal())
			p := strings.TrimSuffix(pathToString(n.GetPrefix()), "/") + pathToString(u.GetPath())
			if n.GetPrefix() != nil && pathToString(u.GetPath()) == "/" {
				p = pathToString(n.GetPrefix())
			}
			if layout == gnmiJSONIETFLayoutLeaf {
				out[p] = jsonClass(v)
			} else {
				flattenFolded(t, p, v, out)
			}
		}
	}
	return out
}

// The fold regroups and never chooses: the folded value holds exactly
// the leaves the per-leaf layout sends, at the same JSON class. Values
// are read at two instants, so the bytes are compared per scalar in
// TestFoldScalarsMatchPerLeafEncoding instead.
func TestASR9902JSONIETFSameLeavesAsPerLeaf(t *testing.T) {
	for _, c := range [][2]string{
		{"", "/components"},
		{"", "/system"},
		{"openconfig-interfaces", "/interfaces/interface/state/counters"},
		{"openconfig-interfaces", "/interfaces/interface/subinterfaces/subinterface/state/counters"},
	} {
		t.Run(c[1], func(t *testing.T) {
			leaf := leavesOf(t, gnmiJSONIETFLayoutLeaf, c[0], c[1])
			folded := leavesOf(t, gnmiJSONIETFLayoutContainer, c[0], c[1])
			if len(leaf) == 0 {
				t.Fatal("per-leaf layout served nothing")
			}
			var diff []string
			for p, cl := range leaf {
				if folded[p] != cl {
					diff = append(diff, "per-leaf "+p+" "+cl+", folded "+folded[p])
				}
			}
			for p := range folded {
				if _, ok := leaf[p]; !ok {
					diff = append(diff, "folded only "+p)
				}
			}
			sort.Strings(diff)
			if len(diff) > 0 {
				t.Fatalf("%d differences of %d leaves:\n  %s", len(diff), len(leaf), strings.Join(diff[:min(len(diff), 20)], "\n  "))
			}
		})
	}
}

// Subscribe folds per list entry: every update path carries the
// interface key, the prefix is empty, and the value nests the leaves.
func TestASR9902JSONIETFSubscribeOncePerEntry(t *testing.T) {
	const ifCount = 2
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), ifCount)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "openconfig-interfaces", "/interfaces/interface/state/counters")
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]bool{}
	for _, r := range resps {
		n := r.GetUpdate()
		if n == nil {
			continue
		}
		if n.GetPrefix() != nil || len(n.GetUpdate()) != 1 {
			t.Fatalf("prefix %v and %d updates, want none and 1", n.GetPrefix(), len(n.GetUpdate()))
		}
		u := n.GetUpdate()[0]
		if u.GetPath().GetOrigin() != "openconfig-interfaces" || u.GetPath().GetElem()[1].GetKey()["name"] == "" {
			t.Errorf("update path %s:%s", u.GetPath().GetOrigin(), pathToString(u.GetPath()))
		}
		var v map[string]any
		if err := json.Unmarshal(u.GetVal().GetJsonIetfVal(), &v); err != nil {
			t.Fatalf("value %q: %v", u.GetVal().GetJsonIetfVal(), err)
		}
		paths[wildcardKeys(pathToString(u.GetPath()))] = true
	}
	// The two subtrees an ASR 9902 sends per interface: carrier-transitions
	// under the shallower state prefix, the other counters below it.
	for _, want := range []string{"/interfaces/interface[name=*]/state", "/interfaces/interface[name=*]/state/counters"} {
		if !paths[want] {
			t.Errorf("no update at %s; got %v", want, paths)
		}
	}
}

// SAMPLE takes the same send path as ONCE.
func TestASR9902JSONIETFSampleFolds(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 2)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p := pathFromString(t, "/system/memory/state")
	if err := stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
		Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_JSON_IETF,
		Subscription: []*gnmipb.Subscription{{Path: p, Mode: gnmipb.SubscriptionMode_SAMPLE, SampleInterval: uint64(time.Second)}},
	}}}); err != nil {
		t.Fatal(err)
	}
	resp, err := stream.Recv()
	if err != nil {
		t.Fatal(err)
	}
	n := resp.GetUpdate()
	if n.GetPrefix() != nil || len(n.GetUpdate()) != 1 || !bytes.HasPrefix(n.GetUpdate()[0].GetVal().GetJsonIetfVal(), []byte("{")) {
		t.Fatalf("want one folded update with no prefix, got %v", n)
	}
	if got := n.GetUpdate()[0].GetPath().GetOrigin() + ":" + pathToString(n.GetUpdate()[0].GetPath()); got != "openconfig-system:/system" {
		t.Errorf("update path %s, want the entry path openconfig-system:/system", got)
	}
}

// PROTO keeps the per-leaf layout under a list-entry prefix.
func TestASR9902ProtoUnchangedUnderContainerLayout(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 2)
	defer cleanup()
	resp, err := getOrigin(t, addr, gnmipb.Encoding_PROTO, "", "/system/memory/state")
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range resp.GetNotification() {
		if n.GetPrefix() == nil {
			t.Fatal("PROTO notification lost its prefix")
		}
		for _, u := range n.GetUpdate() {
			if u.GetVal().GetJsonIetfVal() != nil {
				t.Fatalf("PROTO update %s carries JSON", pathToString(u.GetPath()))
			}
		}
	}
}

// ON_CHANGE is untouched: refused on catalogue paths, per leaf on the
// shared resolver's.
func TestASR9902JSONIETFOnChangeUnchanged(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 2)
	defer cleanup()
	for _, c := range []struct {
		origin, path string
		want         codes.Code
	}{
		{"openconfig-interfaces", "/interfaces/interface/state/counters", codes.Unimplemented},
		{"", "/interfaces/interface/state/oper-status", codes.OK},
	} {
		conn := dialTestGnmi(t, addr)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stream, err := gnmipb.NewGNMIClient(conn).Subscribe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		p := pathFromString(t, c.path)
		p.Origin = c.origin
		_ = stream.Send(&gnmipb.SubscribeRequest{Request: &gnmipb.SubscribeRequest_Subscribe{Subscribe: &gnmipb.SubscriptionList{
			Mode: gnmipb.SubscriptionList_STREAM, Encoding: gnmipb.Encoding_JSON_IETF,
			Subscription: []*gnmipb.Subscription{{Path: p, Mode: gnmipb.SubscriptionMode_ON_CHANGE}},
		}}})
		resp, err := stream.Recv()
		if got := status.Code(err); got != c.want {
			t.Errorf("ON_CHANGE %s: %v, want %v", c.path, err, c.want)
		}
		if err == nil {
			for _, u := range resp.GetUpdate().GetUpdate() {
				if v := u.GetVal().GetJsonIetfVal(); len(v) == 0 || v[0] == '{' {
					t.Errorf("ON_CHANGE %s sent %s, want a per-leaf scalar", c.path, v)
				}
			}
		}
		cancel()
		conn.Close()
	}
}

// GetRequest.type filters leaves before the fold: the ASR 9902
// catalogue serves state only, so CONFIG answers nothing.
func TestASR9902JSONIETFGetTypeFiltersBeforeFold(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 2)
	defer cleanup()
	conn := dialTestGnmi(t, addr)
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// /components ends above the list, so an emptied entry would
	// otherwise still fold to its keys.
	for _, path := range []string{"/system/memory/state", "/components"} {
		for _, c := range []struct {
			typ  gnmipb.GetRequest_DataType
			want int
		}{{gnmipb.GetRequest_CONFIG, 0}, {gnmipb.GetRequest_STATE, 1}} {
			resp, err := gnmipb.NewGNMIClient(conn).Get(ctx, &gnmipb.GetRequest{
				Path: []*gnmipb.Path{pathFromString(t, path)}, Encoding: gnmipb.Encoding_JSON_IETF, Type: c.typ,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(resp.GetNotification()); got != c.want {
				t.Errorf("%s type %v: %d notifications, want %d", path, c.typ, got, c.want)
			}
		}
	}
}

// The CPU index is union { enumeration { enum ALL; } uint32; }. PROTO
// sends ALL as string_val and a numbered CPU as uint_val, JSON_IETF as
// a JSON string and a JSON number (RFC 7951 §6.1, §6.4), as IOS-XR does.
// The path key stays a string in both (nl6#807).
func TestASR9902CPUIndexFollowsTheUnionMember(t *testing.T) {
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 1)
	defer cleanup()
	check := func(enc gnmipb.Encoding, key string, val *gnmipb.TypedValue) {
		t.Helper()
		var got any
		if enc == gnmipb.Encoding_PROTO {
			switch v := val.GetValue().(type) {
			case *gnmipb.TypedValue_StringVal:
				got = v.StringVal
			case *gnmipb.TypedValue_UintVal:
				got = float64(v.UintVal)
			}
		} else {
			// The container layout folds each CPU entry into one value.
			var obj struct {
				State map[string]any `json:"state"`
			}
			if err := json.Unmarshal(val.GetJsonIetfVal(), &obj); err != nil {
				t.Fatalf("%s value %q: %v", key, val.GetJsonIetfVal(), err)
			}
			got = obj.State["index"]
		}
		var want any = "ALL"
		if key != "ALL" {
			n, err := strconv.ParseUint(key, 10, 32)
			if err != nil {
				t.Fatalf("key %q", key)
			}
			want = float64(n)
		}
		if got != want {
			t.Errorf("%v cpu[index=%s] state/index = %v (%T), want %v (%T)", enc, key, got, got, want, want)
		}
	}
	for _, enc := range []gnmipb.Encoding{gnmipb.Encoding_PROTO, gnmipb.Encoding_JSON_IETF} {
		resps, err := subscribeOnceOrigin(t, addr, enc, "openconfig-system", "/system/cpus/cpu/state")
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, r := range resps {
			n := r.GetUpdate()
			for _, u := range n.GetUpdate() {
				full := append(append([]*gnmipb.PathElem{}, n.GetPrefix().GetElem()...), u.GetPath().GetElem()...)
				key := ""
				for _, e := range full {
					if e.GetName() == "cpu" {
						key = e.GetKey()["index"]
					}
				}
				last := full[len(full)-1].GetName()
				if (enc == gnmipb.Encoding_PROTO && last == "index") || (enc == gnmipb.Encoding_JSON_IETF && last == "cpu") {
					seen++
					check(enc, key, u.GetVal())
				}
			}
		}
		if seen != 7 {
			t.Errorf("%v: %d CPU index values, want 7 (ALL and 0..5)", enc, seen)
		}
	}
	// A folded list repeats the key as an entry member. The catalogue
	// serves the key leaf, so the member is typed like state/index.
	resp, err := getOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "", "/system/cpus")
	if err != nil {
		t.Fatal(err)
	}
	_, v := onlyUpdate(t, resp)
	cpus, _ := v["cpu"].([]any)
	if len(cpus) != 7 {
		t.Fatalf("cpu is %T with %d entries, want 7", v["cpu"], len(cpus))
	}
	for _, c := range cpus {
		entry, _ := c.(map[string]any)
		state, _ := entry["state"].(map[string]any)
		if entry["index"] == nil || entry["index"] != state["index"] {
			t.Errorf("entry index %v (%T), state/index %v (%T), want equal", entry["index"], entry["index"], state["index"], state["index"])
		}
	}
}

// A folded CPU key is typed from the catalogue's state/index leaf even
// when the request covers only state/total, so the key a value repeats
// never depends on which leaves rode along, and always equals the path
// key cast through the union (nl6#807).
func TestASR9902FoldedCPUKeyTypedFromCatalogue(t *testing.T) {
	r := newCatalogResolver(&DeviceSimulator{ID: "d", IP: net.IPv4(10, 0, 0, 1)}, asr9902Catalog(t, ""))
	req := pathFromString(t, "/system/cpus")
	cn, err := r.Resolve(req, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	for i := range cn {
		var total []resolvedUpdate
		for _, u := range cn[i].Updates {
			if strings.HasPrefix(pathToString(u.Path), "/state/total/") {
				total = append(total, u)
			}
		}
		cn[i].Updates = total
	}
	ups, err := foldJSONIETFGet(req, cn)
	if err != nil || len(ups) != 1 {
		t.Fatalf("%d updates, %v", len(ups), err)
	}
	var v struct {
		CPU []map[string]any `json:"cpu"`
	}
	if err := json.Unmarshal(ups[0].GetVal().GetJsonIetfVal(), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.CPU) != 7 {
		t.Fatalf("%d cpu entries, want 7", len(v.CPU))
	}
	for i, e := range v.CPU {
		var want any = float64(i - 1)
		if i == 0 {
			want = "ALL"
		}
		if e["index"] != want {
			t.Errorf("entry %d index %v (%T), want %v (%T)", i, e["index"], e["index"], want, want)
		}
	}
	// End to end, a state/total Subscribe folds at the entry, whose path
	// carries the key, so no value repeats it as a string.
	_, _, addr, cleanup := startTestGnmiServerWithCatalogN(t, asr9902Catalog(t, ""), 1)
	defer cleanup()
	resps, err := subscribeOnceOrigin(t, addr, gnmipb.Encoding_JSON_IETF, "openconfig-system", "/system/cpus/cpu/state/total")
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, r := range resps {
		for _, u := range r.GetUpdate().GetUpdate() {
			seen++
			var obj map[string]any
			if err := json.Unmarshal(u.GetVal().GetJsonIetfVal(), &obj); err != nil {
				t.Fatal(err)
			}
			if idx, ok := obj["index"]; ok {
				t.Errorf("%s: value repeats index %v (%T)", pathToString(u.GetPath()), idx, idx)
			}
		}
	}
	if seen != 7 {
		t.Errorf("%d state/total updates, want 7", seen)
	}
}
