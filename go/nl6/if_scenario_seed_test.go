/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"strings"
	"testing"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// -if-scenario is seeded into the interface-state engine (nl6#692).
//
// The issue reported that a SET of ifAdminStatus applied to the engine while
// GET read a scenario override. Probing showed the inverse: findResponse asked
// the cycler BEFORE the override, and the cycler has served .7/.8 from the
// engine since v0.8.0, so on every engine-backed device the override was dead
// and the flag did nothing. These tests pin the flag's effect at seed time and
// the absence of any read-time override between the engine and the encoders.

// withIfScenario sets the process-wide scenario for one test and restores it.
func withIfScenario(t *testing.T, scenario, pct int) {
	t.Helper()
	prev := *ifStateConfig
	*ifStateConfig = IfStateConfig{Scenario: scenario, FailurePct: pct}
	t.Cleanup(func() { *ifStateConfig = prev })
}

// v2cGetNext answers a single-binding v2c GETNEXT with the successor's name
// and its INTEGER value rendered as a decimal string.
func v2cGetNextValue(t *testing.T, s *SNMPServer, oid string) (string, string) {
	t.Helper()
	resp := s.handleSNMPv2cRequest(snmpRequestAt(ASN1_GET_NEXT, snmpVersion2c, []string{oid}))
	vbs := decodeV2cVarbinds(t, resp)
	if len(vbs) != 1 {
		t.Fatalf("GETNEXT %s: %d bindings", oid, len(vbs))
	}
	if vbs[0].valueTag != ASN1_INTEGER {
		t.Fatalf("GETNEXT %s: tag 0x%02X, want INTEGER", oid, vbs[0].valueTag)
	}
	v, ok := parseBERInt(vbs[0].value, 0, len(vbs[0].value))
	if !ok {
		t.Fatalf("GETNEXT %s: unparseable INTEGER % x", oid, vbs[0].value)
	}
	return vbs[0].oid, fmt.Sprint(v)
}

// The test with detection power: on main before this change an engine-backed
// device under scenario 3 read ifOperStatus = 1 on GET and on a walk, because
// the engine was seeded from JSON alone. Reverting the seed call fails this.
func TestIfScenario3SeedsEveryInterfaceOperDown(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 10)
	s, state := newSetTestServer(t, 4)
	for i := 1; i <= 4; i++ {
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfAdminStatus, i)); got != "1" {
			t.Errorf("GET ifAdminStatus.%d = %s, want 1", i, got)
		}
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, i)); got != "2" {
			t.Errorf("GET ifOperStatus.%d = %s, want 2 (scenario 3 seeds oper down)", i, got)
		}
		// A seed is not a transition.
		if got := state.LastChangeNs(i); got != state.bootTimeUnixNs {
			t.Errorf("LastChangeNs(%d) = %d, want the boot epoch %d", i, got, state.bootTimeUnixNs)
		}
	}
	// The walk reads the same engine: GETNEXT from the column and along it.
	prev := oidIfOperStatus
	for i := 1; i <= 4; i++ {
		name, val := v2cGetNextValue(t, s, prev)
		want := fmt.Sprintf("%s.%d", oidIfOperStatus, i)
		if name != want || val != "2" {
			t.Errorf("GETNEXT %s = (%s, %s), want (%s, 2)", prev, name, val, want)
		}
		prev = name
	}
}

// The nl6#692 acceptance: under scenario 3 a SET is read back by GET and by a
// walk. NOTE: this arm PASSES on main before the change for an engine-backed
// device, because the override it was written against was already dead there.
// It pins the outcome; TestIfScenario3SeedsEveryInterfaceOperDown pins the
// mechanism.
func TestSetUnderNonDefaultScenarioIsReadBack(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 10)
	s, _ := newSetTestServer(t, 3)
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Fatalf("precondition: ifOperStatus.2 = %s, want 2", got)
	}
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".2", 2)}); status != snmpErrNoError {
		t.Fatalf("SET admin down: status %d", status)
	}
	if got := v2cGet(t, s, oidIfAdminStatus+".2"); got != "2" {
		t.Errorf("after SET, GET ifAdminStatus.2 = %s, want 2", got)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Errorf("after SET, GET ifOperStatus.2 = %s, want 2", got)
	}
	if name, val := v2cGetNextValue(t, s, oidIfAdminStatus+".1"); name != oidIfAdminStatus+".2" || val != "2" {
		t.Errorf("walk after SET: (%s, %s), want (%s.2, 2)", name, val, oidIfAdminStatus)
	}
	// AN ADMIN BOUNCE DOES NOT HEAL THE CABLE (nl6#694). Scenario 3 is
	// documented as "link failures, SFP issues, cable pull", so it seeds the
	// LINK down; admin-up releases oper to that link rather than forcing it up,
	// and the fault the scenario exists to simulate survives the bounce.
	//
	// This assertion is inverted from nl6#693, which required ifOperStatus = 1
	// here and so required an admin bounce to repair a simulated cable pull.
	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".2", 1)}); status != snmpErrNoError {
		t.Fatalf("SET admin up: status %d", status)
	}
	if got := v2cGet(t, s, oidIfAdminStatus+".2"); got != "1" {
		t.Errorf("after SET up, GET ifAdminStatus.2 = %s, want 1", got)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Errorf("after SET up, GET ifOperStatus.2 = %s, want 2: the link is still down", got)
	}
	if name, val := v2cGetNextValue(t, s, oidIfOperStatus+".1"); name != oidIfOperStatus+".2" || val != "2" {
		t.Errorf("walk after the bounce: (%s, %s), want (%s.2, 2) — GET and the walk must agree",
			name, val, oidIfOperStatus)
	}
	// Interfaces never named still carry the seed.
	for _, i := range []int{1, 3} {
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, i)); got != "2" {
			t.Errorf("ifOperStatus.%d = %s, want 2 (untouched seed)", i, got)
		}
	}
}

// Scenario 1 seeds admin down and PRESERVES the link (nl6#694). The
// observable oper follows by derivation, so the fleet reads down/down exactly
// as before; what changed is that the link survives, and a SET of admin up
// surfaces it with the same event sequence a REST POST produces.
//
// nl6#693 had to write oper explicitly here because a seed runs no cascade.
// Under derivation the forcing lives in the accessor, so writing the link down
// as well would model a fleet of severed cables rather than shut ports — and
// unshutting a port would then leave it dead.
func TestIfScenario1SeedsAdminDownPreservesTheLinkAndSetRaisesIt(t *testing.T) {
	withIfScenario(t, IfScenarioAllShutdown, 10)
	s, state := newSetTestServer(t, 2)
	for i := 1; i <= 2; i++ {
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfAdminStatus, i)); got != "2" {
			t.Errorf("GET ifAdminStatus.%d = %s, want 2", i, got)
		}
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, i)); got != "2" {
			t.Errorf("GET ifOperStatus.%d = %s, want 2", i, got)
		}
		// ifLastChange is TimeTicks, so it does not go through v2cGet's
		// INTEGER decoder; the cycler's serve path is the same one GET
		// reaches through findResponse.
		ic := s.device.metricsCycler.ifCounters.Load()
		if got := ic.GetDynamic(fmt.Sprintf("%s.%d", oidIfLastChange, i)); got != "0" {
			t.Errorf("ifLastChange.%d = %s, want 0 (a seed is not a transition)", i, got)
		}
	}

	type key struct {
		ifIndex     int
		oper, admin uint8
		changed     StateLeafBits
	}
	ch := make(chan StateChange, 16)
	state.AddListener(ch)
	defer state.RemoveListener(ch)
	hooks := 0
	state.SetNotify(func(StateChange) { hooks++ })
	defer state.SetNotify(nil)

	if status, _ := setVia(t, s, snmpVersion2c, []testBind{intBind(oidIfAdminStatus+".1", 1)}); status != snmpErrNoError {
		t.Fatalf("SET admin up: status %d", status)
	}
	if got := v2cGet(t, s, oidIfAdminStatus+".1"); got != "1" {
		t.Errorf("after SET, GET ifAdminStatus.1 = %s, want 1", got)
	}
	if got := v2cGet(t, s, oidIfOperStatus+".1"); got != "1" {
		t.Errorf("after SET, GET ifOperStatus.1 = %s, want 1: the link was preserved by the seed", got)
	}
	var got []key
	for done := false; !done; {
		select {
		case e := <-ch:
			got = append(got, key{e.IfIndex, e.Oper, e.Admin, e.Changed})
		default:
			done = true
		}
	}
	// Both events come from one swap, so both carry the post-swap derived oper.
	want := []key{{1, OperUp, AdminUp, LeafAdminStatus}, {1, OperUp, AdminUp, LeafOperStatus}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("events = %+v, want %+v", got, want)
	}
	if hooks != 1 {
		t.Errorf("notify hook fired %d times, want 1", hooks)
	}
	// Interface 2 keeps the seed.
	if got := v2cGet(t, s, oidIfOperStatus+".2"); got != "2" {
		t.Errorf("ifOperStatus.2 = %s, want 2", got)
	}
}

// Scenario 4 puts down exactly the interfaces with ifIndex % 100 < pct.
func TestIfScenario4IsDeterministicOnIfIndexModulo100(t *testing.T) {
	for _, pct := range []int{0, 30, 100} {
		t.Run(fmt.Sprintf("pct%d", pct), func(t *testing.T) {
			withIfScenario(t, IfScenarioPctFailure, pct)
			s, _ := newSetTestServer(t, 40)
			for i := 1; i <= 40; i++ {
				if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfAdminStatus, i)); got != "1" {
					t.Errorf("GET ifAdminStatus.%d = %s, want 1", i, got)
				}
				want := "1"
				if i%100 < pct {
					want = "2"
				}
				if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, i)); got != want {
					t.Errorf("GET ifOperStatus.%d = %s, want %s", i, got, want)
				}
			}
		})
	}
}

// The default scenario is the identity over the JSON seed. The wire digests
// pin the shipped corpus; this pins the fixture the other tests use.
func TestIfScenario2LeavesTheJSONSeedAlone(t *testing.T) {
	withIfScenario(t, IfScenarioAllNormal, 10)
	s, state := newSetTestServer(t, 2)
	for i := 1; i <= 2; i++ {
		if got := v2cGet(t, s, fmt.Sprintf("%s.%d", oidIfOperStatus, i)); got != "1" {
			t.Errorf("GET ifOperStatus.%d = %s, want 1", i, got)
		}
		if snap := state.Snapshot(i); snap.Oper != OperUp || snap.Admin != AdminUp {
			t.Errorf("slot %d = %+v, want up/up", i, snap)
		}
	}
}

// Table over the pure seed function, both JSON inputs.
func TestScenarioSeedTable(t *testing.T) {
	cases := []struct {
		scenario, pct, ifIndex int
		jsonOper, jsonAdmin    uint8
		wantLink, wantAdmin    uint8
	}{
		{IfScenarioAllNormal, 10, 1, OperUp, AdminUp, OperUp, AdminUp},
		{IfScenarioAllNormal, 10, 1, OperDown, AdminDown, OperDown, AdminDown},
		// Scenario 1 shuts the port and PRESERVES the link (nl6#694): admin
		// down forces oper down by derivation, so seeding the link down too
		// would model a severed cable instead of a shut port, and unshutting
		// would leave the interface dead.
		{IfScenarioAllShutdown, 10, 1, OperUp, AdminUp, OperUp, AdminDown},
		{IfScenarioAllShutdown, 10, 1, OperDown, AdminUp, OperDown, AdminDown},
		{IfScenarioAllFailure, 10, 1, OperUp, AdminUp, OperDown, AdminUp},
		{IfScenarioAllFailure, 10, 1, OperDown, AdminDown, OperDown, AdminUp},
		{IfScenarioPctFailure, 0, 1, OperUp, AdminUp, OperUp, AdminUp},
		{IfScenarioPctFailure, 30, 29, OperUp, AdminUp, OperDown, AdminUp},
		{IfScenarioPctFailure, 30, 30, OperUp, AdminUp, OperUp, AdminUp},
		{IfScenarioPctFailure, 30, 129, OperUp, AdminUp, OperDown, AdminUp},
		{IfScenarioPctFailure, 100, 7, OperUp, AdminUp, OperDown, AdminUp},
		{IfScenarioPctFailure, 30, 5, OperDown, AdminDown, OperDown, AdminUp},
		{9, 10, 1, OperUp, AdminUp, OperUp, AdminUp}, // unknown: identity (refused at startup anyway)
	}
	for _, c := range cases {
		cfg := &IfStateConfig{Scenario: c.scenario, FailurePct: c.pct}
		link, admin := scenarioSeed(cfg, c.ifIndex, c.jsonOper, c.jsonAdmin)
		if link != c.wantLink || admin != c.wantAdmin {
			t.Errorf("scenarioSeed(%d/%d, ifIndex %d, json %d/%d) = link %d/admin %d, want link %d/admin %d",
				c.scenario, c.pct, c.ifIndex, c.jsonOper, c.jsonAdmin, link, admin, c.wantLink, c.wantAdmin)
		}
	}
}

// Without an engine there is nothing to seed and no override to read: the
// static JSON row answers GET, exactly as it already answered a walk. Restoring
// the deleted read-time override fails this arm.
func TestIfScenarioWithoutEngineReadsTheStaticRow(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 10)
	s := newTestServer(map[string]string{oidIfAdminStatus + ".1": "1", oidIfOperStatus + ".1": "1"})
	if got := s.findResponse(oidIfOperStatus + ".1"); got != "1" {
		t.Errorf("no-engine GET ifOperStatus.1 = %q, want the static \"1\" (no read-time override)", got)
	}
	if got := s.findResponse(oidIfAdminStatus + ".1"); got != "1" {
		t.Errorf("no-engine GET ifAdminStatus.1 = %q, want \"1\"", got)
	}
}

// gNMI reads the same seeded engine.
func TestIfScenario3IsVisibleOnGnmiGet(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 10)
	device := newTestGnmiDevice(t, 2)
	srv := newGnmiServer(device, new(int64), new(uint64), new(uint64))
	srv.resolver = newPathResolver(device)
	get := func(leaf string) string {
		resp, err := srv.Get(context.Background(), &gnmipb.GetRequest{
			Path: []*gnmipb.Path{pathFromString(t, "/interfaces/interface[name=TestIf1]/state/"+leaf)},
		})
		if err != nil {
			t.Fatalf("gNMI Get %s: %v", leaf, err)
		}
		if len(resp.GetNotification()) != 1 || len(resp.GetNotification()[0].GetUpdate()) != 1 {
			t.Fatalf("gNMI Get %s returned %+v, want one update", leaf, resp)
		}
		return string(resp.GetNotification()[0].GetUpdate()[0].GetVal().GetJsonIetfVal())
	}
	if v := get("oper-status"); !strings.Contains(v, "DOWN") {
		t.Errorf("gNMI oper-status = %s, want DOWN", v)
	}
	if v := get("admin-status"); !strings.Contains(v, "UP") {
		t.Errorf("gNMI admin-status = %s, want UP", v)
	}
	state := device.metricsCycler.ifCounters.Load().State()
	if v := get("last-change"); !strings.Contains(v, fmt.Sprint(state.bootTimeUnixNs)) {
		t.Errorf("gNMI last-change = %s, want the boot epoch %d (no transition)", v, state.bootTimeUnixNs)
	}
}

// A REST oper-status POST under scenario 3 is read back by SNMP, and the
// other interface keeps its seed.
func TestRestMutationUnderScenario3IsReadBackBySNMP(t *testing.T) {
	withIfScenario(t, IfScenarioAllFailure, 10)
	f := newStateAPIFixture(t)
	ic := f.device.metricsCycler.ifCounters.Load()
	if got := ic.GetDynamic(oidIfOperStatus + ".1"); got != "2" {
		t.Fatalf("precondition: ifOperStatus.1 = %s, want 2", got)
	}
	// postInterfaceStatus fails the test unless the handler answers 202.
	postInterfaceStatus(t, f, "oper-status", 1, `{"status":"UP"}`)
	if got := ic.State().OperStatus(1); got != OperUp {
		t.Errorf("engine OperStatus(1) after REST UP = %d, want OperUp", got)
	}
	if got := ic.GetDynamic(oidIfOperStatus + ".1"); got != "1" {
		t.Errorf("SNMP ifOperStatus.1 after REST UP = %s, want 1", got)
	}
	if got := ic.GetDynamic(oidIfOperStatus + ".2"); got != "2" {
		t.Errorf("SNMP ifOperStatus.2 = %s, want 2 (untouched seed)", got)
	}
}

// The seed goes through Seed, not through the mutators, and THAT is what
// costs no ON_CHANGE event and no Tier C link trap or syslog.
//
// The observable difference is lastChange. Seed stores 0 and broadcasts
// nothing by construction; SetOperStatus / SetAdminStatus stamp the wall clock
// and return an event for the caller to broadcast. So a scenarioSeed routed
// through the mutators — the obvious-looking implementation, and the one that
// would fire link telemetry for every interface of every device at fleet
// start — leaves a non-zero lastChange behind and fails here.
//
// Asserting on a trap or syslog counter instead would NOT pin this: no
// exporter is attached at engine-construction time, so those counters read
// zero whatever the seed does. An earlier draft of this test did exactly that
// and asserted nothing at all.
func TestIfScenarioSeedStampsNoTransition(t *testing.T) {
	for _, sc := range []int{IfScenarioAllShutdown, IfScenarioAllFailure, IfScenarioPctFailure} {
		t.Run(fmt.Sprintf("scenario%d", sc), func(t *testing.T) {
			withIfScenario(t, sc, 100)
			_, state := newSetTestServer(t, 3)
			for i := 1; i <= 3; i++ {
				snap := state.Snapshot(i)
				if !snap.Found {
					t.Fatalf("ifIndex %d not seeded", i)
				}
				// Seed stored a relative 0, which LastChangeNs renders as
				// the boot epoch. A mutator would have stored `now`.
				if got := state.LastChangeNs(i); got != state.bootTimeUnixNs {
					t.Errorf("LastChangeNs(%d) = %d, want the boot epoch %d; the scenario was "+
						"applied through a mutator, which also broadcasts and would fire link "+
						"telemetry for the whole fleet at startup", i, got, state.bootTimeUnixNs)
				}
			}
		})
	}
}

// The validation has to be WIRED, and no unit test on validate() can see
// that: deleting the call from main leaves a correct function nothing invokes,
// which is the accepted-and-ignored shape one level up. Ordering matters too —
// after the -version early return, so `./nl6 -version` still works with a bad
// value — so the scan asserts position, not just presence.
func TestIfScenarioValidationIsWiredIntoStartupAfterVersion(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "simulator.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body []ast.Stmt
	for _, d := range file.Decls {
		if fn, ok := d.(*ast.FuncDecl); ok && fn.Name.Name == "main" && fn.Recv == nil {
			body = fn.Body.List
		}
	}
	if body == nil {
		t.Fatal("simulator.go declares no func main")
	}

	// Index of the `if *showVersion { ... return }` block and of the
	// statement containing a call to ifStateConfig.validate().
	versionAt, validateAt := -1, -1
	for i, stmt := range body {
		if ifs, ok := stmt.(*ast.IfStmt); ok && versionAt < 0 {
			if star, ok := ifs.Cond.(*ast.StarExpr); ok {
				if id, ok := star.X.(*ast.Ident); ok && id.Name == "showVersion" {
					versionAt = i
				}
			}
		}
		ast.Inspect(stmt, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "validate" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "ifStateConfig" && validateAt < 0 {
				validateAt = i
			}
			return true
		})
	}
	if validateAt < 0 {
		t.Fatal("main does not call ifStateConfig.validate(): an -if-scenario outside 1..4 would " +
			"be accepted and silently ignored, which is the defect nl6#692 closed one level down")
	}
	if versionAt < 0 {
		t.Fatal("main has no `if *showVersion` early-return block to order against")
	}
	if validateAt < versionAt {
		t.Errorf("ifStateConfig.validate() runs at statement %d, before the -version early return at %d; "+
			"`./nl6 -version` must still work when paired with a bad -if-scenario", validateAt, versionAt)
	}
}

// Startup validation: the flag is refused, not accepted and ignored.
func TestIfStateConfigValidate(t *testing.T) {
	good := []IfStateConfig{{1, 10}, {2, 10}, {3, 10}, {4, 0}, {4, 100}}
	for _, c := range good {
		if err := c.validate(); err != nil {
			t.Errorf("validate(%+v) = %v, want nil", c, err)
		}
	}
	bad := []struct {
		cfg  IfStateConfig
		want string
	}{
		{IfStateConfig{0, 10}, "-if-scenario"},
		{IfStateConfig{5, 10}, "-if-scenario"},
		{IfStateConfig{4, -1}, "-if-failure-pct"},
		{IfStateConfig{4, 101}, "-if-failure-pct"},
		{IfStateConfig{2, 101}, "-if-failure-pct"}, // out of range even when unused
	}
	for _, b := range bad {
		err := b.cfg.validate()
		if err == nil || !strings.Contains(err.Error(), b.want) {
			t.Errorf("validate(%+v) = %v, want an error naming %s", b.cfg, err, b.want)
		}
	}
}
