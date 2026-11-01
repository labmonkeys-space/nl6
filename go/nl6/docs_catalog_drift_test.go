/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// These tests keep the two reference catalogs operators build against in step
// with the code: the flag table in docs/reference/cli-flags.md and the
// endpoint catalog in docs/reference/web-api.md. Both report drift in both
// directions, so a removed flag or route left in the docs fails as loudly as
// a new one left out.

const (
	cliFlagsDoc = "../../docs/reference/cli-flags.md"
	webAPIDoc   = "../../docs/reference/web-api.md"
)

// flagNameArg maps each flag-registering method to the index of its name
// argument: flag.String(name, …) and flag.Func(name, …) take it first, the
// *Var forms (flag.StringVar(&p, name, …), flag.Var(v, name, …)) second.
var flagNameArg = map[string]int{
	"String": 0, "Bool": 0, "Int": 0, "Int64": 0, "Uint": 0, "Uint64": 0,
	"Float64": 0, "Duration": 0, "Func": 0, "BoolFunc": 0,
	"StringVar": 1, "BoolVar": 1, "IntVar": 1, "Int64Var": 1, "UintVar": 1,
	"Uint64Var": 1, "Float64Var": 1, "DurationVar": 1, "Var": 1,
}

// flagReceiver reports whether expr is a flag set the simulator registers
// flags on: the flag package itself, flag.CommandLine, or the fs FlagSet
// parameter used by the helpers in flag_seconds_or_duration.go. A new FlagSet
// under another name is not seen; the len(registered) floor in the test
// catches a wholesale miss.
func flagReceiver(expr ast.Expr) bool {
	switch x := expr.(type) {
	case *ast.Ident:
		return x.Name == "flag" || x.Name == "fs"
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && id.Name == "flag" && x.Sel.Name == "CommandLine"
	}
	return false
}

// registeredFlags parses every non-test Go file of the package and returns the
// names of all registered flags. A registration whose name is not a string
// literal fails the test, because its name cannot be checked against the docs.
func registeredFlags(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	fset := token.NewFileSet()
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !flagReceiver(sel.X) {
				return true
			}
			idx, ok := flagNameArg[sel.Sel.Name]
			if !ok || idx >= len(call.Args) {
				return true
			}
			lit, ok := call.Args[idx].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: flag registered with a non-literal name; the docs check cannot read it", fset.Position(call.Pos()))
				return true
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Errorf("%s: unquote flag name: %v", fset.Position(lit.Pos()), err)
				return true
			}
			seen[name] = true
			return true
		})
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// flagRow matches a table row whose first cell is a backticked flag. Prose
// mentions do not match, so the page can still name a flag that does not
// exist, for example to say it is absent on purpose.
var flagRow = regexp.MustCompile("(?m)^\\| `-([a-z0-9][a-z0-9-]*)`")

func TestCLIFlagsDocMatchesRegisteredFlags(t *testing.T) {
	body, err := os.ReadFile(cliFlagsDoc)
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range flagRow.FindAllStringSubmatch(string(body), -1) {
		documented[m[1]] = true
	}
	registered := registeredFlags(t)
	if len(registered) < 50 {
		t.Fatalf("found only %d flag registrations; the parser no longer recognises how flags are registered", len(registered))
	}
	var missing, stale []string
	for _, name := range registered {
		if !documented[name] {
			missing = append(missing, "-"+name)
		}
	}
	for name := range documented {
		if !slices.Contains(registered, name) {
			stale = append(stale, "-"+name)
		}
	}
	slices.Sort(stale)
	if len(missing) > 0 {
		t.Errorf("flags registered in code with no row in docs/reference/cli-flags.md: %s", strings.Join(missing, ", "))
	}
	if len(stale) > 0 {
		t.Errorf("flag rows in docs/reference/cli-flags.md with no registration in code: %s", strings.Join(stale, ", "))
	}
}

// prefixMounts are mounted with PathPrefix and carry no method, so the router
// walk cannot pair them with a catalog row. The catalog documents them as
// `/web/*` and `/debug/pprof/`; both rows are skipped on the docs side too.
var prefixMounts = []string{"/web/*", "/debug/pprof/"}

// catalogRow matches one row of the endpoint catalog: the backticked paths of
// the first cell and the method of the second.
var catalogRow = regexp.MustCompile("(?m)^\\| (`/[^|]*?) \\| ([A-Z]+) \\|")
var backticked = regexp.MustCompile("`([^`]+)`")

func TestWebAPICatalogMatchesRouter(t *testing.T) {
	body, err := os.ReadFile(webAPIDoc)
	if err != nil {
		t.Fatal(err)
	}
	documented := map[string]bool{}
	for _, m := range catalogRow.FindAllStringSubmatch(string(body), -1) {
		for _, p := range backticked.FindAllStringSubmatch(m[1], -1) {
			if slices.Contains(prefixMounts, p[1]) {
				continue
			}
			documented[m[2]+" "+p[1]] = true
		}
	}

	routed := map[string]bool{}
	err = setupRoutes().Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		path, err := route.GetPathTemplate()
		if err != nil {
			return nil
		}
		methods, err := route.GetMethods()
		if err != nil {
			return nil // a PathPrefix mount or redirect, see prefixMounts
		}
		for _, m := range methods {
			routed[m+" "+path] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(routed) < 30 {
		t.Fatalf("router walk found only %d routes; the walk no longer sees the API", len(routed))
	}

	var missing, stale []string
	for r := range routed {
		if !documented[r] {
			missing = append(missing, r)
		}
	}
	for d := range documented {
		if !routed[d] {
			stale = append(stale, d)
		}
	}
	slices.Sort(missing)
	slices.Sort(stale)
	if len(missing) > 0 {
		t.Errorf("routes registered in setupRoutes with no row in the docs/reference/web-api.md catalog: %s", strings.Join(missing, "; "))
	}
	if len(stale) > 0 {
		t.Errorf("catalog rows in docs/reference/web-api.md with no route in setupRoutes: %s", strings.Join(stale, "; "))
	}
}
