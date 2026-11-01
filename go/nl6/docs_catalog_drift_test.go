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

// flagRegistrars are the receiver.method pairs that register a flag. The name
// is the first string literal among the call's first two arguments, which
// covers flag.String(name, …), flag.StringVar(&p, name, …), flag.Var(v, name, …),
// flag.Func(name, …) and the fs.Var helper in flag_seconds_or_duration.go.
var flagRegistrars = map[string]bool{
	"flag.String": true, "flag.Bool": true, "flag.Int": true, "flag.Int64": true,
	"flag.Uint": true, "flag.Uint64": true, "flag.Float64": true, "flag.Duration": true,
	"flag.StringVar": true, "flag.BoolVar": true, "flag.IntVar": true, "flag.Int64Var": true,
	"flag.UintVar": true, "flag.Uint64Var": true, "flag.Float64Var": true, "flag.DurationVar": true,
	"flag.Var": true, "flag.Func": true, "flag.BoolFunc": true,
	"fs.Var": true,
}

// registeredFlags parses every non-test Go file of the package and returns the
// names of all flags registered through flagRegistrars.
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
			if !ok {
				return true
			}
			recv, ok := sel.X.(*ast.Ident)
			if !ok || !flagRegistrars[recv.Name+"."+sel.Sel.Name] {
				return true
			}
			for _, arg := range call.Args[:min(2, len(call.Args))] {
				if lit, ok := arg.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					name, err := strconv.Unquote(lit.Value)
					if err == nil {
						seen[name] = true
					}
					break
				}
			}
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
