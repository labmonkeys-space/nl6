/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"encoding/json"
	"math"
	"math/rand"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	gnmipb "github.com/openconfig/gnmi/proto/gnmi"
)

// fractionDigits counts the digits after the decimal point in the
// shortest decimal that round-trips v, which is what a client prints.
func fractionDigits(v float64) int {
	s := strconv.FormatFloat(v, 'f', -1, 64)
	if i := strings.IndexByte(s, '.'); i >= 0 {
		return len(s) - i - 1
	}
	return 0
}

// TestCatalogDecimal64ServedAtDeclaredDigits resolves every subtree of
// every embedded catalogue that declares a decimal64 leaf, at fixed
// instants spread over the generators' periods, and requires every
// decimal64 value to carry at most its catalogue digits in every PROTO
// form and in JSON_IETF, with the forms agreeing (nl6#812: double_val
// carried ~15 fraction digits).
func TestCatalogDecimal64ServedAtDeclaredDigits(t *testing.T) {
	cats, err := loadEmbeddedGnmiCatalogs()
	if err != nil {
		t.Fatal(err)
	}
	types := make([]string, 0, len(cats))
	for typ := range cats {
		types = append(types, typ)
	}
	sort.Strings(types)
	tested := map[string]bool{}
	for _, typ := range types {
		cat := cats[typ]
		// subtree path -> leaf name -> digits, so same-named leaves of
		// different subtrees cannot borrow each other's digits.
		declared := map[string]map[string]int{}
		var subtrees []*gnmiCatalogSubtree
		for _, st := range cat.Subtrees {
			for _, l := range st.Leaves {
				if l.Type != "decimal64" {
					continue
				}
				if declared[st.Path] == nil {
					declared[st.Path] = map[string]int{}
					subtrees = append(subtrees, st)
				}
				declared[st.Path][l.Name] = l.Digits
			}
		}
		if len(subtrees) == 0 {
			continue
		}
		tested[typ] = true
		t.Run(typ, func(t *testing.T) {
			r := newCatalogResolver(newTestGnmiDevice(t, 4), cat)
			seen := map[string]bool{}
			base := time.Unix(1_800_000_000, 0)
			for step := 0; step < 37; step++ {
				now := base.Add(time.Duration(step*25+7) * time.Second)
				for _, st := range subtrees {
					notifs, err := r.resolveSubtrees(&gnmipb.Path{}, st.Origin, nil, false, []*gnmiCatalogSubtree{st}, now, nil)
					if err != nil {
						t.Fatalf("%s: %v", st.Path, err)
					}
					for _, n := range notifs {
						for _, u := range n.Updates {
							d, ok := u.Value.(gnmiDecimal)
							if !ok {
								continue
							}
							path := pathToString(u.Path)
							// The longest declared leaf name the path ends
							// with is the leaf that rendered it.
							name := ""
							for leaf := range declared[st.Path] {
								if (path == "/"+leaf || strings.HasSuffix(path, "/"+leaf)) && len(leaf) > len(name) {
									name = leaf
								}
							}
							if name == "" {
								t.Fatalf("%s: decimal at %s matches no declared decimal64 leaf", st.Path, path)
							}
							seen[st.Path+" "+name] = true
							if want := declared[st.Path][name]; d.digits != want {
								t.Fatalf("%s: cast digits %d, catalogue %d", path, d.digits, want)
							}
							checkDecimalForms(t, path, d)
						}
					}
				}
			}
			for st, leaves := range declared {
				for leaf := range leaves {
					if !seen[st+" "+leaf] {
						t.Errorf("decimal64 leaf %s %s was never served", st, leaf)
					}
				}
			}
		})
	}
	for _, typ := range []string{"cisco_asr9902", "juniper_mx10004"} {
		if !tested[typ] {
			t.Errorf("%s declares no decimal64 leaf; the test no longer covers it", typ)
		}
	}
}

// TestGnmiDecimalFormsAgree: JSON_IETF, PROTO double_val and PROTO
// decimal_val derive from one rounding, so they agree at every digits
// the YANG type allows, including 14..18 where a float64 multiply by
// 10^digits rounds differently from the decimal formatter.
func TestGnmiDecimalFormsAgree(t *testing.T) {
	rng := rand.New(rand.NewSource(812))
	for digits := 1; digits <= 18; digits++ {
		for i := 0; i < 2000; i++ {
			// |v| < 9 keeps the 18-digit value inside int64 units.
			v := (rng.Float64()*18 - 9) * math.Pow10(-rng.Intn(6))
			checkDecimalForms(t, strconv.FormatFloat(v, 'g', -1, 64), newGnmiDecimal(v, digits))
		}
	}
	// The value the review sampled.
	checkDecimalForms(t, "0.000599960161935", newGnmiDecimal(0.000599960161935, 14))
}

// TestGnmiDecimalRoundedZeroIsPositive: a negative value that rounds
// to zero is served as +0 in every form, never "-0.0" or a signed
// double next to a sign-less decimal_val.
func TestGnmiDecimalRoundedZeroIsPositive(t *testing.T) {
	for _, v := range []float64{-0.04, math.Copysign(0, -1), -0.00049} {
		d := newGnmiDecimal(v, 1)
		ietf, err := gnmiEncodeTypedValue(d, gnmipb.Encoding_JSON_IETF)
		if err != nil {
			t.Fatal(err)
		}
		if got := string(ietf.GetJsonIetfVal()); got != `"0.0"` {
			t.Errorf("%v: JSON_IETF %s, want \"0.0\"", v, got)
		}
		pb, err := gnmiEncodeTypedValue(d, gnmipb.Encoding_PROTO)
		if err != nil {
			t.Fatal(err)
		}
		if got := pb.GetDoubleVal(); got != 0 || math.Signbit(got) {
			t.Errorf("%v: double_val %v (signbit %v), want +0", v, got, math.Signbit(got))
		}
		checkDecimalForms(t, strconv.FormatFloat(v, 'g', -1, 64), d)
	}
}

// TestCastDecimal64RejectsUnrepresentable: NaN and infinities are not
// decimal64 values, and neither is a value whose scaled integer does
// not fit int64. A catalogue can produce them (const:NaN, sine:Inf,...
// both parse), so the cast refuses them and the resolver skips the leaf.
func TestCastDecimal64RejectsUnrepresentable(t *testing.T) {
	for _, c := range []struct {
		in     any
		digits int
	}{
		{"NaN", 1}, {"Inf", 1}, {"-Inf", 1}, {math.NaN(), 2}, {math.Inf(1), 2},
		{float64(10), 18}, {float64(-1e17), 2},
	} {
		if got, err := castGnmiLeafDigits(c.in, "decimal64", c.digits); err == nil {
			t.Errorf("cast(%v, digits %d) = %v, want an error", c.in, c.digits, got)
		}
	}
	if _, err := castGnmiLeafDigits(float64(9), "decimal64", 18); err != nil {
		t.Errorf("9 at 18 digits fits decimal64: %v", err)
	}
}

// checkDecimalForms encodes d as JSON_IETF, PROTO double_val and PROTO
// decimal_val, and requires at most d.digits fraction digits in each,
// one reading across them, and no negative zero.
func checkDecimalForms(t *testing.T, what string, d gnmiDecimal) {
	t.Helper()
	ietf, err := gnmiEncodeTypedValue(d, gnmipb.Encoding_JSON_IETF)
	if err != nil {
		t.Fatal(err)
	}
	var s string
	if err := json.Unmarshal(ietf.GetJsonIetfVal(), &s); err != nil {
		t.Fatalf("%s: JSON_IETF %s is not an RFC 7951 string: %v", what, ietf.GetJsonIetfVal(), err)
	}
	intPart, frac, _ := strings.Cut(s, ".")
	if len(frac) > d.digits {
		t.Fatalf("%s: JSON_IETF %q has %d fraction digits, want at most %d", what, s, len(frac), d.digits)
	}
	want, err := strconv.ParseFloat(s, 64)
	if err != nil {
		t.Fatal(err)
	}
	if want == 0 && strings.HasPrefix(s, "-") {
		t.Fatalf("%s: JSON_IETF %q is a negative zero", what, s)
	}
	wantUnits, err := strconv.ParseInt(intPart+frac+strings.Repeat("0", d.digits-len(frac)), 10, 64)
	if err != nil {
		t.Fatal(err)
	}

	d.decimalVal = false
	tv, err := gnmiEncodeTypedValue(d, gnmipb.Encoding_PROTO)
	if err != nil {
		t.Fatal(err)
	}
	got := tv.GetDoubleVal()
	if n := fractionDigits(got); n > d.digits {
		t.Fatalf("%s: double_val %v has %d fraction digits, want at most %d", what, got, n, d.digits)
	}
	if got != want || math.Signbit(got) != math.Signbit(want) {
		t.Fatalf("%s: double_val %v, JSON_IETF %q", what, got, s)
	}

	d.decimalVal = true
	tv, err = gnmiEncodeTypedValue(d, gnmipb.Encoding_PROTO)
	if err != nil {
		t.Fatal(err)
	}
	dv := tv.GetDecimalVal() //nolint:staticcheck // gNMI deprecates Decimal64; Junos still sends it (nl6#772)

	if dv == nil || int(dv.GetPrecision()) != d.digits || dv.GetDigits() != wantUnits { //nolint:staticcheck // as above
		t.Fatalf("%s: decimal_val %v, JSON_IETF %q (want digits %d precision %d)", what, dv, s, wantUnits, d.digits)
	}
}
