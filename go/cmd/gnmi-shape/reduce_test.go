/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestWildcardKeysAndOrigin(t *testing.T) {
	for _, c := range []struct{ in, origin, path string }{
		{"openconfig-platform:components/component[name=Rack 0]/state", "openconfig-platform", "/components/component[name=*]/state"},
		{"Cisco-IOS-XR-asr9k-np-oper:hardware-module-np/nodes/node[node-name=0/RP0/CPU0]/nps/np[np-name=np0]", "Cisco-IOS-XR-asr9k-np-oper", "/hardware-module-np/nodes/node[node-name=*]/nps/np[np-name=*]"},
		// A ':' inside a key is not an origin separator.
		{"components/component[name=FPC0:CPU]/state", "", "/components/component[name=*]/state"},
		{"a/b[eos=0][label-value=424242]/c", "", "/a/b[eos=*][label-value=*]/c"},
	} {
		o, p := splitOrigin(wildcardKeys(c.in))
		if o != c.origin || p != c.path {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.in, o, p, c.origin, c.path)
		}
	}
}

func TestReduceMatchesGolden(t *testing.T) {
	f, err := os.Open("testdata/fake-capture.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fx, err := reduceCapture(f, "fake", "0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	got, err := marshalFixture(fx)
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/fake-capture.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("reduce output differs from golden:\n%s", got)
	}
}

// The fixture must carry no value, key value or address from the capture.
func TestReduceCarriesNoCaptureContent(t *testing.T) {
	f, err := os.Open("testdata/fake-capture.log")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fx, err := reduceCapture(f, "fake", "0.0.0")
	if err != nil {
		t.Fatal(err)
	}
	out, _ := marshalFixture(fx)
	for _, secret := range []string{"Bundle-Ether77", "TenGigE0/0/0/3", "0/RP0/CPU0", "424242", "198.51.100.77", "192.0.2.10", "lab-r1", "99887766", "731"} {
		if bytes.Contains(out, []byte(secret)) {
			t.Errorf("fixture carries %q", secret)
		}
	}
}

func TestReduceClassMismatchNamesWildcardPath(t *testing.T) {
	in := `{"prefix":"x:a[k=v1]","updates":[{"Path":"b","values":{"b":1}}]}
{"prefix":"x:a[k=v2]","updates":[{"Path":"b","values":{"b":"s"}}]}`
	_, err := reduceCapture(strings.NewReader(in), "t", "0")
	if err == nil || !strings.Contains(err.Error(), "/a[k=*]/b") || strings.Contains(err.Error(), "v1") {
		t.Fatalf("got %v, want a class error naming /a[k=*]/b and no key value", err)
	}
}

func TestReduceIntegerAndFractionMergeToFraction(t *testing.T) {
	in := `{"prefix":"x:a","updates":[{"Path":"b","values":{"b":30}}]}
{"prefix":"x:a","updates":[{"Path":"b","values":{"b":30.5}}]}`
	fx, err := reduceCapture(strings.NewReader(in), "t", "0")
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Leaves) != 1 || fx.Leaves[0].Class != "fraction" || !fx.Leaves[0].Always {
		t.Fatalf("got %+v, want one always leaf of class fraction", fx.Leaves)
	}
}
