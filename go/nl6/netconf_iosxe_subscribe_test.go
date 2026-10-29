/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import "testing"

func iosxeSubReq(stream, xpath, timing string) []byte {
	s := `<establish-subscription xmlns="urn:ietf:params:xml:ns:yang:ietf-event-notifications" xmlns:yp="urn:ietf:params:xml:ns:yang:ietf-yang-push">`
	if stream != "" {
		s += `<stream>` + stream + `</stream>`
	}
	s += `<yp:xpath-filter>` + xpath + `</yp:xpath-filter>` + timing + `</establish-subscription>`
	return []byte(s)
}

const (
	iosxeTestDamp0   = `<yp:dampening-period>0</yp:dampening-period>`
	iosxeTestIfaces  = "/interfaces-ios-xe-oper:interfaces"
	iosxeTestIfaceNm = iosxeTestIfaces + "/interface"
)

func TestNetconfParseEstablishSubscription(t *testing.T) {
	cases := []struct {
		name   string
		body   []byte
		sel    iosxeSelection
		result iosxeSubResult
		rpcErr *iosxeRPCError
	}{
		{"oper", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']/oper-status", iosxeTestDamp0), iosxeSelection{"X", iosxeLeafOper}, iosxeSubOK, nil},
		{"admin", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']/admin-status", iosxeTestDamp0), iosxeSelection{"X", iosxeLeafAdmin}, iosxeSubOK, nil},
		{"row", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']", iosxeTestDamp0), iosxeSelection{"X", iosxeLeafRow}, iosxeSubOK, nil},
		{"keyless oper", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"/oper-status", iosxeTestDamp0), iosxeSelection{"", iosxeLeafOper}, iosxeSubOK, nil},
		{"keyless admin", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"/admin-status", iosxeTestDamp0), iosxeSelection{"", iosxeLeafAdmin}, iosxeSubOK, nil},
		{"keyless row", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm, iosxeTestDamp0), iosxeSelection{"", iosxeLeafRow}, iosxeSubOK, nil},
		{"container", iosxeSubReq("yp:yang-push", iosxeTestIfaces, iosxeTestDamp0), iosxeSelection{}, iosxeSubNoSuchOption, nil},
		{"interfaces-state", iosxeSubReq("yp:yang-push", "/if:interfaces-state/interface/oper-status", iosxeTestDamp0), iosxeSelection{}, iosxeSubErrorOther, nil},
		{"interfaces-state container", iosxeSubReq("yp:yang-push", "/if:interfaces-state", iosxeTestDamp0), iosxeSelection{}, iosxeSubErrorOther, nil},
		{"nmda", iosxeSubReq("yp:yang-push", "/if:interfaces/interface/oper-status", iosxeTestDamp0), iosxeSelection{}, iosxeSubNoSuchOption, nil},
		{"unknown module", iosxeSubReq("yp:yang-push", "/nope-module:interfaces/interface/oper-status", iosxeTestDamp0), iosxeSelection{}, iosxeSubNoSuchOption, nil},
		{"malformed xpath", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X'/oper-status", iosxeTestDamp0), iosxeSelection{}, iosxeSubErrorOther, nil},
		{"missing stream", iosxeSubReq("", iosxeTestIfaceNm+"[name='X']", iosxeTestDamp0), iosxeSelection{}, iosxeSubNoSuchOption, nil},
		{"no timing", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']", ""), iosxeSelection{}, iosxeSubErrorOther, nil},
		{"dampening nonzero", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']", `<yp:dampening-period>500</yp:dampening-period>`), iosxeSelection{}, "", &iosxeRPCError{"protocol", "invalid-value", "dampening-period"}},
		{"periodic", iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name='X']", `<yp:period>1000</yp:period>`), iosxeSelection{}, iosxeSubNoSuchOption, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sel, result, rpcErr := parseEstablishSubscription(c.body)
			if result != c.result {
				t.Fatalf("result = %q, want %q", result, c.result)
			}
			if c.result == iosxeSubOK && sel != c.sel {
				t.Fatalf("sel = %+v, want %+v", sel, c.sel)
			}
			if (rpcErr == nil) != (c.rpcErr == nil) || (rpcErr != nil && *rpcErr != *c.rpcErr) {
				t.Fatalf("rpcErr = %+v, want %+v", rpcErr, c.rpcErr)
			}
		})
	}
}

func TestNetconfParseEstablishSubscriptionNameWithSlashAndQuotes(t *testing.T) {
	for _, q := range []string{`'GigabitEthernet1/0/24'`, `"Gi1/0/1"`} {
		body := iosxeSubReq("yp:yang-push", iosxeTestIfaceNm+"[name="+q+"]/oper-status", iosxeTestDamp0)
		sel, result, _ := parseEstablishSubscription(body)
		want := q[1 : len(q)-1]
		if result != iosxeSubOK || sel.IfName != want || sel.Leaves != iosxeLeafOper {
			t.Fatalf("%s: got %+v %q", q, sel, result)
		}
	}
}
