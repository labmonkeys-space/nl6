/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"testing"
	"time"
)

func TestOperTwins(t *testing.T) {
	t1 := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Second)
	at := func(n int) time.Time { return t1.Add(time.Duration(n) * time.Second) }
	admin := func(idx int, at time.Time) StateChange {
		return StateChange{IfIndex: idx, Changed: LeafAdminStatus, PrevOper: OperUp, Oper: OperDown, At: at}
	}
	oper := func(idx int, at time.Time) StateChange {
		return StateChange{IfIndex: idx, Changed: LeafOperStatus, PrevOper: OperUp, Oper: OperDown, At: at}
	}
	// An admin change over a link that is already down moves no oper-status.
	adminOnly := StateChange{IfIndex: 1, Changed: LeafAdminStatus, PrevOper: OperDown, Oper: OperDown, At: t1}

	cases := []struct {
		name    string
		evts    []StateChange
		want    []bool
		wantLen int // pending instants over all interfaces
	}{
		{"single pair", []StateChange{admin(1, t1), oper(1, t1)}, []bool{false, true}, 0},
		{"interleaved", []StateChange{admin(1, t1), admin(2, t1), oper(1, t1), oper(2, t1)}, []bool{false, false, true, true}, 0},
		{"twin consumed once", []StateChange{admin(1, t1), oper(1, t1), oper(1, t1)}, []bool{false, true, false}, 0},
		{"lost twin", []StateChange{admin(1, t1), oper(1, t2)}, []bool{false, false}, 1},
		{"lost twin then admin", []StateChange{admin(1, t1), oper(1, t2), admin(1, t2)}, []bool{false, false, false}, 2},
		{"oper without admin", []StateChange{oper(1, t1)}, []bool{false}, 0},
		{"admin only", []StateChange{adminOnly, oper(1, t1)}, []bool{false, false}, 0},
		{"re-armed", []StateChange{admin(1, t1), admin(1, t2), oper(1, t2)}, []bool{false, false, true}, 1},
		{"same interface interleaved", []StateChange{admin(1, t1), admin(1, t2), oper(1, t1), oper(1, t2)}, []bool{false, false, true, true}, 0},
		{"same interface, oper reversed", []StateChange{admin(1, t1), admin(1, t2), oper(1, t2), oper(1, t1)}, []bool{false, false, true, true}, 0},
		{"same instant twice", []StateChange{admin(1, t1), admin(1, t1), oper(1, t1), oper(1, t1)}, []bool{false, false, true, true}, 0},
		{"beyond the cap", []StateChange{admin(1, at(1)), admin(1, at(2)), admin(1, at(3)), admin(1, at(4)), admin(1, at(5)), oper(1, at(1)), oper(1, at(5)), oper(1, at(2))},
			[]bool{false, false, false, false, false, false, true, true}, 2},
		{"lost twins stay bounded", []StateChange{admin(1, at(1)), admin(1, at(2)), admin(1, at(3)), admin(1, at(4)), admin(1, at(5)), admin(1, at(6))},
			[]bool{false, false, false, false, false, false}, 4},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tw := operTwins{}
			for i, evt := range c.evts {
				if got := tw.twin(evt); got != c.want[i] {
					t.Errorf("event %d: twin = %v, want %v", i, got, c.want[i])
				}
			}
			pending := 0
			for idx, ats := range tw {
				if len(ats) == 0 {
					t.Errorf("interface %d holds an empty list", idx)
				}
				pending += len(ats)
			}
			if pending != c.wantLen {
				t.Errorf("instants left = %d, want %d", pending, c.wantLen)
			}
		})
	}
}
