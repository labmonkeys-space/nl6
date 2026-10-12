/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// notification is one message of gnmic --format json output.
type notification struct {
	Source  string   `json:"source"`
	Prefix  string   `json:"prefix"`
	Target  string   `json:"target"`
	Updates []update `json:"updates"`
}

type update struct {
	Path   string                     `json:"Path"`
	Values map[string]json.RawMessage `json:"values"`
}

// readCapture streams the notifications of a gnmic --format json capture.
// Text before the first '{' (gnmic echoes its command line) is skipped, and
// objects with neither prefix nor updates (sync-response) are dropped. A
// decode error names the byte offset only: the capture is non-public, so no
// error may quote it.
func readCapture(r io.Reader, fn func(notification) error) error {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if b == '{' {
			if err := br.UnreadByte(); err != nil {
				return err
			}
			break
		}
	}
	dec := json.NewDecoder(br)
	for {
		var n notification
		err := dec.Decode(&n)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("capture: malformed JSON near byte %d after the command echo", dec.InputOffset())
		}
		if n.Prefix == "" && len(n.Updates) == 0 {
			continue
		}
		if err := fn(n); err != nil {
			return err
		}
	}
}
