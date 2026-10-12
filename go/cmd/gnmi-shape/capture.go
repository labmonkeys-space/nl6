/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	"bytes"
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
// Objects with neither prefix nor updates (sync-response) are dropped. An
// error names a byte offset only: the capture is non-public, so no error may
// quote it.
func readCapture(r io.Reader, fn func(notification) error) error {
	return readCaptureText(r, fn, nil)
}

// readCaptureText is readCapture that also hands every run of text outside
// the JSON objects to onText: gnmic's command echo, and a shell prompt pasted
// after the last object, which carries the host name. Objects are found by
// brace depth outside strings rather than by a JSON decoder, because a
// decoder cannot skip text between objects.
func readCaptureText(r io.Reader, fn func(notification) error, onText func(string)) error {
	br := bufio.NewReaderSize(r, 1<<20)
	var obj, text []byte
	depth, inStr, esc := 0, false, false
	var off, start int64
	flushText := func() {
		if onText != nil && len(bytes.TrimSpace(text)) > 0 {
			onText(string(text))
		}
		text = text[:0]
	}
	for {
		b, err := br.ReadByte()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		off++
		if depth == 0 {
			if b != '{' {
				text = append(text, b)
				continue
			}
			flushText()
			start = off - 1
		}
		if inStr && !esc && (b == '\r' || b == '\n') {
			// A terminal's hard wrap; JSON allows no raw line break here.
			continue
		}
		obj = append(obj, b)
		switch {
		case esc:
			esc = false
		case inStr && b == '\\':
			esc = true
		case inStr && b == '"':
			inStr = false
		case inStr:
		case b == '"':
			inStr = true
		case b == '{', b == '[':
			depth++
		case b == '}', b == ']':
			depth--
		}
		if depth > 0 {
			continue
		}
		var n notification
		if err := json.Unmarshal(obj, &n); err != nil {
			return fmt.Errorf("capture: malformed JSON object at byte %d", start)
		}
		obj = obj[:0]
		if n.Prefix == "" && len(n.Updates) == 0 {
			continue
		}
		if err := fn(n); err != nil {
			return err
		}
	}
	if depth != 0 {
		return fmt.Errorf("capture: truncated JSON object at byte %d", start)
	}
	flushText()
	return nil
}
