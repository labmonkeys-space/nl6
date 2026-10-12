/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// tokenSet holds lower-cased tokens taken from a non-public capture. It is
// never printed.
type tokenSet map[string]struct{}

const (
	minWordToken   = 4  // a token that has a letter
	minValueDigits = 6  // an all-digit token from a value
	minKeyDigits   = 4  // an all-digit token from a key value
	maxWindow      = 16 // pieces per diff lookup
	separators     = "._:/+-"
)

func isAlnum(r rune) bool { return r >= 'a' && r <= 'z' || r >= '0' && r <= '9' }

func hasLetter(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r >= 'a' && r <= 'z' }) >= 0
}

func pieces(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return !isAlnum(r) })
}

func (set tokenSet) addValue(v string, key bool) {
	v = strings.ToLower(strings.TrimSpace(v))
	digits := minValueDigits
	if key {
		digits = minKeyDigits
	}
	for _, p := range pieces(v) {
		if hasLetter(p) && len(p) >= minWordToken || !hasLetter(p) && len(p) >= digits {
			set[p] = struct{}{}
		}
	}
	if len(v) >= minWordToken && !strings.ContainsAny(v, " \t\r\n") && strings.ContainsAny(v, separators) &&
		(hasLetter(v) || len(v) >= digits) {
		set[v] = struct{}{}
	}
}

// captureTokens adds the tokens of one capture file to set.
func captureTokens(r io.Reader, set tokenSet) error {
	return readCapture(r, func(n notification) error {
		set.addValue(n.Source, false)
		set.addValue(n.Target, false)
		paths := []string{n.Prefix}
		for _, u := range n.Updates {
			paths = append(paths, u.Path)
			for _, raw := range u.Values {
				var s string
				switch valueClass(raw) {
				case "string":
					if err := json.Unmarshal(raw, &s); err != nil {
						return fmt.Errorf("capture: undecodable string value")
					}
				case "integer", "fraction":
					s = string(raw)
				default:
					continue
				}
				set.addValue(s, false)
			}
		}
		for _, p := range paths {
			for _, m := range keyRe.FindAllStringSubmatch(p, -1) {
				set.addValue(m[2], true)
			}
		}
		return nil
	})
}

// addedLine is one added line of a diff, or one line of a scanned file.
type addedLine struct {
	File string
	Line int
	Text string
}

var hunkRe = regexp.MustCompile(`^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@`)

// parseUnifiedDiff returns the added lines of a `git diff` with their
// new-file line numbers.
func parseUnifiedDiff(r io.Reader) ([]addedLine, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	var out []addedLine
	file, line := "", 0
	// header is true between a "diff " line and the first hunk, so an added
	// line whose content starts with "++ " is not read as a file header.
	header := false
	for sc.Scan() {
		t := sc.Text()
		switch {
		case strings.HasPrefix(t, "diff "):
			header = true
		case header && strings.HasPrefix(t, "+++ "):
			file = strings.TrimPrefix(strings.TrimPrefix(t, "+++ "), "b/")
		case strings.HasPrefix(t, "@@"):
			header = false
			m := hunkRe.FindStringSubmatch(t)
			if m == nil {
				return nil, fmt.Errorf("diff: unparsable hunk header")
			}
			line, _ = strconv.Atoi(m[1])
		case header, strings.HasPrefix(t, `\`):
			// ---, index and mode lines; "\ No newline at end of file".
		case strings.HasPrefix(t, "+"):
			out = append(out, addedLine{file, line, t[1:]})
			line++
		case strings.HasPrefix(t, " "):
			line++
		}
	}
	return out, sc.Err()
}

// hit reports where a capture token was found, never the token itself.
type hit struct {
	File   string
	Line   int
	Length int
}

func isRunByte(r rune) bool { return isAlnum(r) || strings.ContainsRune(separators, r) }

// scanLines looks up every window of up to maxWindow pieces of every run of
// every line. allowed drops grammar, base-tree and locally allowed tokens.
// One line reports at most one hit, the longest token.
func scanLines(lines []addedLine, set tokenSet, allowed func(string) bool) []hit {
	var hits []hit
	for _, l := range lines {
		best := 0
		for _, run := range strings.FieldsFunc(strings.ToLower(l.Text), func(r rune) bool { return !isRunByte(r) }) {
			// Piece boundaries inside the run, as byte offsets.
			var starts, ends []int
			in := false
			for i, r := range run {
				if isAlnum(r) && !in {
					starts, in = append(starts, i), true
				} else if !isAlnum(r) && in {
					ends, in = append(ends, i), false
				}
			}
			if in {
				ends = append(ends, len(run))
			}
			for i := range starts {
				for j := i; j < len(ends) && j < i+maxWindow; j++ {
					tok := run[starts[i]:ends[j]]
					if _, ok := set[tok]; ok && len(tok) > best && !allowed(tok) {
						best = len(tok)
					}
				}
			}
		}
		if best > 0 {
			hits = append(hits, hit{l.File, l.Line, best})
		}
	}
	return hits
}

//go:embed grammar-allow.txt
var grammarAllowText string

var grammarAllowRes = func() []*regexp.Regexp {
	var res []*regexp.Regexp
	for _, l := range strings.Split(grammarAllowText, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			res = append(res, regexp.MustCompile("(?i)"+l))
		}
	}
	return res
}()

func grammarAllowed(tok string) bool {
	for _, re := range grammarAllowRes {
		if re.MatchString(tok) {
			return true
		}
	}
	return false
}
