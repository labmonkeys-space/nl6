/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
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
	digits := minValueDigits
	if key {
		digits = minKeyDigits
	}
	// Each run is tokenised on its own, so a host name inside a sentence or
	// a shell prompt is a token, not only a value that is a name by itself.
	for _, run := range strings.FieldsFunc(strings.ToLower(v), func(r rune) bool { return !isRunByte(r) }) {
		for _, p := range pieces(run) {
			if hasLetter(p) && len(p) >= minWordToken || !hasLetter(p) && len(p) >= digits {
				set[p] = struct{}{}
			}
		}
		// The run, and each part of it between ':' or '/', so an address
		// held only as addr:port is a token by itself.
		for _, w := range append([]string{run}, strings.FieldsFunc(run, func(r rune) bool { return r == ':' || r == '/' })...) {
			if len(w) >= minWordToken && strings.ContainsAny(w, separators) && (hasLetter(w) || len(w) >= digits) {
				set[w] = struct{}{}
			}
		}
	}
}

// captureTokens adds the tokens of one capture file to set, including the
// text outside its JSON objects (the echoed command, a pasted prompt).
func captureTokens(r io.Reader, set tokenSet) error {
	return readCaptureText(r, func(n notification) error {
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
	}, func(text string) { set.addValue(text, false) })
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

// gitOut runs git in repo and returns stdout.
func gitOut(repo string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repo
	return cmd.Output()
}

// inBaseTree reports whether tok occurs anywhere in the tree at rev. A token
// already in the base was published before this change, so the change does
// not leak it. Results are cached; only hit candidates reach this.
func inBaseTree(repo, rev string) func(string) bool {
	cache := map[string]bool{}
	return func(tok string) bool {
		if v, ok := cache[tok]; ok {
			return v
		}
		err := exec.Command("git", "-C", repo, "grep", "-q", "-i", "-F", "-e", tok, rev, "--").Run()
		cache[tok] = err == nil
		return err == nil
	}
}

// fileLines reads a file as added lines.
func fileLines(path, name string) ([]addedLine, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []addedLine
	for i, t := range strings.Split(string(b), "\n") {
		out = append(out, addedLine{name, i + 1, t})
	}
	return out, nil
}

// changeLines returns the added lines of the working tree against the
// merge base of rev and HEAD, plus every line of every untracked file.
func changeLines(repo, rev string) (base string, lines []addedLine, err error) {
	mb, err := gitOut(repo, "merge-base", rev, "HEAD")
	if err != nil {
		return "", nil, fmt.Errorf("git merge-base %s HEAD failed", rev)
	}
	base = strings.TrimSpace(string(mb))
	diff, err := gitOut(repo, "diff", "--no-color", "--no-ext-diff", "--unified=0", base)
	if err != nil {
		return "", nil, fmt.Errorf("git diff failed")
	}
	if lines, err = parseUnifiedDiff(strings.NewReader(string(diff))); err != nil {
		return "", nil, err
	}
	untracked, err := gitOut(repo, "ls-files", "--others", "--exclude-standard", "-z")
	if err != nil {
		return "", nil, fmt.Errorf("git ls-files failed")
	}
	for _, name := range strings.Split(strings.TrimRight(string(untracked), "\x00"), "\x00") {
		if name == "" {
			continue
		}
		fl, err := fileLines(filepath.Join(repo, name), name)
		if err != nil {
			return "", nil, err
		}
		lines = append(lines, fl...)
	}
	return base, lines, nil
}

// selfTest plants one capture token in a line and requires scanLines to
// report it, so a broken check cannot report clean. The token is chosen
// deterministically and never printed.
func selfTest(set tokenSet, allowed func(string) bool) error {
	cands := make([]string, 0, len(set))
	for tok := range set {
		if hasLetter(tok) && len(tok) >= 6 && !allowed(tok) {
			cands = append(cands, tok)
		}
	}
	if len(cands) == 0 {
		return fmt.Errorf("self-test: the capture yielded no checkable token")
	}
	sort.Strings(cands)
	if len(scanLines([]addedLine{{"self-test", 1, "planted " + cands[0] + " here"}}, set, allowed)) != 1 {
		return fmt.Errorf("self-test: a planted capture token was not found")
	}
	return nil
}

// loadAllow reads an optional local allowlist: one lower-cased token per
// line, kept outside the repo next to the capture.
func loadAllow(path string) (map[string]bool, error) {
	allow := map[string]bool{}
	if path == "" {
		return allow, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	for _, l := range strings.Split(string(b), "\n") {
		if l = strings.ToLower(strings.TrimSpace(l)); l != "" && !strings.HasPrefix(l, "#") {
			allow[l] = true
		}
	}
	return allow, nil
}

func runLeak(args []string, stdout io.Writer) int {
	fs := flag.NewFlagSet("leak", flag.ContinueOnError)
	fs.SetOutput(stdout)
	capDir := fs.String("capture", "", "directory of gnmic captures (outside the repo)")
	repo := fs.String("repo", ".", "repository root")
	rev := fs.String("base", "origin/main", "branch the change merges into")
	allowPath := fs.String("allow", "", "optional local allowlist file, kept outside the repo")
	var files multiFlag
	fs.Var(&files, "file", "scan this file instead of the diff (repeatable), e.g. a PR body")
	if err := fs.Parse(args); err != nil || *capDir == "" {
		_, _ = fmt.Fprintln(stdout, "usage: gnmi-shape leak -capture DIR [-repo DIR] [-base REV] [-allow FILE] [-file F]...")
		return 2
	}
	set := tokenSet{}
	entries, err := os.ReadDir(*capDir)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "leak: cannot read capture directory: %v\n", err)
		return 2
	}
	for _, e := range entries {
		if !e.Type().IsRegular() || !(strings.HasSuffix(e.Name(), ".log") || strings.HasSuffix(e.Name(), ".json")) {
			continue
		}
		f, err := os.Open(filepath.Join(*capDir, e.Name()))
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "leak: %v\n", err)
			return 2
		}
		err = captureTokens(f, set)
		f.Close()
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "leak: %s: %v\n", e.Name(), err)
			return 2
		}
	}
	local, err := loadAllow(*allowPath)
	if err != nil {
		_, _ = fmt.Fprintf(stdout, "leak: allowlist: %v\n", err)
		return 2
	}
	var lines []addedLine
	base := func(string) bool { return false }
	if len(files) > 0 {
		// Words the repository already has are public; outside a git
		// repository there is no such filter.
		if _, err := gitOut(*repo, "rev-parse", "--verify", "-q", "HEAD"); err == nil {
			base = inBaseTree(*repo, "HEAD")
		}
		for _, p := range files {
			fl, err := fileLines(p, p)
			if err != nil {
				_, _ = fmt.Fprintf(stdout, "leak: %v\n", err)
				return 2
			}
			lines = append(lines, fl...)
		}
	} else {
		mb, cl, err := changeLines(*repo, *rev)
		if err != nil {
			_, _ = fmt.Fprintf(stdout, "leak: %v\n", err)
			return 2
		}
		lines, base = cl, inBaseTree(*repo, mb)
	}
	allowed := func(tok string) bool { return grammarAllowed(tok) || local[tok] || base(tok) }
	// The self-test must not consult the base tree: a token that is already
	// public cannot prove the scanner works.
	if err := selfTest(set, func(tok string) bool { return grammarAllowed(tok) || local[tok] }); err != nil {
		_, _ = fmt.Fprintf(stdout, "leak: %v; refusing to report a result\n", err)
		return 2
	}
	_, _ = fmt.Fprintf(stdout, "leak: self-test passed (%d capture tokens, %d lines scanned)\n", len(set), len(lines))
	hits := scanLines(lines, set, allowed)
	for _, h := range hits {
		_, _ = fmt.Fprintf(stdout, "%s:%d: capture-derived token (%d chars)\n", h.File, h.Line, h.Length)
	}
	if len(hits) > 0 {
		_, _ = fmt.Fprintf(stdout, "leak: %d line(s) carry a token from the non-public capture; rewrite them, or add a reviewed public token to the local allowlist\n", len(hits))
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "leak: clean")
	return 0
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
