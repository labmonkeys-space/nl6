/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// leakRepo makes a repository whose main branch holds base.txt with the
// given content, checked out on a work branch.
func leakRepo(t *testing.T, base string) string {
	t.Helper()
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "base.txt"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "base")
	git(t, repo, "checkout", "-q", "-b", "work")
	return repo
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func leakExit(t *testing.T, args ...string) (int, string) {
	t.Helper()
	capDir, _ := filepath.Abs("testdata")
	var out bytes.Buffer
	code := runLeak(append([]string{"-capture", capDir}, args...), &out)
	return code, out.String()
}

// A token in an intermediate commit stays in the PR's history after a
// later commit removes it.
func TestLeakScansBranchHistory(t *testing.T) {
	repo := leakRepo(t, "ok\n")
	writeFile(t, filepath.Join(repo, "a.txt"), "Bundle-Ether77 here\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "leak")
	writeFile(t, filepath.Join(repo, "a.txt"), "fixed\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "fix")
	if code, out := leakExit(t, "-repo", repo, "-base", "main"); code != 1 {
		t.Fatalf("exit %d, want 1 for a token in branch history\n%s", code, out)
	}
}

// A staged token is what the next commit publishes, whatever the working
// tree says.
func TestLeakScansIndex(t *testing.T) {
	repo := leakRepo(t, "ok\n")
	writeFile(t, filepath.Join(repo, "s.txt"), "Bundle-Ether77 here\n")
	git(t, repo, "add", "s.txt")
	writeFile(t, filepath.Join(repo, "s.txt"), "nothing\n")
	if code, out := leakExit(t, "-repo", repo, "-base", "main"); code != 1 {
		t.Fatalf("exit %d, want 1 for a staged token\n%s", code, out)
	}
}

// A token is public only if the base has it as a whole word, not inside a
// longer one.
func TestLeakBaseFilterMatchesWholeWords(t *testing.T) {
	repo := leakRepo(t, "uplinks everywhere\n")
	writeFile(t, filepath.Join(repo, "n.txt"), "the uplink\n")
	if code, out := leakExit(t, "-repo", repo, "-base", "main"); code != 1 || !strings.Contains(out, "n.txt:1:") {
		t.Fatalf("exit %d, want a hit at n.txt:1 (base has only uplinks)\n%s", code, out)
	}
}

// Binary content and new file names are published too.
func TestLeakScansBinaryFilesAndNames(t *testing.T) {
	repo := leakRepo(t, "ok\n")
	writeFile(t, filepath.Join(repo, "bin.dat"), "x Bundle-Ether77 \x00\x01\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "bin")
	writeFile(t, filepath.Join(repo, "uplink-notes.txt"), "harmless\n")
	code, out := leakExit(t, "-repo", repo, "-base", "main")
	if code != 1 || !strings.Contains(out, "bin.dat:") || !strings.Contains(out, "uplink-notes.txt:0:") {
		t.Fatalf("exit %d, want hits in bin.dat and on the name uplink-notes.txt\n%s", code, out)
	}
}

// -file mode must not treat a token the branch itself added as public.
func TestLeakFileModeFiltersAgainstMergeBase(t *testing.T) {
	repo := leakRepo(t, "ok\n")
	writeFile(t, filepath.Join(repo, "a.txt"), "Bundle-Ether77\n")
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "leak")
	body := filepath.Join(t.TempDir(), "body.md")
	writeFile(t, body, "Renamed Bundle-Ether77.\n")
	if code, out := leakExit(t, "-repo", repo, "-base", "main", "-file", body); code != 1 {
		t.Fatalf("exit %d, want 1: the branch added the token, the base does not have it\n%s", code, out)
	}
}

// Container values (json_ietf), deletes and error objects carry tokens.
func TestCaptureTokensWalkEveryJSONValue(t *testing.T) {
	in := `{"prefix":"x:a","updates":[{"Path":"c","values":{"c":{"description":"zenithcorp uplink","peers":["zenpeer9"]}}}]}
{"prefix":"x:a","deletes":["b[name=zenhost77]/c"]}
{"error":"rpc failed: target zenithhost01 unreachable"}`
	set := tokenSet{}
	if err := captureTokens(strings.NewReader(in), set); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"zenithcorp", "zenpeer9", "zenhost77", "zenithhost01"} {
		if _, ok := set[want]; !ok {
			t.Errorf("token %q missing", want)
		}
	}
}

// An escaped ']' inside a key value wildcards whole; an unescaped one is
// refused without quoting the path.
func TestReduceKeyValuesWithBrackets(t *testing.T) {
	fx, err := reduceCapture(strings.NewReader(`{"prefix":"x:a/b[name=zen\\]ithsecret]/c","updates":[{"Path":"d","values":{"d":1}}]}`), "t", "0")
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Prefixes) != 1 || fx.Prefixes[0] != "x:/a/b[name=*]/c" {
		t.Fatalf("prefixes %v, want x:/a/b[name=*]/c", fx.Prefixes)
	}
	_, err = reduceCapture(strings.NewReader(`{"prefix":"x:a/b[desc=x [secretword] y]/c","updates":[{"Path":"d","values":{"d":1}}]}`), "t", "0")
	if err == nil || strings.Contains(err.Error(), "secretword") || strings.Contains(err.Error(), " y]") {
		t.Fatalf("got %v, want a refusal that quotes nothing", err)
	}
}

// Every regular file under the capture directory is read, whatever its
// name, so a capture saved as .txt or in a subdirectory is not skipped.
func TestLeakReadsEveryCaptureFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "a.log"), `{"prefix":"x:a[name=Bundle-Ether55]","updates":[{"Path":"b","values":{"b":1}}]}`)
	writeFile(t, filepath.Join(dir, "sub", "b.txt"), `{"prefix":"x:a[name=zenithcorp-edge]","updates":[{"Path":"b","values":{"b":1}}]}`)
	body := filepath.Join(t.TempDir(), "body.md")
	writeFile(t, body, "about zenithcorp-edge\n")
	var out bytes.Buffer
	if code := runLeak([]string{"-capture", dir, "-file", body}, &out); code != 1 {
		t.Fatalf("exit %d, want 1: the token is in sub/b.txt\n%s", code, out.String())
	}
}

// YANG schema in paths and object keys is public; only key values inside
// a path are capture data.
func TestCaptureTokensSkipSchemaInPaths(t *testing.T) {
	in := `{"prefix":"openconfig-interfaces:interfaces/interface[name=zenedge4]/state","updates":[{"Path":"counters/in-unicast-pkts","values":{"counters/in-unicast-pkts":1}}]}`
	set := tokenSet{}
	if err := captureTokens(strings.NewReader(in), set); err != nil {
		t.Fatal(err)
	}
	if _, ok := set["zenedge4"]; !ok {
		t.Error("key value zenedge4 missing")
	}
	for _, schema := range []string{"openconfig-interfaces", "interfaces", "counters", "in-unicast-pkts", "prefix", "updates"} {
		if _, ok := set[schema]; ok {
			t.Errorf("schema word %q is a token", schema)
		}
	}
}
