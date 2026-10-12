/*
 * Copyright 2026 Ronny Trommer <ronny@no42.org>
 * SPDX-License-Identifier: Apache-2.0
 */

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "commit.gpgsign=false"}, args...)...)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func TestLeakCLIAgainstARepo(t *testing.T) {
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	// "uplink" is in the base tree, so it is public by the time this diff lands.
	if err := os.WriteFile(filepath.Join(repo, "base.txt"), []byte("uplink\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "base")
	if err := os.WriteFile(filepath.Join(repo, "base.txt"), []byte("uplink\nnext hop 198.51.100.77\nuplink again\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "new.txt"), []byte("ok\nBundle-Ether77 here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	capDir, _ := filepath.Abs("testdata")
	var out bytes.Buffer
	code := runLeak([]string{"-capture", capDir, "-repo", repo, "-base", "main"}, &out)
	if code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out.String())
	}
	o := out.String()
	if !strings.Contains(o, "base.txt:2:") || !strings.Contains(o, "new.txt:2:") || strings.Contains(o, "base.txt:3:") {
		t.Fatalf("want hits at base.txt:2 and new.txt:2, none at base.txt:3 (uplink is in the base tree):\n%s", o)
	}
	for _, secret := range []string{"198.51", "bundle", "ether77"} {
		if strings.Contains(strings.ToLower(o), secret) {
			t.Fatalf("output quotes a capture token:\n%s", o)
		}
	}
	// A clean tree exits 0 after a passing self-test.
	git(t, repo, "checkout", "-q", "--", "base.txt")
	os.Remove(filepath.Join(repo, "new.txt"))
	out.Reset()
	if code := runLeak([]string{"-capture", capDir, "-repo", repo, "-base", "main"}, &out); code != 0 {
		t.Fatalf("clean tree: exit %d\n%s", code, out.String())
	}
	if !strings.Contains(out.String(), "self-test passed") {
		t.Fatalf("clean result without a self-test:\n%s", out.String())
	}
}

func TestSelfTestRefusesEmptyTokenSet(t *testing.T) {
	if err := selfTest(tokenSet{}, func(string) bool { return false }); err == nil {
		t.Fatal("an empty token set passed the self-test")
	}
}

// -file mode drops words the repository already has, like the diff mode.
func TestLeakFileMode(t *testing.T) {
	repo := t.TempDir()
	git(t, repo, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(repo, "base.txt"), []byte("uplink\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	git(t, repo, "add", ".")
	git(t, repo, "commit", "-q", "-m", "base")
	body := filepath.Join(t.TempDir(), "pr-body.md")
	if err := os.WriteFile(body, []byte("The uplink is fine.\nFixed the counters on 198.51.100.77.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	capDir, _ := filepath.Abs("testdata")
	var out bytes.Buffer
	if code := runLeak([]string{"-capture", capDir, "-repo", repo, "-base", "main", "-file", body}, &out); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out.String())
	}
	if o := out.String(); !strings.Contains(o, "pr-body.md:2:") || strings.Contains(o, "pr-body.md:1:") {
		t.Fatalf("want a hit on line 2 only (uplink is in the repo):\n%s", o)
	}
}

// A capture with no checkable token leaves the self-test nothing to
// plant. runLeak must refuse rather than report clean.
func TestLeakRefusesWhenSelfTestCannotRun(t *testing.T) {
	dir := t.TempDir()
	capture := `{"a":"x"}`
	if err := os.WriteFile(filepath.Join(dir, "c.log"), []byte(capture), 0o644); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(t.TempDir(), "body.md")
	if err := os.WriteFile(body, []byte("nothing here\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	code := runLeak([]string{"-capture", dir, "-file", body}, &out)
	if code != 2 || strings.Contains(out.String(), "clean") {
		t.Fatalf("exit %d, want 2 and no clean verdict:\n%s", code, out.String())
	}
}

// A capture echoes its gnmic command line, which holds "--insecure". The
// scanner never forms a token that starts with a separator, so the set
// must not hold one; with "insecure" allowlisted the self-test planted
// "--insecure" and refused to run (nl6#809).
func TestLeakSelfTestPassesWithAllowlistedFlagWord(t *testing.T) {
	dir := t.TempDir()
	capture := "gnmic sub -a 192.0.2.1:57400 --insecure -e proto --path 'openconfig-system:/system/memory/state' --mode once\n" +
		`{"source": "192.0.2.1:57400", "prefix": "openconfig-system:system/memory/state", "updates": [{"Path": "physical", "values": {"physical": 8589934592}}]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.log"), []byte(capture), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := filepath.Join(t.TempDir(), "allow.txt")
	if err := os.WriteFile(allow, []byte("insecure\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := filepath.Join(t.TempDir(), "draft.md")
	if err := os.WriteFile(body, []byte("nothing to see\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := runLeak([]string{"-capture", dir, "-repo", t.TempDir(), "-allow", allow, "-file", body}, &out); code != 0 || !strings.Contains(out.String(), "leak: self-test passed") || !strings.Contains(out.String(), "leak: clean") {
		t.Fatalf("exit %d, want 0, a passed self-test and a clean verdict:\n%s", code, out.String())
	}
}

// A value can begin or end with a separator ("-r1.ams", "h1.lab:",
// "s2.par." at the end of a sentence). Its
// pieces are below the word floor, so only the value without its edge
// separators can catch a draft that repeats it (nl6#809).
func TestLeakFindsValuesWithEdgeSeparators(t *testing.T) {
	dir := t.TempDir()
	capture := "gnmic sub -a 192.0.2.1:57400 --insecure\n" +
		`{"source": "192.0.2.1:57400", "updates": [{"Path": "d", "values": {"d": "edge -r1.ams core h1.lab: up via s2.par."}}]}` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "fake.log"), []byte(capture), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, draft := range []string{"see r1.ams\n", "see h1.lab\n", "see s2.par\n"} {
		body := filepath.Join(t.TempDir(), "draft.md")
		if err := os.WriteFile(body, []byte(draft), 0o644); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		if code := runLeak([]string{"-capture", dir, "-repo", t.TempDir(), "-file", body}, &out); code != 1 {
			t.Errorf("draft %q: exit %d, want 1 (a leak):\n%s", draft, code, out.String())
		}
	}
}
