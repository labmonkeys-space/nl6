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
	if code := runLeak([]string{"-capture", capDir, "-repo", repo, "-file", body}, &out); code != 1 {
		t.Fatalf("exit %d, want 1\n%s", code, out.String())
	}
	if o := out.String(); !strings.Contains(o, "pr-body.md:2:") || strings.Contains(o, "pr-body.md:1:") {
		t.Fatalf("want a hit on line 2 only (uplink is in the repo):\n%s", o)
	}
}

// A capture whose only tokens are public grammar leaves the self-test
// nothing to plant. runLeak must refuse rather than report clean.
func TestLeakRefusesWhenSelfTestCannotRun(t *testing.T) {
	dir := t.TempDir()
	capture := `{"prefix":"openconfig-interfaces:interfaces/interface[name=TenGigE0/0/0/1]/state","updates":[{"Path":"oper-status","values":{"oper-status":"UP"}}]}`
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
