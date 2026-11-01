package main

import (
	"bytes"
	"encoding/json"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/sys"
)

func TestParseOptionsAnywhere(t *testing.T) {
	o, err := parse([]string{"why", "--json", "disk", "/var", "--timeout=30s", "-vq"})
	if err != nil {
		t.Fatal(err)
	}
	if o.format != "json" || !o.verbose || !o.quiet || o.timeout != 30*time.Second {
		t.Fatalf("options: %+v", o)
	}
	if strings.Join(o.args, " ") != "why disk /var" {
		t.Fatalf("args: %v", o.args)
	}
	o, err = parse([]string{"--since", "3d", "changes", "--", "--json"})
	if err != nil || o.since != "3d" || strings.Join(o.args, " ") != "changes --json" {
		t.Fatalf("-- ends the options: %+v %v", o, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string][]string{
		"choose one output":   {"--json", "--md"},
		"did you mean --json": {"--jsno"},
		"needs a value":       {"--only"},
		"--color wants":       {"--color", "rainbow"},
		"--keep wants":        {"snapshot", "--keep", "0"},
		"--timeout wants":     {"--timeout", "soon"},
	}
	for want, argv := range cases {
		if _, err := parse(argv); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: want an error with %q, got %v", argv, want, err)
		}
	}
}

func TestParseSince(t *testing.T) {
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.Local)
	boot := now.Add(-5 * time.Hour)
	cases := map[string]time.Time{
		"":           now.Add(-24 * time.Hour),
		"2h":         now.Add(-2 * time.Hour),
		"3d":         now.Add(-72 * time.Hour),
		"1w":         now.Add(-7 * 24 * time.Hour),
		"boot":       boot,
		"today":      time.Date(2026, 11, 1, 0, 0, 0, 0, time.Local),
		"yesterday":  time.Date(2026, 10, 31, 0, 0, 0, 0, time.Local),
		"2026-10-30": time.Date(2026, 10, 30, 0, 0, 0, 0, time.Local),
	}
	for in, want := range cases {
		got, label, err := parseSince(in, now, boot)
		if err != nil || !got.Equal(want) || label == "" {
			t.Errorf("%q: got %v %q %v, want %v", in, got, label, err, want)
		}
	}
	for _, bad := range []string{"2027-01-01", "soon", "-3h"} {
		if _, _, err := parseSince(bad, now, boot); err == nil {
			t.Errorf("%q must be an error", bad)
		}
	}
}

func TestDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		d    int
	}{{"slow", "slow", 0}, {"slwo", "slow", 1}, {"memroy", "memory", 1}, {"kitten", "sitting", 3}, {"", "abc", 3}} {
		if got := distance(c.a, c.b); got != c.d {
			t.Errorf("distance(%q, %q) = %d, want %d", c.a, c.b, got, c.d)
		}
	}
}

// fake is a healthy little machine for the command tests.
func fake(t *testing.T) *sys.Fake {
	f := sys.NewFake(t.TempDir())
	f.File("/etc/os-release", "ID=debian\nPRETTY_NAME=\"Debian GNU/Linux 12\"\n")
	f.File("/proc/uptime", "3600.0 100.0\n")
	f.File("/proc/meminfo", "MemTotal: 8000000 kB\nMemAvailable: 6000000 kB\n")
	f.File("/proc/self/mountinfo", "22 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw\n")
	f.Fs["/"] = sys.Statfs{Size: 100 << 30, Free: 60 << 30, Avail: 55 << 30, Files: 1000, FilesFree: 900}
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\n")
	f.File("/var/log/app/big.log", strings.Repeat("x", 4096))
	return f
}

func runWith(t *testing.T, f *sys.Fake, argv ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	oldOut, oldErr, oldM := stdout, stderr, machine
	stdout, stderr, machine = &out, &errb, func() sys.Sys { return f }
	defer func() { stdout, stderr, machine = oldOut, oldErr, oldM }()
	code := run(argv)
	return code, out.String(), errb.String()
}

func TestCheckCommand(t *testing.T) {
	f := fake(t)
	code, out, _ := runWith(t, f, "--json", "--only", "disk,memory,accounts")
	if code != 0 {
		t.Fatalf("a healthy machine exits 0, got %d:\n%s", code, out)
	}
	var j struct {
		Schema string
		Checks []struct{ Name string }
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Schema != "nabd/1" || len(j.Checks) != 3 {
		t.Fatalf("json: %v %+v", err, j)
	}
	f.Fs["/"] = sys.Statfs{Size: 100 << 30, Free: 1 << 30, Avail: 1 << 30, Files: 1000, FilesFree: 900}
	code, out, _ = runWith(t, f, "--nagios", "--only=disk")
	if code != 2 || !strings.HasPrefix(out, "NABD CRITICAL - / is 99% full") {
		t.Fatalf("a full disk is critical (exit 2), got %d: %s", code, out)
	}
}

func TestUsageErrorsExit3(t *testing.T) {
	f := fake(t)
	for argv, want := range map[string]string{
		"--only dsik": "did you mean disk",
		"bogus":       "unknown command",
		"why slwo":    "did you mean slow",
		"why port x":  "port number",
		"check disk":  "nabd why disk",
		"diff a b c":  "at most two",
	} {
		code, _, errOut := runWith(t, f, strings.Fields(argv)...)
		if code != 3 || !strings.Contains(errOut, want) {
			t.Errorf("nabd %s: want exit 3 and %q, got %d %q", argv, want, code, errOut)
		}
	}
}

func TestWhyShortForms(t *testing.T) {
	f := fake(t)
	code, out, errOut := runWith(t, f, "why", "/var/log", "--json")
	if code != 0 {
		t.Fatalf("why /var/log: exit %d %s", code, errOut)
	}
	var j struct {
		Why struct{ Topic, Subject string }
	}
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Why.Topic != "disk" {
		t.Fatalf("a path means disk: %v %+v", err, j)
	}
	_, out, _ = runWith(t, f, "why", "443", "--json")
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Why.Topic != "port" || j.Why.Subject != "443" {
		t.Fatalf("a number means port: %v %+v", err, j)
	}
	_, out, _ = runWith(t, f, "why", "nginx", "--json")
	if err := json.Unmarshal([]byte(out), &j); err != nil || j.Why.Topic != "service" {
		t.Fatalf("another word means a service: %v %+v", err, j)
	}
}

func TestSnapshotAndDiff(t *testing.T) {
	f := fake(t)
	t.Setenv("NABD_STATE_DIR", t.TempDir())
	if code, out, errOut := runWith(t, f, "snapshot"); code != 0 || !strings.Contains(out, "first snapshot") {
		t.Fatalf("snapshot: %d %s %s", code, out, errOut)
	}
	if code, out, _ := runWith(t, f, "diff"); code != 0 || !strings.Contains(out, "no differences") {
		t.Fatalf("nothing changed: %d %s", code, out)
	}
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/bash\n")
	code, out, _ := runWith(t, f, "diff", "--color", "never")
	if code != 2 || !strings.Contains(out, "toor uid=0") {
		t.Fatalf("a new UID 0 user is critical (exit 2): %d\n%s", code, out)
	}
	f.Clock = f.Clock.Add(time.Hour)
	if code, out, _ := runWith(t, f, "snapshot"); code != 0 || !strings.Contains(out, "1 critical") {
		t.Fatalf("the second snapshot reports the change: %d %s", code, out)
	}
	if code, out, _ := runWith(t, f, "diff", "prev", "last", "--json"); code != 2 || !strings.Contains(out, `"status": "crit"`) {
		t.Fatalf("diff prev last: %d %s", code, out)
	}
	if code, out, _ := runWith(t, f, "snapshot", "--list"); code != 0 || strings.Count(out, ".json") != 2 {
		t.Fatalf("list: %d %s", code, out)
	}
}

func TestVersionAndHelp(t *testing.T) {
	f := fake(t)
	if code, out, _ := runWith(t, f, "--version"); code != 0 || !strings.HasPrefix(out, "nabd "+version) {
		t.Fatalf("version: %d %s", code, out)
	}
	if code, out, _ := runWith(t, f, "help", "why"); code != 0 || !strings.Contains(out, "service NAME") {
		t.Fatalf("help why: %d %s", code, out)
	}
	if code, out, _ := runWith(t, f, "checks"); code != 0 || strings.Count(out, "\n") != 14 {
		t.Fatalf("checks: %d %s", code, out)
	}
}

func TestVersionFrom(t *testing.T) {
	rev := []debug.BuildSetting{{Key: "vcs.revision", Value: "305abc563e0302f254a0a09c8e9901b1c2312e16"}}
	cases := []struct {
		bi   *debug.BuildInfo
		want string
	}{
		{nil, releaseVersion},
		{&debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, "1.2.3"},
		{&debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, releaseVersion},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261101210729-305abc563e03"}, Settings: rev}, releaseVersion + "-dev+305abc5"},
		{&debug.BuildInfo{Main: debug.Module{Version: "v0.1.1-0.20261101210729-305abc563e03+dirty"}}, releaseVersion + "-dev+305abc5"},
	}
	for _, c := range cases {
		if got := versionFrom(c.bi); got != c.want {
			t.Errorf("%+v: got %q, want %q", c.bi, got, c.want)
		}
	}
}
