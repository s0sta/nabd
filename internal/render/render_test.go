package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/core"
)

func report() Report {
	fs := []core.Finding{
		{ID: "disk.full", Check: "disk", Severity: core.Crit, Title: "/var is 97% full (1 GB free of 40 GB)", Why: []string{"the journal uses 12 GB"},
			Fix: []string{"journalctl --vacuum-size=500M   # keep 500 MB of logs"}},
		{ID: "ports.exposed-6379", Check: "ports", Severity: core.Warn, Title: `Redis listens on 0.0.0.0:6379 | "open"`},
		{ID: "reboot.kernel", Check: "reboot", Severity: core.Info, Title: "a newer kernel is installed"},
	}
	return Report{Version: "0.1.0", Facts: core.Facts{Hostname: "web1", OS: "Debian GNU/Linux 12", Kernel: "6.1.0"},
		Time: time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC), Duration: 1200 * time.Millisecond,
		Checks:   []core.CheckResult{{Name: "disk", Status: "crit"}, {Name: "ports", Status: "warn"}, {Name: "memory", Status: "ok"}, {Name: "time", Status: "skipped"}},
		Findings: fs, Status: core.Overall(fs)}
}

func TestOverallIgnoresInfo(t *testing.T) {
	if core.Overall([]core.Finding{{Severity: core.Info}}) != core.OK {
		t.Fatal("notes do not change the status")
	}
	if r := report(); r.Status != core.Crit || core.ExitCode(r.Status) != 2 {
		t.Fatalf("status %s", r.Status)
	}
}

func TestJSON(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, report()); err != nil {
		t.Fatal(err)
	}
	var j struct {
		Schema   string `json:"schema"`
		Status   string `json:"status"`
		ExitCode int    `json:"exit_code"`
		Summary  map[string]int
		Findings []struct {
			ID       string `json:"id"`
			Severity string `json:"severity"`
		}
	}
	if err := json.Unmarshal(buf.Bytes(), &j); err != nil {
		t.Fatal(err)
	}
	if j.Schema != "nabd/1" || j.Status != "crit" || j.ExitCode != 2 || j.Summary["warn"] != 1 || j.Summary["ok_checks"] != 1 {
		t.Fatalf("json: %+v", j)
	}
	if j.Findings[0].Severity != "crit" {
		t.Fatal("severities are written as names")
	}
}

func TestNagios(t *testing.T) {
	var buf bytes.Buffer
	Nagios(&buf, report())
	first := strings.SplitN(buf.String(), "\n", 2)[0]
	if !strings.HasPrefix(first, "NABD CRITICAL - /var is 97% full") {
		t.Fatalf("status line: %s", first)
	}
	if strings.Count(first, "|") != 1 {
		t.Fatalf("only the perfdata separator may be a |: %s", first)
	}
	if !strings.Contains(first, "crit=1;;;0 warn=1;;;0") {
		t.Fatalf("perfdata: %s", first)
	}
}

func TestPrometheus(t *testing.T) {
	var buf bytes.Buffer
	Prometheus(&buf, report())
	out := buf.String()
	for _, want := range []string{"nabd_status 2\n", `nabd_findings{severity="crit"} 1`, `nabd_check_status{check="time"} -1`,
		`title="Redis listens on 0.0.0.0:6379 | \"open\""`, "nabd_last_run_timestamp_seconds 1793534400\n"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestHumanAndMarkdown(t *testing.T) {
	var buf bytes.Buffer
	Human(&buf, report(), Style{Width: 100})
	out := buf.String()
	for _, want := range []string{"✖ CRIT", "journalctl --vacuum-size=500M", "2 problems: 1 critical, 1 warning, 1 note"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(out, "\x1b[") {
		t.Error("no colour codes without a colour style")
	}
	buf.Reset()
	Human(&buf, report(), Style{Width: 100, ASCII: true, Quiet: true})
	if strings.Contains(buf.String(), "newer kernel") || strings.ContainsAny(buf.String(), "✖▲●✔") {
		t.Errorf("quiet hides notes, ascii has no symbols:\n%s", buf.String())
	}
	buf.Reset()
	Markdown(&buf, report())
	if !strings.Contains(buf.String(), `Redis listens on 0.0.0.0:6379 \| "open"`) {
		t.Errorf("a | in a table cell must be escaped:\n%s", buf.String())
	}
}

func TestWrap(t *testing.T) {
	lines := wrap("one two three four five six seven", 10)
	for _, l := range lines {
		if len(l) > 10 {
			t.Fatalf("line too long: %q", l)
		}
	}
	if strings.Join(lines, " ") != "one two three four five six seven" {
		t.Fatal("wrap must keep every word")
	}
}
