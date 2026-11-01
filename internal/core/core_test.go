package core

import (
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/sys"
)

func TestTimeoutBecomesUnknown(t *testing.T) {
	c := NewCtx(sys.NewFake(t.TempDir()))
	slow := Check{Name: "slow", Run: func(*Ctx, *Out) { time.Sleep(2 * time.Second) }}
	fast := Check{Name: "fast", Run: func(_ *Ctx, o *Out) { o.OK("fine") }}
	start := time.Now()
	res, fs := Run(c, []Check{slow, fast}, Options{Timeout: 100 * time.Millisecond})
	if time.Since(start) > time.Second {
		t.Fatal("a hung check must not hold the run")
	}
	if len(fs) != 1 || fs[0].ID != "slow.timeout" || fs[0].Severity != Unknown {
		t.Fatalf("findings: %+v", fs)
	}
	if res[0].Status != "unknown" || res[1].Status != "ok" || res[1].Detail != "fine" {
		t.Fatalf("results: %+v", res)
	}
	if ExitCode(Overall(fs)) != 3 {
		t.Fatal("unknown exits 3")
	}
}

func TestOnlyAndSkip(t *testing.T) {
	c := NewCtx(sys.NewFake(t.TempDir()))
	mk := func(n string) Check { return Check{Name: n, Run: func(*Ctx, *Out) {}} }
	all := []Check{mk("a"), mk("b"), mk("c")}
	res, _ := Run(c, all, Options{Only: map[string]bool{"a": true, "c": true}, Skip: map[string]bool{"c": true}})
	if len(res) != 1 || res[0].Name != "a" {
		t.Fatalf("only a, c minus skip c = a, got %+v", res)
	}
}

func TestSortAndExitCodes(t *testing.T) {
	fs := []Finding{{Check: "b", Severity: Info}, {Check: "a", Severity: Warn}, {Check: "c", Severity: Crit}, {Check: "d", Severity: Unknown}}
	SortFindings(fs)
	if fs[0].Severity != Crit || fs[1].Severity != Warn || fs[2].Severity != Unknown || fs[3].Severity != Info {
		t.Fatalf("order: %+v", fs)
	}
	for sev, code := range map[Severity]int{OK: 0, Info: 0, Warn: 1, Crit: 2, Unknown: 3} {
		if ExitCode(sev) != code {
			t.Errorf("%s exits %d", sev, ExitCode(sev))
		}
	}
}

func TestFormat(t *testing.T) {
	if Bytes(1536) != "1.5 KB" && Bytes(1536) != "1.5 kB" {
		t.Errorf("bytes: %s", Bytes(1536))
	}
	if Plural(1, "file", "files") != "1 file" || Plural(3, "file", "files") != "3 files" {
		t.Error("plural")
	}
	if ts, ok := ParseISO("2026-11-01T11:58:00+0000"); !ok || ts.UTC().Hour() != 11 {
		t.Errorf("iso: %v %v", ts, ok)
	}
	if _, ok := ParseISO("not a time"); ok {
		t.Error("garbage is not a time")
	}
}
