package why

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
	"github.com/s0sta/nabd/internal/sys"
)

func box(t *testing.T) *sys.Fake {
	f := sys.NewFake(t.TempDir())
	f.File("/proc/uptime", "3600.0 100.0\n")
	f.File("/proc/self/mountinfo", "22 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw\n")
	f.Fs["/"] = sys.Statfs{Size: 10 << 20, Free: 1 << 20, Avail: 1 << 20, Files: 1000, FilesFree: 900}
	return f
}

func TestDiskFindsTheBigFolder(t *testing.T) {
	f := box(t)
	f.File("/var/log/huge/app.log", strings.Repeat("x", 600<<10))
	f.File("/home/alice/notes.txt", "small")
	c := core.NewCtx(f)
	a := Disk(c, "", 10*time.Second)
	if a.Subject != "/" || a.Severity != core.Warn {
		t.Fatalf("/ is 90%% full: %+v", a)
	}
	if len(a.Fix) == 0 || !strings.Contains(a.Fix[0], "/var/log/huge") {
		t.Fatalf("the fix must point at the folder that holds the space: %v", a.Fix)
	}
	var all []string
	for _, s := range a.Sections {
		all = append(all, s.Title+": "+strings.Join(s.Lines, " | "))
	}
	text := strings.Join(all, "\n")
	if !strings.Contains(text, "/var/log/huge") {
		t.Fatalf("the biggest folder must be listed:\n%s", text)
	}
	var buf bytes.Buffer
	Human(&buf, a, render.Style{}, c.Facts)
	if !strings.Contains(buf.String(), "nabd why disk /") {
		t.Fatalf("header:\n%s", buf.String())
	}
}

func TestDiskReadOnly(t *testing.T) {
	f := box(t)
	f.File("/proc/self/mountinfo", "22 1 252:1 / / ro,relatime - ext4 /dev/vda1 ro\n")
	a := Disk(core.NewCtx(f), "/", time.Second)
	if a.Severity != core.OK || !strings.Contains(a.Verdict, "read-only") {
		t.Fatalf("a read-only file system cannot fill up: %+v", a)
	}
}

func TestMemoryNamesTheBigProcess(t *testing.T) {
	f := box(t)
	f.File("/proc/meminfo", "MemTotal: 1000000 kB\nMemAvailable: 30000 kB\nSwapTotal: 0 kB\nSwapFree: 0 kB\n")
	f.File("/proc/4242/stat", "4242 (java) S 1 1 1 0 -1 0 0 0 0 0 10 10 0 0 20 0 50 0 100 1000 200000 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	f.File("/proc/4242/status", "Name:\tjava\nUid:\t1000\t1000\t1000\t1000\n")
	f.File("/proc/4242/comm", "java\n")
	a := Memory(core.NewCtx(f))
	if a.Severity == core.OK {
		t.Fatalf("3%% free is a problem: %+v", a)
	}
	found := false
	for _, s := range a.Sections {
		for _, l := range s.Lines {
			if strings.Contains(l, "java") {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("java must be named: %+v", a.Sections)
	}
}

func TestServiceWithoutSystemd(t *testing.T) {
	a := Service(core.NewCtx(box(t)), "nginx")
	if a.Severity != core.Unknown || !strings.Contains(a.Verdict, "systemd") {
		t.Fatalf("%+v", a)
	}
}
