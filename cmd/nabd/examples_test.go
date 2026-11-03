package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/s0sta/nabd/internal/sys"
)

// healthyMachine is the demo server with its five problems fixed.
func healthyMachine(t *testing.T) *sys.Fake {
	t.Helper()
	f := demoMachine(t)
	for _, p := range []string{
		"/var/log/journal/4f1c2e/system.journal", "/var/log/journal/4f1c2e/system@0006.journal~",
		"/run/reboot-required", "/run/reboot-required.pkgs", "/etc/letsencrypt",
	} {
		if err := os.RemoveAll(filepath.Join(f.Root, p)); err != nil {
			t.Fatal(err)
		}
	}
	f.Fs["/var"] = sys.Statfs{Size: 40 << 30, Free: 31 << 30, Avail: 29 << 30, Files: 2600000, FilesFree: 2500000}
	f.Cmd("systemctl list-units --failed *", 0, "")
	f.Cmd("systemctl list-units --type=service *", 0, "nginx.service loaded active running A high performance web server\nredis-server.service loaded active running Advanced key-value store\nssh.service loaded active running OpenBSD Secure Shell server\n")
	// Redis only on localhost (127.0.0.1:6379)
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	f.File("/proc/net/tcp", head+
		"   0: 0100007F:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   110        0 31001 1 0 100 0 0 10 0\n"+
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31002 1 0 100 0 0 10 0\n")
	f.File("/lib/modules/6.8.0-48-generic/.keep", "")
	f.File("/proc/sys/kernel/osrelease", "6.8.0-48-generic\n")
	return f
}

// TestReadmeExamples are the examples of the README: what nabd prints on a
// healthy server and on a server with problems. NABD_EXAMPLES=DIR saves them.
func TestReadmeExamples(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	type example struct {
		name string
		f    func(*testing.T) *sys.Fake
		args []string
		code int
		want []string
	}
	for _, e := range []example{
		{"ok", healthyMachine, nil, 0, []string{"web-prod-1"}},
		{"problems", demoMachine, nil, 2, []string{"/var is 96% full", "nginx.service failed"}},
		{"quiet-ok", healthyMachine, []string{"-q"}, 0, nil},
		{"why-disk", demoMachine, []string{"why", "disk", "/var"}, -1, []string{"journal"}},
		{"why-nginx", demoMachine, []string{"why", "nginx"}, -1, []string{"servr"}},
		{"why-port", demoMachine, []string{"why", "6379"}, 2, []string{"Redis listens on 0.0.0.0:6379"}},
		{"nagios-ok", healthyMachine, []string{"--nagios"}, 0, []string{"OK"}},
		{"nagios-problems", demoMachine, []string{"--nagios"}, 2, []string{"CRITICAL"}},
	} {
		t.Run(e.name, func(t *testing.T) {
			code, out, errOut := runWith(t, e.f(t), append(e.args, "--color", "never")...)
			if e.code >= 0 && code != e.code {
				t.Errorf("exit %d, want %d\n%s%s", code, e.code, out, errOut)
			}
			for _, w := range e.want {
				if !strings.Contains(out, w) {
					t.Errorf("missing %q in:\n%s", w, out)
				}
			}
			if dir := os.Getenv("NABD_EXAMPLES"); dir != "" {
				_ = os.WriteFile(filepath.Join(dir, e.name+".txt"), []byte(out+"\n[exit "+string(rune('0'+code))+"]\n"), 0o644)
			}
		})
	}
}

// TestWhyPortMatchesPortsCheck: `nabd why port` gives the same verdict as the
// ports check of `nabd` (it said OK for an open Redis while `nabd` said CRIT).
func TestWhyPortMatchesPortsCheck(t *testing.T) {
	code, out, _ := runWith(t, demoMachine(t), "why", "6379", "--color", "never")
	if code != 2 || !strings.Contains(out, "CRIT  Redis listens on 0.0.0.0:6379: other machines can connect") ||
		!strings.Contains(out, "bind 127.0.0.1") {
		t.Errorf("open Redis: exit %d\n%s", code, out)
	}
	code, out, _ = runWith(t, healthyMachine(t), "why", "6379", "--color", "never")
	if code != 0 || !strings.Contains(out, "OK    redis-server") || !strings.Contains(out, "only for this machine") {
		t.Errorf("Redis on localhost: exit %d\n%s", code, out)
	}
	code, out, _ = runWith(t, demoMachine(t), "why", "22", "--color", "never")
	if code != 0 || !strings.Contains(out, "open to the network") {
		t.Errorf("SSH is not a risky port: exit %d\n%s", code, out)
	}
}
