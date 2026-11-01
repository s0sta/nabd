package changes

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
	"github.com/s0sta/nabd/internal/sys"
)

func TestTimeline(t *testing.T) {
	f := sys.NewFake(t.TempDir())
	now := f.Clock
	f.File("/proc/uptime", "864000.00 1000.00\n")
	at := func(d time.Duration) string { return now.Add(-d).In(time.Local).Format("2006-01-02 15:04:05") }
	f.File("/var/log/dpkg.log",
		at(72*time.Hour)+" upgrade bash:amd64 5.2.15-2 5.2.15-2+b7\n"+
			at(2*time.Hour)+" upgrade openssl:amd64 3.0.13-1 3.0.15-1\n"+
			at(2*time.Hour)+" install nginx:amd64 <none> 1.22.1-9\n")
	f.File("/etc/nginx/nginx.conf", "events {}\n")
	f.Touch("/etc/nginx/nginx.conf", now.Add(-2*time.Hour+time.Minute)) // written by the package
	f.File("/etc/ssh/sshd_config", "PermitRootLogin yes\n")
	f.Touch("/etc/ssh/sshd_config", now.Add(-time.Hour))
	f.File("/etc/old.conf", "x\n")
	f.Touch("/etc/old.conf", now.Add(-72*time.Hour))
	f.File("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA test\n")
	f.Touch("/root/.ssh/authorized_keys", now.Add(-30*time.Minute))
	f.Touch("/etc/ssh", now.Add(-48*time.Hour))
	f.Touch("/etc/nginx", now.Add(-48*time.Hour))
	f.Touch("/etc", now.Add(-48*time.Hour))

	c := core.NewCtx(f)
	r := Collect(c, now.Add(-24*time.Hour))

	var got []string
	alerts := 0
	for _, e := range r.Events {
		got = append(got, e.Kind+": "+e.Text)
		if e.Alert {
			alerts++
		}
	}
	all := strings.Join(got, "\n")
	for _, want := range []string{"openssl", "nginx installed", "/etc/ssh/sshd_config", "SSH keys of root changed", "changed by the package update"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in:\n%s", want, all)
		}
	}
	if strings.Contains(all, "bash") || strings.Contains(all, "old.conf") {
		t.Errorf("changes older than --since must not show:\n%s", all)
	}
	if strings.Contains(all, "file: /etc/nginx/nginx.conf") {
		t.Errorf("a file written by a package update is grouped, not listed:\n%s", all)
	}
	if alerts != 2 {
		t.Errorf("want 2 security alerts (sshd_config, authorized_keys), got %d:\n%s", alerts, all)
	}
	for i := 1; i < len(r.Events); i++ {
		if r.Events[i].Time.Before(r.Events[i-1].Time) {
			t.Fatal("the timeline must be sorted by time")
		}
	}
	var buf bytes.Buffer
	Human(&buf, r, render.Style{}, c.Facts, now, "last 24 hours")
	if !strings.Contains(buf.String(), "marked ! touch security") {
		t.Errorf("the human view must explain the ! marks:\n%s", buf.String())
	}
}

func TestSensitive(t *testing.T) {
	for _, p := range []string{"/etc/sudoers.d/90-admin", "/etc/ssh/sshd_config", "/etc/pam.d/sshd", "/etc/ld.so.preload", "/etc/shadow"} {
		if !Sensitive(p) {
			t.Errorf("%s must be sensitive", p)
		}
	}
	for _, p := range []string{"/etc/nginx/nginx.conf", "/etc/motd"} {
		if Sensitive(p) {
			t.Errorf("%s is not sensitive", p)
		}
	}
}
