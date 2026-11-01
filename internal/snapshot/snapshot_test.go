package snapshot

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
	"github.com/s0sta/nabd/internal/sys"
)

func base() State {
	return State{Schema: Schema, Host: "web1", Time: time.Date(2026, 10, 31, 12, 0, 0, 0, time.UTC), Root: true, Complete: true,
		Kernel: "6.1.0-28", Firewall: "nftables", SELinux: "enforcing",
		Listeners: []string{"tcp 0.0.0.0:22 sshd", "tcp 127.0.0.1:5432 postgres"},
		Users:     []string{"root uid=0 shell=/bin/bash", "www-data uid=33 shell=/usr/sbin/nologin"},
		Admins:    []string{"sudo: alice"},
		SUID:      []string{"/usr/bin/passwd", "/usr/bin/sudo"},
		Enabled:   []string{"nginx.service", "ssh.service"},
		Packages:  map[string]string{"openssl": "3.0.13-1", "nginx": "1.22.1-9", "telnet": "0.17"},
		Files:     map[string]string{"/etc/hosts": "aa", "/etc/sudoers": "bb", "/root/.ssh/authorized_keys": "cc"},
		Sysctl:    map[string]string{"net.ipv4.ip_forward": "0"},
	}
}

func sevOf(items []Item, what string) (core.Severity, bool) {
	for _, it := range items {
		if strings.Contains(it.What, what) {
			return it.Severity, true
		}
	}
	return core.OK, false
}

func TestDiffSame(t *testing.T) {
	if d := Diff(base(), base()); len(d) != 0 {
		t.Fatalf("no differences expected, got %v", d)
	}
}

func TestDiffSeverities(t *testing.T) {
	a, b := base(), base()
	b.Time = a.Time.Add(24 * time.Hour)
	b.Users = append(b.Users, "toor uid=0 shell=/bin/sh", "deploy uid=1001 shell=/bin/bash")
	b.Admins = append(b.Admins, "sudo: deploy")
	b.SUID = append(b.SUID, "/tmp/.x/bash")
	b.Listeners = append(b.Listeners, "tcp 0.0.0.0:6379 redis-server", "tcp 127.0.0.1:8080 java")
	b.Firewall = "none"
	b.Packages = map[string]string{"openssl": "3.0.15-1", "nginx": "1.22.1-9", "redis": "7.0.15"}
	b.Files = map[string]string{"/etc/hosts": "aa", "/etc/sudoers": "XX", "/root/.ssh/authorized_keys": "cc", "/etc/motd": "dd"}
	b.Sysctl = map[string]string{"net.ipv4.ip_forward": "1"}
	d := Diff(a, b)
	want := map[string]core.Severity{
		"toor uid=0":                  core.Crit, // a second root
		"/tmp/.x/bash":                core.Crit, // SUID in a writable place
		"deploy uid=1001":             core.Warn, // new login user
		"sudo: deploy":                core.Warn, // new admin
		"0.0.0.0:6379":                core.Warn, // new open port
		"127.0.0.1:8080":              core.Info, // local only
		"nftables → none":             core.Warn, // firewall off
		"/etc/sudoers":                core.Warn,
		"/etc/motd":                   core.Info,
		"openssl 3.0.13-1 → 3.0.15-1": core.Info,
		"redis 7.0.15":                core.Info,
		"telnet 0.17":                 core.Info,
		"net.ipv4.ip_forward 0 → 1":   core.Info,
	}
	for what, sev := range want {
		got, ok := sevOf(d, what)
		if !ok {
			t.Errorf("missing difference %q", what)
			continue
		}
		if got != sev {
			t.Errorf("%q: severity %s, want %s", what, got, sev)
		}
	}
	// the most important areas come first
	if d[0].Area != "users" || d[0].Severity != core.Crit {
		t.Errorf("first difference should be the new root user, got %+v", d[0])
	}
	r := Report{From: SideOf(a, "a.json"), To: SideOf(b, ""), Items: d}
	if r.Worst() != core.Crit {
		t.Errorf("worst: %s", r.Worst())
	}
	var buf bytes.Buffer
	if err := JSON(&buf, r, "test"); err != nil {
		t.Fatal(err)
	}
	var j map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &j); err != nil || j["status"] != "crit" || j["schema"] != render.Schema {
		t.Fatalf("json: %v %v", err, j["status"])
	}
}

func TestIncompleteScanHidesFileAddsAndRemoves(t *testing.T) {
	a, b := base(), base()
	b.Complete = false
	delete(b.Files, "/etc/hosts")
	if d := Diff(a, b); len(d) != 0 {
		t.Fatalf("a scan that stopped early must not report removed files: %v", d)
	}
}

func TestSaveListKeep(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "snaps")
	s := base()
	for i := 0; i < 5; i++ {
		s.Time = s.Time.Add(time.Hour)
		if _, err := Save(dir, s, 3); err != nil {
			t.Fatal(err)
		}
	}
	list, err := List(dir)
	if err != nil || len(list) != 3 {
		t.Fatalf("keep 3: got %d files (%v)", len(list), err)
	}
	if st, _ := os.Stat(dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the snapshot folder must be private, got %v", st.Mode().Perm())
	}
	got, err := Load(list[len(list)-1])
	if err != nil || !got.Time.Equal(s.Time) || got.Host != "web1" {
		t.Fatalf("load: %v %+v", err, got.Time)
	}
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte(`{"schema":"other"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(filepath.Join(dir, "bad.json")); err == nil {
		t.Fatal("a file with another schema must be refused")
	}
}

func TestTake(t *testing.T) {
	f := sys.NewFake(t.TempDir())
	f.File("/proc/uptime", "100.0 10.0\n")
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	f.File("/etc/group", "root:x:0:\nsudo:x:27:alice\ndocker:x:999:alice,bob\nusers:x:100:alice\n")
	f.File("/etc/hosts", "127.0.0.1 localhost\n")
	f.File("/etc/passwd-", "old copy\n")
	f.File("/home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA alice\n")
	f.File("/proc/sys/net/ipv4/ip_forward", "0\n")
	f.Cmd("dpkg-query *", 0, "bash 5.2.15-2\nopenssl 3.0.15-1\n")
	c := core.NewCtx(f)
	s := Take(c, "test")
	if len(s.Users) != 2 || len(s.Admins) != 3 {
		t.Errorf("users %v admins %v", s.Users, s.Admins)
	}
	if s.Packages["openssl"] != "3.0.15-1" {
		t.Errorf("packages: %v", s.Packages)
	}
	if _, ok := s.Files["/home/alice/.ssh/authorized_keys"]; !ok {
		t.Errorf("authorized_keys must be hashed: %v", s.Files)
	}
	if _, ok := s.Files["/etc/passwd-"]; ok {
		t.Error("backup copies are noise")
	}
	if s.Sysctl["net.ipv4.ip_forward"] != "0" {
		t.Errorf("sysctl: %v", s.Sysctl)
	}
}
