// Package snapshot saves the security-relevant state of the machine and
// compares two states: new open ports, users, admin group members, SUID
// files, SSH keys, sudoers, packages, enabled services and /etc files.
//
// "nabd snapshot" is the only command that writes, and only into its own
// folder (/var/lib/nabd/snapshots as root).
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/checks"
	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Schema of the snapshot files.
const Schema = "nabd-snapshot/1"

// State is the saved state of a machine.
type State struct {
	Schema    string            `json:"schema"`
	Version   string            `json:"version"`
	Host      string            `json:"host"`
	Time      time.Time         `json:"time"`
	Root      bool              `json:"root"`
	Kernel    string            `json:"kernel"`
	SELinux   string            `json:"selinux,omitempty"`
	Firewall  string            `json:"firewall"`
	Listeners []string          `json:"listeners"`
	Enabled   []string          `json:"enabled_units"`
	Users     []string          `json:"users"`
	Admins    []string          `json:"admin_members"`
	SUID      []string          `json:"suid_files"`
	Packages  map[string]string `json:"packages"`
	Files     map[string]string `json:"files"`
	Sysctl    map[string]string `json:"sysctl"`
	Complete  bool              `json:"files_complete"`
}

var sysctls = []string{"net/ipv4/ip_forward", "kernel/randomize_va_space", "kernel/kptr_restrict", "kernel/dmesg_restrict",
	"kernel/yama/ptrace_scope", "kernel/unprivileged_bpf_disabled", "fs/protected_symlinks", "fs/protected_hardlinks",
	"net/ipv4/conf/all/accept_redirects", "net/ipv4/conf/all/send_redirects", "net/ipv4/tcp_syncookies", "kernel/modules_disabled"}

var adminGroups = map[string]bool{"wheel": true, "sudo": true, "admin": true, "docker": true, "adm": true, "libvirt": true, "lxd": true, "root": true}

var suidDirs = []string{"/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin", "/usr/libexec", "/usr/lib", "/opt", "/tmp", "/var/tmp", "/dev/shm", "/home"}

// Take reads the state now.
func Take(c *core.Ctx, version string) State {
	s := State{Schema: Schema, Version: version, Host: c.Facts.Hostname, Time: c.Sys.Now().UTC(), Root: c.Facts.Root,
		Kernel: c.Facts.Kernel, Packages: map[string]string{}, Files: map[string]string{}, Sysctl: map[string]string{}, Complete: true}
	if b, err := c.Sys.ReadFile("/sys/fs/selinux/enforce"); err == nil {
		s.SELinux = map[string]string{"1": "enforcing", "0": "permissive"}[strings.TrimSpace(string(b))]
	}
	fw := checks.DetectFirewall(c)
	s.Firewall = "none"
	if fw.Active {
		s.Firewall = fw.Name
	}
	ls, _ := c.Listeners()
	for _, l := range ls {
		who := l.Process
		if who == "" {
			who = "?"
		}
		s.Listeners = append(s.Listeners, fmt.Sprintf("%s %s %s", strings.TrimSuffix(l.Proto, "6"), l.Addr(), who))
	}
	s.Listeners = uniqSorted(s.Listeners)
	if c.Facts.Systemd {
		r := c.Sys.Run(10*time.Second, "systemctl", "list-unit-files", "--state=enabled", "--no-legend", "--plain", "--no-pager")
		for _, l := range strings.Split(r.Stdout, "\n") {
			if f := strings.Fields(l); len(f) > 0 && strings.Contains(f[0], ".") {
				s.Enabled = append(s.Enabled, f[0])
			}
		}
		s.Enabled = uniqSorted(s.Enabled)
	}
	if b, err := c.Sys.ReadFile("/etc/passwd"); err == nil {
		for _, l := range linux.Lines(b) {
			if f := strings.Split(l, ":"); len(f) >= 7 {
				s.Users = append(s.Users, f[0]+" uid="+f[2]+" shell="+f[6])
			}
		}
		sort.Strings(s.Users)
	}
	if b, err := c.Sys.ReadFile("/etc/group"); err == nil {
		for _, l := range linux.Lines(b) {
			f := strings.Split(l, ":")
			if len(f) >= 4 && adminGroups[f[0]] && f[3] != "" {
				for _, u := range strings.Split(f[3], ",") {
					s.Admins = append(s.Admins, f[0]+": "+u)
				}
			}
		}
		sort.Strings(s.Admins)
	}
	s.Packages = packages(c)
	deadline := time.Now().Add(12 * time.Second)
	hash := func(p string) {
		if time.Now().After(deadline) {
			s.Complete = false
			return
		}
		b, err := c.Sys.ReadFile(p)
		if err != nil {
			return
		}
		sum := sha256.Sum256(b)
		s.Files[p] = hex.EncodeToString(sum[:])
	}
	_ = c.Sys.Walk("/etc", func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			s.Complete = false
			return io.EOF
		}
		if e.IsDir() {
			for _, d := range noisyDirs {
				if p+"/" == d || strings.HasPrefix(p+"/", d) {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !e.Type().IsRegular() || noisyFile(p) {
			return nil
		}
		if info, err := e.Info(); err == nil && info.Size() <= 1<<20 {
			hash(p)
		}
		return nil
	})
	homes := []string{"/root"}
	if ents, err := c.Sys.ReadDir("/home"); err == nil {
		for _, e := range ents {
			homes = append(homes, "/home/"+e.Name())
		}
	}
	for _, h := range homes {
		hash(h + "/.ssh/authorized_keys")
	}
	for _, d := range []string{"/var/spool/cron", "/var/spool/cron/crontabs"} {
		if ents, err := c.Sys.ReadDir(d); err == nil {
			for _, e := range ents {
				if !e.IsDir() {
					hash(d + "/" + e.Name())
				}
			}
		}
	}
	for _, d := range suidDirs {
		_ = c.Sys.Walk(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if time.Now().After(deadline) {
				s.Complete = false
				return io.EOF
			}
			if e.IsDir() {
				if strings.Count(strings.TrimPrefix(p, d), "/") > 4 {
					return filepath.SkipDir
				}
				return nil
			}
			if info, err := e.Info(); err == nil && info.Mode().IsRegular() && info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
				s.SUID = append(s.SUID, p)
			}
			return nil
		})
	}
	s.SUID = uniqSorted(s.SUID)
	for _, k := range sysctls {
		if b, err := c.Sys.ReadFile("/proc/sys/" + k); err == nil {
			s.Sysctl[strings.ReplaceAll(k, "/", ".")] = strings.TrimSpace(string(b))
		}
	}
	return s
}

var noisyDirs = []string{"/etc/ssl/certs/", "/etc/pki/ca-trust/extracted/", "/etc/selinux/targeted/active/",
	"/etc/selinux/targeted/policy/", "/etc/lvm/archive/", "/etc/lvm/backup/", "/etc/alternatives/", "/etc/fonts/", "/etc/pki/nssdb/"}

func noisyFile(p string) bool {
	switch p {
	case "/etc/mtab", "/etc/adjtime", "/etc/ld.so.cache", "/etc/.pwd.lock", "/etc/aliases.db", "/etc/resolv.conf", "/etc/udev/hwdb.bin",
		// backup copies that shadow-utils writes on every change
		"/etc/passwd-", "/etc/group-", "/etc/shadow-", "/etc/gshadow-", "/etc/subuid-", "/etc/subgid-":
		return true
	}
	return strings.HasSuffix(p, "~") || strings.HasSuffix(p, ".swp") || strings.HasSuffix(p, ".dpkg-old")
}

func packages(c *core.Ctx) map[string]string {
	out := map[string]string{}
	add := func(stdout string, split func(string) (string, string, bool)) {
		for _, l := range strings.Split(stdout, "\n") {
			if n, v, ok := split(l); ok {
				out[n] = v
			}
		}
	}
	two := func(l string) (string, string, bool) {
		f := strings.Fields(l)
		if len(f) == 2 {
			return f[0], f[1], true
		}
		return "", "", false
	}
	switch {
	case c.Sys.Has("rpm") && (c.Facts.Family() == "rhel" || c.Facts.Family() == "suse"):
		add(c.Sys.Run(30*time.Second, "rpm", "-qa", "--qf", "%{NAME} %{VERSION}-%{RELEASE}\n").Stdout, two)
	case c.Sys.Has("dpkg-query"):
		add(c.Sys.Run(30*time.Second, "dpkg-query", "-W", "-f", "${Package} ${Version}\n").Stdout, two)
	case c.Sys.Has("pacman"):
		add(c.Sys.Run(30*time.Second, "pacman", "-Q").Stdout, two)
	case c.Sys.Has("apk"):
		add(c.Sys.Run(30*time.Second, "apk", "info", "-v").Stdout, func(l string) (string, string, bool) {
			// name-1.2.3-r0: the version starts after the second-last dash
			l = strings.TrimSpace(l)
			j := strings.LastIndexByte(l, '-')
			if j <= 0 {
				return "", "", false
			}
			k := strings.LastIndexByte(l[:j], '-')
			if k <= 0 {
				return "", "", false
			}
			return l[:k], l[k+1:], true
		})
	}
	return out
}

func uniqSorted(in []string) []string {
	sort.Strings(in)
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// Dir is where snapshots are saved: /var/lib/nabd/snapshots for root, else in the user's state folder.
func Dir(root bool) string {
	if v := os.Getenv("NABD_STATE_DIR"); v != "" {
		return filepath.Join(v, "snapshots")
	}
	if root {
		return "/var/lib/nabd/snapshots"
	}
	if x := os.Getenv("XDG_STATE_HOME"); x != "" {
		return filepath.Join(x, "nabd", "snapshots")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local", "state", "nabd", "snapshots")
}

// Save writes the state and removes the oldest files beyond keep (0 = keep all).
func Save(dir string, s State, keep int) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := filepath.Join(dir, s.Time.Format("20060102T150405Z")+".json")
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		return "", err
	}
	tmp := name + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, name); err != nil {
		return "", err
	}
	if keep > 0 {
		list, _ := List(dir)
		for i := 0; i < len(list)-keep; i++ {
			_ = os.Remove(list[i])
		}
	}
	return name, nil
}

// List returns the snapshot files, oldest first.
func List(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".json") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out, nil
}

// Load reads a snapshot file.
func Load(path string) (State, error) {
	var s State
	b, err := os.ReadFile(path)
	if err != nil {
		return s, err
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("%s: %w", path, err)
	}
	if s.Schema != Schema {
		return s, errors.New(path + ": not a nabd snapshot")
	}
	return s, nil
}

// Item is one difference.
type Item struct {
	Area     string        `json:"area"`
	Change   string        `json:"change"` // added, removed, changed
	What     string        `json:"what"`
	Severity core.Severity `json:"severity"`
}

// Diff compares two states.
func Diff(a, b State) []Item {
	var out []Item
	set := func(area string, x, y []string, addSev, delSev func(string) core.Severity) {
		inA, inB := map[string]bool{}, map[string]bool{}
		for _, v := range x {
			inA[v] = true
		}
		for _, v := range y {
			inB[v] = true
		}
		for _, v := range y {
			if !inA[v] {
				out = append(out, Item{area, "added", v, addSev(v)})
			}
		}
		for _, v := range x {
			if !inB[v] {
				out = append(out, Item{area, "removed", v, delSev(v)})
			}
		}
	}
	info := func(string) core.Severity { return core.Info }
	set("open ports", a.Listeners, b.Listeners, func(v string) core.Severity {
		if strings.Contains(v, " 0.0.0.0:") || strings.Contains(v, " [::]:") {
			return core.Warn
		}
		return core.Info
	}, info)
	set("users", a.Users, b.Users, func(v string) core.Severity {
		if strings.Contains(v, " uid=0 ") {
			return core.Crit
		}
		if !strings.HasSuffix(v, "nologin") && !strings.HasSuffix(v, "false") {
			return core.Warn
		}
		return core.Info
	}, info)
	set("admin groups", a.Admins, b.Admins, func(string) core.Severity { return core.Warn }, info)
	set("SUID/SGID files", a.SUID, b.SUID, func(v string) core.Severity {
		for _, d := range []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/"} {
			if strings.HasPrefix(v, d) {
				return core.Crit
			}
		}
		return core.Warn
	}, info)
	set("enabled services", a.Enabled, b.Enabled, func(string) core.Severity { return core.Warn }, info)
	if a.Firewall != b.Firewall {
		sev := core.Info
		if b.Firewall == "none" {
			sev = core.Warn
		}
		out = append(out, Item{"firewall", "changed", a.Firewall + " → " + b.Firewall, sev})
	}
	if a.SELinux != b.SELinux && a.SELinux != "" {
		sev := core.Info
		if b.SELinux != "enforcing" {
			sev = core.Warn
		}
		out = append(out, Item{"SELinux", "changed", a.SELinux + " → " + nzs(b.SELinux, "off"), sev})
	}
	if a.Kernel != b.Kernel {
		out = append(out, Item{"kernel", "changed", a.Kernel + " → " + b.Kernel, core.Info})
	}
	for k, v := range b.Sysctl {
		if old, ok := a.Sysctl[k]; ok && old != v {
			out = append(out, Item{"kernel settings", "changed", fmt.Sprintf("%s %s → %s", k, old, v), core.Info})
		}
	}
	for n, v := range b.Packages {
		old, ok := a.Packages[n]
		switch {
		case !ok:
			out = append(out, Item{"packages", "added", n + " " + v, core.Info})
		case old != v:
			out = append(out, Item{"packages", "changed", n + " " + old + " → " + v, core.Info})
		}
	}
	for n, v := range a.Packages {
		if _, ok := b.Packages[n]; !ok {
			out = append(out, Item{"packages", "removed", n + " " + v, core.Info})
		}
	}
	for p, h := range b.Files {
		old, ok := a.Files[p]
		sev := core.Info
		if strings.HasSuffix(p, "authorized_keys") || strings.HasPrefix(p, "/etc/sudoers") || strings.HasPrefix(p, "/var/spool/cron") ||
			p == "/etc/ld.so.preload" || p == "/etc/passwd" || p == "/etc/shadow" || strings.HasPrefix(p, "/etc/ssh/sshd_config") {
			sev = core.Warn
		}
		switch {
		case !ok && a.Complete:
			out = append(out, Item{"files", "added", p, sev})
		case ok && old != h:
			out = append(out, Item{"files", "changed", p, sev})
		}
	}
	for p := range a.Files {
		if _, ok := b.Files[p]; !ok && b.Complete {
			out = append(out, Item{"files", "removed", p, core.Info})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Area != out[j].Area {
			return areaOrder(out[i].Area) < areaOrder(out[j].Area)
		}
		if out[i].Severity.Rank() != out[j].Severity.Rank() {
			return out[i].Severity.Rank() > out[j].Severity.Rank()
		}
		return out[i].What < out[j].What
	})
	return out
}

func areaOrder(a string) int {
	for i, x := range []string{"users", "admin groups", "SUID/SGID files", "open ports", "firewall", "SELinux", "enabled services", "files", "kernel", "kernel settings", "packages"} {
		if x == a {
			return i
		}
	}
	return 99
}

func nzs(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
