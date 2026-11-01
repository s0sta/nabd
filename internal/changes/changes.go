// Package changes builds a timeline of what changed on the machine:
// packages, config files, SSH keys, cron jobs, logins, reboots and failed
// services. It needs no earlier snapshot: it reads logs and file times.
package changes

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/checks"
	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
)

// Event is one change.
type Event struct {
	Time  time.Time `json:"time"`
	Kind  string    `json:"kind"` // pkg, file, key, cron, login, boot, svc
	Text  string    `json:"text"`
	Alert bool      `json:"alert,omitempty"` // security relevant
}

// Result is the timeline.
type Result struct {
	Since   time.Time `json:"since"`
	Events  []Event   `json:"events"`
	Limited []string  `json:"limited,omitempty"`
}

var noisy = []string{"/etc/mtab", "/etc/adjtime", "/etc/ld.so.cache", "/etc/.pwd.lock", "/etc/aliases.db",
	"/etc/printcap", "/etc/.updated", "/etc/udev/hwdb.bin", "/etc/resolv.conf"}
var noisyDirs = []string{"/etc/ssl/certs/", "/etc/pki/ca-trust/extracted/", "/etc/selinux/targeted/active/",
	"/etc/lvm/archive/", "/etc/lvm/backup/", "/etc/cups/", "/etc/fonts/", "/etc/alternatives/", "/etc/pki/nssdb/",
	"/etc/ca-certificates/extracted/", "/etc/selinux/targeted/policy/", "/etc/selinux/targeted/contexts/files/file_contexts.bin"}

// sensitive files: a change here can mean an attacker or a big admin change.
var sensitive = []string{"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/",
	"/etc/ssh/", "/etc/pam.d/", "/etc/cron", "/etc/crontab", "/etc/anacrontab", "/etc/systemd/system/", "/etc/ld.so.preload",
	"/etc/profile", "/etc/profile.d/", "/etc/bash.bashrc", "/etc/rc.local", "/etc/hosts", "/etc/security/",
	"/etc/environment", "/etc/modprobe.d/", "/etc/sysctl.conf", "/etc/sysctl.d/"}

func isNoisy(p string) bool {
	for _, n := range noisy {
		if p == n {
			return true
		}
	}
	for _, d := range noisyDirs {
		if strings.HasPrefix(p, d) {
			return true
		}
	}
	return strings.HasSuffix(p, "~") || strings.HasSuffix(p, ".swp")
}

// Sensitive is true for files whose change matters for security.
func Sensitive(p string) bool {
	for _, s := range sensitive {
		if p == s || strings.HasPrefix(p, s) {
			return true
		}
	}
	return false
}

// Collect reads all changes since the time.
func Collect(c *core.Ctx, since time.Time) Result {
	now := c.Sys.Now()
	res := Result{Since: since}
	add := func(e Event) { res.Events = append(res.Events, e) }

	pkgTimes := []time.Time{}
	evs, _ := c.PkgEvents()
	for _, e := range evs {
		if !e.Time.Before(since) {
			add(Event{Time: e.Time, Kind: "pkg", Text: checks.PkgEventText(e)})
			pkgTimes = append(pkgTimes, e.Time)
		}
	}
	nearPkg := func(t time.Time) bool {
		for _, pt := range pkgTimes {
			if d := t.Sub(pt); d > -2*time.Minute && d < 3*time.Minute {
				return true
			}
		}
		return false
	}
	byPkg := map[string]int{}
	for _, fc := range core.ModTimeInside(c.Sys, []string{"/etc"}, since, now.Add(time.Minute), 400, 4*time.Second) {
		if isNoisy(fc.Path) {
			continue
		}
		alert := Sensitive(fc.Path)
		text := fc.Path
		if nearPkg(fc.Time) {
			if !alert {
				byPkg[fc.Time.Truncate(time.Minute).Format(time.RFC3339)]++
				continue
			}
			text += "  (during a package update)"
		}
		add(Event{Time: fc.Time, Kind: "file", Text: text, Alert: alert})
	}
	for k, n := range byPkg {
		t, _ := time.Parse(time.RFC3339, k)
		add(Event{Time: t, Kind: "file", Text: fmt.Sprintf("%s in /etc changed by the package update", core.Plural(n, "file", "files"))})
	}
	// SSH keys and cron tables of users
	homes := []string{"/root"}
	if ents, err := c.Sys.ReadDir("/home"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				homes = append(homes, "/home/"+e.Name())
			}
		}
	}
	denied := false
	for _, h := range homes {
		for _, f := range []string{"/.ssh/authorized_keys", "/.ssh/authorized_keys2"} {
			info, err := c.Sys.Stat(h + f)
			if err != nil {
				if os.IsPermission(err) {
					denied = true
				}
				continue
			}
			if !info.ModTime().Before(since) {
				add(Event{Time: info.ModTime(), Kind: "key", Text: "SSH keys of " + path.Base(h) + " changed (" + h + f + ")", Alert: true})
			}
		}
	}
	for _, d := range []string{"/var/spool/cron", "/var/spool/cron/crontabs"} {
		ents, err := c.Sys.ReadDir(d)
		if err != nil {
			if os.IsPermission(err) {
				denied = true
			}
			continue
		}
		for _, e := range ents {
			if info, err := e.Info(); err == nil && !info.IsDir() && !info.ModTime().Before(since) {
				add(Event{Time: info.ModTime(), Kind: "cron", Text: "cron table of " + e.Name() + " changed", Alert: true})
			}
		}
	}
	if denied {
		res.Limited = append(res.Limited, "SSH keys and cron tables of other users")
	}
	// reboots and logins
	if !c.Facts.BootTime.Before(since) {
		add(Event{Time: c.Facts.BootTime, Kind: "boot", Text: "the machine started (kernel " + c.Facts.Kernel + ")"})
	}
	if r := c.Sys.Run(8*time.Second, "last", "--time-format", "iso", "-w", "-n", "200"); r.OK() {
		for _, l := range strings.Split(r.Stdout, "\n") {
			f := strings.Fields(l)
			if len(f) < 4 || f[0] == "wtmp" || f[0] == "reboot" || f[0] == "shutdown" {
				continue
			}
			var t time.Time
			ok := false
			host := ""
			for i := 2; i < len(f) && i < 5; i++ {
				if tt, good := core.ParseISO(f[i]); good {
					t, ok = tt, true
					if i == 3 {
						host = f[2]
					}
					break
				}
			}
			if !ok || t.Before(since) {
				continue
			}
			text := f[0] + " logged in"
			if host != "" && host != ":0" && !strings.HasPrefix(host, ":") {
				text += " from " + host
			}
			text += " (" + f[1] + ")"
			add(Event{Time: t, Kind: "login", Text: text, Alert: f[0] == "root" && host != ""})
		}
	}
	// failed services
	if c.Facts.Systemd {
		r := c.Sys.Run(8*time.Second, "systemctl", "list-units", "--failed", "--all", "--plain", "--no-legend", "--no-pager")
		var ids []string
		for _, l := range strings.Split(r.Stdout, "\n") {
			if f := strings.Fields(l); len(f) > 0 && strings.Contains(f[0], ".") {
				ids = append(ids, f[0])
			}
		}
		for _, u := range checks.ShowUnits(c, ids...) {
			if !u.FailedAt.IsZero() && !u.FailedAt.Before(since) {
				add(Event{Time: u.FailedAt, Kind: "svc", Text: u.ID + " failed: " + checks.Meaning(u)})
			}
		}
	}
	sort.SliceStable(res.Events, func(i, j int) bool { return res.Events[i].Time.Before(res.Events[j].Time) })
	return res
}

// Human writes the timeline.
func Human(w io.Writer, r Result, st render.Style, facts core.Facts, now time.Time, label string) {
	b := func(code, s string) string {
		if !st.Color {
			return s
		}
		return code + s + "\x1b[0m"
	}
	fmt.Fprintf(w, "%s %s\n", b("\x1b[1m", "nabd changes"), b("\x1b[2m", "· "+label+" · "+facts.Hostname))
	if len(r.Events) == 0 {
		fmt.Fprintf(w, "\n %s\n\n", b("\x1b[32m", "nothing changed in this time (packages, /etc, SSH keys, cron, logins, services)"))
		return
	}
	day := ""
	count := map[string]int{}
	alerts := 0
	for _, e := range r.Events {
		lt := e.Time.In(time.Local)
		if d := lt.Format("Mon 2 Jan"); d != day {
			day = d
			fmt.Fprintf(w, "\n %s\n", b("\x1b[1;34m", d))
		}
		mark := " "
		text := e.Text
		if e.Alert {
			mark = b("\x1b[33;1m", "!")
			alerts++
		}
		if e.Kind == "svc" {
			mark = b("\x1b[31;1m", "x")
		}
		fmt.Fprintf(w, "  %s %s %-6s %s\n", b("\x1b[2m", lt.Format("15:04")), mark, e.Kind, text)
		count[e.Kind]++
	}
	var parts []string
	for _, k := range []string{"pkg", "file", "key", "cron", "login", "boot", "svc"} {
		if n := count[k]; n > 0 {
			name := map[string][2]string{"pkg": {"package", "packages"}, "file": {"file", "files"}, "key": {"SSH key change", "SSH key changes"},
				"cron": {"cron change", "cron changes"}, "login": {"login", "logins"}, "boot": {"boot", "boots"}, "svc": {"service failure", "service failures"}}[k]
			parts = append(parts, core.Plural(n, name[0], name[1]))
		}
	}
	fmt.Fprintf(w, "\n %s\n", strings.Join(parts, " · "))
	if alerts == 1 {
		fmt.Fprintf(w, " %s\n", b("\x1b[33m", "1 change marked ! touches security: check that you or your team made it"))
	} else if alerts > 1 {
		fmt.Fprintf(w, " %s\n", b("\x1b[33m", fmt.Sprintf("%d changes marked ! touch security: check that you or your team made them", alerts)))
	}
	if len(r.Limited) > 0 {
		msg := "without root nabd could not read: "
		if facts.Root {
			msg = "nabd could not read: "
		}
		fmt.Fprintf(w, " %s\n", b("\x1b[34m", msg+strings.Join(r.Limited, "; ")))
	}
	fmt.Fprintln(w)
}

// JSON writes the timeline.
func JSON(w io.Writer, r Result, facts core.Facts, version string) error {
	if r.Events == nil {
		r.Events = []Event{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"schema": render.Schema, "version": version, "host": facts, "changes": r})
}

// Markdown writes the timeline for a ticket.
func Markdown(w io.Writer, r Result, facts core.Facts, label string) {
	fmt.Fprintf(w, "## nabd changes — %s (%s)\n\n", facts.Hostname, label)
	if len(r.Events) == 0 {
		fmt.Fprintln(w, "Nothing changed (packages, /etc, SSH keys, cron, logins, services).")
		return
	}
	fmt.Fprintln(w, "| Time | Kind | Change |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, e := range r.Events {
		mark := ""
		if e.Alert {
			mark = "⚠️ "
		}
		fmt.Fprintf(w, "| %s | %s | %s%s |\n", e.Time.In(time.Local).Format("2006-01-02 15:04"), e.Kind, mark, strings.ReplaceAll(e.Text, "|", "\\|"))
	}
	if len(r.Limited) > 0 {
		fmt.Fprintf(w, "\n> without root nabd could not read: %s\n", strings.Join(r.Limited, "; "))
	}
}
