package checks

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Services finds failed systemd units and services that keep restarting.
var Services = core.Check{
	Name:  "services",
	Title: "Services",
	Help:  "Failed systemd units with the reason in plain words (exit code, signal, timeout, OOM), the last log lines, the result of the service's own config test, and the files or packages that changed just before it failed. Also services that keep restarting.",
	Run:   runServices,
}

var unitProps = []string{"Id", "Description", "LoadState", "ActiveState", "SubState", "Result", "UnitFileState",
	"Type", "ExecMainCode", "ExecMainStatus", "MainPID", "NRestarts", "FragmentPath", "DropInPaths",
	"InactiveEnterTimestampMonotonic", "ActiveEnterTimestampMonotonic", "ExecMainExitTimestampMonotonic",
	"ExecStart", "MemoryCurrent", "CPUUsageNSec", "User"}

// Unit is what systemctl show says about a unit.
type Unit struct {
	ID, Description, LoadState, ActiveState, SubState, Result, FileState, Type, User string
	MainCode, MainStatus, MainPID, Restarts                                          int
	Fragment                                                                         string
	DropIns                                                                          []string
	FailedAt, ActiveSince                                                            time.Time
	ExecPath                                                                         string
	Memory, CPUNsec                                                                  uint64
}

// Base is "nginx" for "nginx.service".
func (u Unit) Base() string {
	b := u.ID
	if i := strings.LastIndexByte(b, '.'); i > 0 {
		b = b[:i]
	}
	if i := strings.IndexByte(b, '@'); i > 0 {
		b = b[:i]
	}
	return b
}

// Kind is "service", "mount", "timer" …
func (u Unit) Kind() string {
	if i := strings.LastIndexByte(u.ID, '.'); i > 0 {
		return u.ID[i+1:]
	}
	return ""
}

var execPathRe = regexp.MustCompile(`path=([^ ;]+)`)

// ShowUnits runs one systemctl show for many units.
func ShowUnits(c *core.Ctx, ids ...string) []Unit {
	if len(ids) == 0 {
		return nil
	}
	args := append([]string{"show", "--no-pager", "--property=" + strings.Join(unitProps, ",")}, ids...)
	r := c.Sys.Run(10*time.Second, "systemctl", args...)
	if !r.OK() && strings.TrimSpace(r.Stdout) == "" {
		return nil
	}
	var out []Unit
	for _, kv := range linux.KVBlocks(r.Stdout) {
		if kv["Id"] == "" {
			continue
		}
		u := Unit{ID: kv["Id"], Description: kv["Description"], LoadState: kv["LoadState"], ActiveState: kv["ActiveState"],
			SubState: kv["SubState"], Result: kv["Result"], FileState: kv["UnitFileState"], Type: kv["Type"],
			Fragment: kv["FragmentPath"], DropIns: strings.Fields(kv["DropInPaths"]), User: kv["User"]}
		u.MainCode, _ = strconv.Atoi(kv["ExecMainCode"])
		u.MainStatus, _ = strconv.Atoi(kv["ExecMainStatus"])
		u.MainPID, _ = strconv.Atoi(kv["MainPID"])
		u.Restarts, _ = strconv.Atoi(kv["NRestarts"])
		u.Memory, _ = strconv.ParseUint(kv["MemoryCurrent"], 10, 64)
		u.CPUNsec, _ = strconv.ParseUint(kv["CPUUsageNSec"], 10, 64)
		u.FailedAt = monoTime(c, kv["InactiveEnterTimestampMonotonic"])
		if t := monoTime(c, kv["ExecMainExitTimestampMonotonic"]); u.FailedAt.IsZero() || (!t.IsZero() && t.Before(u.FailedAt) && u.ActiveState == "failed") {
			if !t.IsZero() {
				u.FailedAt = t
			}
		}
		u.ActiveSince = monoTime(c, kv["ActiveEnterTimestampMonotonic"])
		if m := execPathRe.FindStringSubmatch(kv["ExecStart"]); m != nil {
			u.ExecPath = m[1]
		}
		out = append(out, u)
	}
	return out
}

func monoTime(c *core.Ctx, us string) time.Time {
	n, err := strconv.ParseUint(us, 10, 64)
	if err != nil || n == 0 {
		return time.Time{}
	}
	return c.Facts.BootTime.Add(time.Duration(n) * time.Microsecond)
}

var signalNames = map[int]string{1: "SIGHUP", 2: "SIGINT", 3: "SIGQUIT", 4: "SIGILL", 6: "SIGABRT", 7: "SIGBUS",
	8: "SIGFPE", 9: "SIGKILL", 11: "SIGSEGV", 13: "SIGPIPE", 14: "SIGALRM", 15: "SIGTERM"}

// systemd's own exit codes (systemd.exec(5), "Process exit codes").
var systemdCodes = map[int]string{
	200: "the WorkingDirectory= folder does not exist (exit 200/CHDIR)",
	203: "the program in ExecStart= was not found or cannot run (exit 203/EXEC): check the path and the x permission",
	204: "out of memory while starting (exit 204/MEMORY)",
	205: "a resource limit (Limit…=) could not be set (exit 205/LIMITS)",
	208: "standard input could not be set up (exit 208/STDIN)",
	209: "standard output could not be set up, often a missing log file folder (exit 209/STDOUT)",
	210: "the RootDirectory= chroot failed (exit 210/CHROOT)",
	214: "the CPU scheduling settings failed (exit 214/SETSCHEDULER)",
	216: "the group in Group= does not exist (exit 216/GROUP)",
	217: "the user in User= does not exist (exit 217/USER)",
	218: "capabilities could not be set (exit 218/CAPABILITIES)",
	219: "the cgroup could not be set up (exit 219/CGROUP)",
	222: "standard error could not be set up (exit 222/STDERR)",
	224: "the PAM session failed (exit 224/PAM)",
	226: "a sandbox setting failed, often a path in ReadWritePaths= or PrivateTmp that does not exist (exit 226/NAMESPACE)",
	228: "the seccomp filter (SystemCallFilter=) failed (exit 228/SECCOMP)",
	229: "the SELinux context could not be set (exit 229/SELINUX_CONTEXT)",
	231: "the AppArmor profile could not be set (exit 231/APPARMOR)",
	233: "the RuntimeDirectory= could not be made (exit 233/RUNTIME_DIRECTORY)",
	235: "files could not be given to the service user (exit 235/CHOWN)",
	238: "the StateDirectory= could not be made (exit 238/STATE_DIRECTORY)",
	240: "the LogsDirectory= could not be made (exit 240/LOGS_DIRECTORY)",
	243: "the credentials (LoadCredential=) could not be read (exit 243/CREDENTIALS)",
}

// Meaning says in plain words why a unit stopped.
func Meaning(u Unit) string {
	switch u.Result {
	case "start-limit-hit":
		return "it failed and restarted too often, so systemd stopped trying (start limit)"
	case "timeout":
		return "it did not finish starting or stopping in time (TimeoutStartSec / TimeoutStopSec)"
	case "oom-kill":
		return "the kernel killed it because memory ran out (OOM)"
	case "watchdog":
		return "it stopped answering the systemd watchdog (it hung)"
	case "resources":
		return "systemd could not prepare what it needs: a missing folder, user, file or socket"
	case "protocol":
		return "it never told systemd that it was ready (check Type= and PIDFile= in the unit)"
	case "exec-condition", "condition":
		return "a condition in the unit was not met"
	case "core-dump":
		return fmt.Sprintf("it crashed with %s and dumped core (coredumpctl info %d shows where)", sig(u.MainStatus), u.MainPID)
	case "signal":
		switch u.MainStatus {
		case 9:
			return "it was killed with SIGKILL: often the OOM killer or a manual kill -9"
		case 11:
			return "it crashed: segmentation fault (SIGSEGV), a bug or a broken library"
		case 6:
			return "it aborted itself (SIGABRT): usually a fatal error it wrote to the log just before"
		case 7:
			return "it crashed with SIGBUS: often a full disk or a file that changed under it"
		}
		return "it was stopped by " + sig(u.MainStatus)
	}
	if u.MainCode == 1 && u.MainStatus != 0 { // exited
		if m, ok := systemdCodes[u.MainStatus]; ok {
			return m
		}
		switch u.MainStatus {
		case 1:
			return "the program stopped with an error (exit code 1); its log lines say which"
		case 2:
			return "exit code 2: usually a wrong option or a config error"
		case 78:
			return "exit code 78: configuration error"
		case 126:
			return "exit code 126: the program file cannot run (permission)"
		case 127:
			return "exit code 127: a command in the start line was not found"
		case 137:
			return "exit code 137: killed with SIGKILL (often out of memory)"
		case 143:
			return "exit code 143: stopped with SIGTERM"
		}
		return fmt.Sprintf("the program stopped with exit code %d", u.MainStatus)
	}
	if u.Result == "exit-code" {
		return "a start or stop command of the unit failed"
	}
	return ""
}

func sig(n int) string {
	if s, ok := signalNames[n]; ok {
		return s
	}
	return "signal " + strconv.Itoa(n)
}

// ConfigTest is a service's own read-only config check (nginx -t …).
type ConfigTest struct {
	Command string   `json:"command"`
	OK      bool     `json:"ok"`
	Errors  []string `json:"errors,omitempty"`
	NoRoot  bool     `json:"needs_root,omitempty"`
}

type cfgTest struct {
	names []string
	bin   string
	args  []string
	dirs  []string
}

var cfgTests = []cfgTest{
	{[]string{"nginx"}, "nginx", []string{"-t"}, []string{"/etc/nginx"}},
	{[]string{"httpd", "apache2"}, "apachectl", []string{"-t"}, []string{"/etc/httpd", "/etc/apache2"}},
	{[]string{"sshd", "ssh"}, "sshd", []string{"-t"}, []string{"/etc/ssh"}},
	{[]string{"haproxy"}, "haproxy", []string{"-c", "-f", "/etc/haproxy/haproxy.cfg"}, []string{"/etc/haproxy"}},
	{[]string{"named", "bind9"}, "named-checkconf", nil, []string{"/etc/named.conf", "/etc/named", "/etc/bind"}},
	{[]string{"dovecot"}, "doveconf", []string{"-n"}, []string{"/etc/dovecot"}},
	{[]string{"php-fpm"}, "php-fpm", []string{"-t"}, []string{"/etc/php-fpm.conf", "/etc/php-fpm.d", "/etc/php"}},
	{[]string{"squid"}, "squid", []string{"-k", "parse"}, []string{"/etc/squid"}},
	{[]string{"dnsmasq"}, "dnsmasq", []string{"--test"}, []string{"/etc/dnsmasq.conf", "/etc/dnsmasq.d"}},
	{[]string{"unbound"}, "unbound-checkconf", nil, []string{"/etc/unbound"}},
	{[]string{"keepalived"}, "keepalived", []string{"-t"}, []string{"/etc/keepalived"}},
	// adapt only parses the Caddyfile; "caddy validate" would provision modules and storage
	{[]string{"caddy"}, "caddy", []string{"adapt", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"}, []string{"/etc/caddy"}},
}

// Only tests that read are in cfgTests. "postfix check" can create folders and
// "varnishd -C" compiles code, so those services get their config folders only.

// extra config folders for services without a config test
var cfgDirs = map[string][]string{
	"mysqld": {"/etc/my.cnf", "/etc/my.cnf.d", "/etc/mysql"}, "mariadb": {"/etc/my.cnf", "/etc/my.cnf.d", "/etc/mysql"},
	"mysql": {"/etc/mysql", "/etc/my.cnf"}, "postgresql": {"/etc/postgresql", "/var/lib/pgsql/data/postgresql.conf", "/var/lib/pgsql/data/pg_hba.conf"},
	"redis": {"/etc/redis", "/etc/redis.conf"}, "redis-server": {"/etc/redis"}, "docker": {"/etc/docker"},
	"containerd": {"/etc/containerd"}, "chronyd": {"/etc/chrony.conf", "/etc/chrony"}, "chrony": {"/etc/chrony"},
	"firewalld": {"/etc/firewalld"}, "NetworkManager": {"/etc/NetworkManager"}, "kubelet": {"/etc/kubernetes", "/var/lib/kubelet/config.yaml"},
	"postfix": {"/etc/postfix"}, "varnish": {"/etc/varnish"},
	"grafana-server": {"/etc/grafana"}, "prometheus": {"/etc/prometheus"}, "elasticsearch": {"/etc/elasticsearch"},
	"rabbitmq-server": {"/etc/rabbitmq"}, "mongod": {"/etc/mongod.conf"}, "memcached": {"/etc/sysconfig/memcached", "/etc/memcached.conf"},
	"fail2ban": {"/etc/fail2ban"}, "rsyslog": {"/etc/rsyslog.conf", "/etc/rsyslog.d"}, "cron": {"/etc/crontab"}, "crond": {"/etc/crontab"},
	"systemd-resolved": {"/etc/systemd/resolved.conf"}, "systemd-networkd": {"/etc/systemd/network"},
}

func testFor(base string) (cfgTest, bool) {
	for _, t := range cfgTests {
		for _, n := range t.names {
			if base == n {
				return t, true
			}
		}
	}
	// php8.2-fpm (Debian) -> php-fpm8.2
	if m := regexp.MustCompile(`^php(\d+\.\d+)-fpm$`).FindStringSubmatch(base); m != nil {
		return cfgTest{[]string{base}, "php-fpm" + m[1], []string{"-t"}, []string{"/etc/php/" + m[1] + "/fpm"}}, true
	}
	return cfgTest{}, false
}

var cfgErrRe = regexp.MustCompile(`(?i)\[emerg\]|error|invalid|unknown|failed|not found|syntax|cannot|could not|unexpected|denied|fatal|alert`)

// RunConfigTest runs the service's own config check, if it has one.
func RunConfigTest(c *core.Ctx, base string) *ConfigTest {
	t, ok := testFor(base)
	if !ok {
		return nil
	}
	bin := t.bin
	if !c.Sys.Has(bin) {
		if bin == "apachectl" && c.Sys.Has("apache2ctl") {
			bin = "apache2ctl"
		} else {
			return nil
		}
	}
	r := c.Sys.Run(10*time.Second, bin, t.args...)
	ct := &ConfigTest{Command: strings.TrimSpace(bin + " " + strings.Join(t.args, " ")), OK: r.OK()}
	if r.NotFound || r.TimedOut {
		return nil
	}
	if !ct.OK {
		for _, l := range strings.Split(r.Output(), "\n") {
			l = strings.TrimSpace(l)
			if l == "" || !cfgErrRe.MatchString(l) {
				continue
			}
			if strings.Contains(strings.ToLower(l), "permission denied") && !c.Facts.Root {
				ct.NoRoot = true
				continue
			}
			ct.Errors = append(ct.Errors, core.Clip(l, 200))
			if len(ct.Errors) == 3 {
				break
			}
		}
		if len(ct.Errors) == 0 && ct.NoRoot {
			ct.OK = true // only failed because we are not root
		}
	}
	return ct
}

// ConfigPaths lists the files that configure a unit (unit file, drop-ins, its /etc folders).
func ConfigPaths(u Unit) []string {
	var out []string
	if u.Fragment != "" {
		out = append(out, u.Fragment)
	}
	out = append(out, u.DropIns...)
	out = append(out, "/etc/systemd/system/"+u.ID+".d")
	base := u.Base()
	if t, ok := testFor(base); ok {
		out = append(out, t.dirs...)
	}
	out = append(out, cfgDirs[base]...)
	out = append(out, "/etc/default/"+base, "/etc/sysconfig/"+base)
	if u.ExecPath != "" {
		out = append(out, u.ExecPath)
	}
	return out
}

// Change is something that changed shortly before a time.
type Change struct {
	Time time.Time `json:"time"`
	What string    `json:"what"`
}

// ChangesBefore finds config files and packages of a unit that changed in the
// day before t (and up to a minute after).
func ChangesBefore(c *core.Ctx, u Unit, t time.Time) []Change {
	if t.IsZero() {
		return nil
	}
	from, to := t.Add(-24*time.Hour), t.Add(time.Minute)
	var out []Change
	for _, fc := range core.ModTimeInside(c.Sys, ConfigPaths(u), from, to, 5, 2*time.Second) {
		out = append(out, Change{fc.Time, "file " + fc.Path + " changed"})
	}
	evs, _ := c.PkgEvents()
	base := strings.ToLower(u.Base())
	related := map[string]bool{}
	if u.ExecPath != "" {
		related[strings.ToLower(path.Base(u.ExecPath))] = true
	}
	n := 0
	for i := len(evs) - 1; i >= 0 && n < 5; i-- {
		e := evs[i]
		if e.Time.Before(from) || e.Time.After(to) {
			continue
		}
		name := strings.ToLower(e.Name)
		near := t.Sub(e.Time) <= 30*time.Minute
		if near || strings.Contains(name, base) || strings.Contains(base, name) || related[name] {
			out = append(out, Change{e.Time, "package " + PkgEventText(e)})
			n++
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 6 {
		out = out[:6]
	}
	return out
}

// PkgEventText is "nginx upgraded 1.24.0-1 → 1.26.1-1".
func PkgEventText(e core.PkgEvent) string {
	switch e.Action {
	case "upgrade", "downgrade":
		if e.From != "" {
			return fmt.Sprintf("%s %sd %s → %s", e.Name, e.Action, e.From, e.To)
		}
		return fmt.Sprintf("%s %sd to %s", e.Name, e.Action, e.To)
	case "install":
		return fmt.Sprintf("%s installed (%s)", e.Name, e.To)
	case "remove":
		return fmt.Sprintf("%s removed (%s)", e.Name, e.From)
	}
	return fmt.Sprintf("%s %s %s", e.Name, e.Action, e.To)
}

var noiseRe = regexp.MustCompile(`^(Started|Starting|Stopped|Stopping|Reloading|Reloaded|Finished|Deactivated successfully|Consumed|Scheduled restart job|Failed to start|Failed with result|Main process exited|Unit entered failed state|.*\.service: )`)

// UnitLogs returns the last useful log lines of a unit in this boot.
func UnitLogs(c *core.Ctx, id string, n int) (lines []string, limited bool) {
	r := c.Sys.Run(8*time.Second, "journalctl", "-u", id, "-b", "-n", strconv.Itoa(n*4), "-o", "cat", "--no-pager", "-q")
	if !r.OK() && strings.TrimSpace(r.Stdout) == "" {
		return nil, !c.Facts.Root
	}
	all := strings.Split(strings.TrimSpace(r.Stdout), "\n")
	for i := len(all) - 1; i >= 0 && len(lines) < n; i-- {
		l := strings.TrimSpace(all[i])
		if l == "" || noiseRe.MatchString(l) {
			continue
		}
		lines = append([]string{core.Clip(l, 160)}, lines...)
	}
	if len(lines) == 0 && strings.TrimSpace(r.Stdout) == "" && !c.Facts.Root {
		limited = true
	}
	return lines, limited
}

// Explain builds the full story of one unit: why it stopped, what changed, what to run.
// errAtRe finds "FILE:LINE" in an error of a config test.
var errAtRe = regexp.MustCompile(`(/[^\s:"']+):(\d+)`)

func Explain(c *core.Ctx, u Unit) (why []string, fix []string, ct *ConfigTest, limited []string) {
	now := c.Sys.Now()
	if m := Meaning(u); m != "" {
		why = append(why, m)
	}
	ct = RunConfigTest(c, u.Base())
	shown := map[string]bool{}
	where := ""
	if ct != nil && !ct.OK {
		var keep []string
		for _, e := range ct.Errors {
			le := strings.ToLower(e)
			if len(ct.Errors) > 1 && (strings.Contains(le, "test failed") || strings.Contains(le, "test is failed")) {
				continue // the summary line says nothing new
			}
			keep = append(keep, e)
		}
		for i, e := range keep {
			if i == 2 {
				break
			}
			why = append(why, "config test ("+ct.Command+"): "+e)
			shown[strings.TrimSpace(e)] = true
			if m := errAtRe.FindStringSubmatch(e); m != nil && where == "" {
				where = m[1] + ", line " + m[2]
			}
		}
	}
	if ct != nil && ct.NoRoot {
		limited = append(limited, "config test of "+u.Base())
	}
	when := u.FailedAt
	if when.IsZero() {
		when = now
	}
	for _, ch := range ChangesBefore(c, u, when) {
		rel := "before it failed"
		if ch.Time.After(when) {
			rel = "after it failed"
		}
		why = append(why, fmt.Sprintf("%s %s %s (%s)", ch.What, core.Duration(when.Sub(ch.Time)), rel, ch.Time.Format("15:04")))
	}
	logs, lim := UnitLogs(c, u.ID, 3)
	for _, l := range logs {
		if shown[strings.TrimSpace(l)] {
			continue
		}
		why = append(why, "log: "+l)
	}
	if lim {
		limited = append(limited, "logs of "+u.ID)
	}
	sudo := c.Sudo()
	if ct != nil {
		if b, _ := testFor(u.Base()); b.bin != "" {
			if where != "" {
				fix = append(fix, "# the error is in "+where)
			}
			fix = append(fix, sudo+ct.Command+"   # must say OK before you restart")
		}
	}
	if u.Result == "start-limit-hit" {
		fix = append(fix, sudo+"systemctl reset-failed "+u.ID)
	}
	if u.Kind() == "service" || u.Kind() == "mount" || u.Kind() == "socket" {
		fix = append(fix, sudo+"systemctl restart "+u.ID)
	}
	fix = append(fix, "journalctl -u "+u.ID+" -b -e")
	return why, fix, ct, limited
}

func runServices(c *core.Ctx, o *core.Out) {
	if !c.Facts.Systemd {
		o.Skip("no systemd on this machine")
		return
	}
	r := c.Sys.Run(8*time.Second, "systemctl", "list-units", "--failed", "--all", "--plain", "--no-legend", "--no-pager")
	if r.NotFound {
		o.Skip("systemctl is not installed")
		return
	}
	var failed []string
	for _, l := range strings.Split(r.Stdout, "\n") {
		if f := strings.Fields(strings.TrimPrefix(strings.TrimSpace(l), "●")); len(f) > 0 && strings.Contains(f[0], ".") {
			failed = append(failed, f[0])
		}
	}
	if len(failed) > 10 {
		failed = failed[:10]
	}
	now := c.Sys.Now()
	for _, u := range ShowUnits(c, failed...) {
		why, fix, _, lim := Explain(c, u)
		for _, l := range lim {
			o.Limit(l)
		}
		sev := core.Warn
		switch {
		case u.Kind() == "mount" || u.Kind() == "swap" || u.Kind() == "automount":
			sev = core.Crit
		case u.Kind() == "service" && u.Type != "oneshot" && strings.HasPrefix(u.FileState, "enabled"):
			sev = core.Crit
		}
		title := u.ID + " failed"
		if !u.FailedAt.IsZero() {
			title += " " + core.Ago(now, u.FailedAt)
		}
		fix = append(fix, "nabd why service "+u.Base())
		o.Add(core.Finding{ID: "failed", Severity: sev, Title: title, Why: why, Fix: fix,
			Data: map[string]interface{}{"unit": u.ID, "result": u.Result, "exit_code": u.MainCode, "exit_status": u.MainStatus,
				"failed_at": u.FailedAt, "unit_file_state": u.FileState}})
	}
	// services that keep restarting
	rr := c.Sys.Run(8*time.Second, "systemctl", "list-units", "--type=service", "--state=running", "--plain", "--no-legend", "--no-pager")
	var running []string
	for _, l := range strings.Split(rr.Stdout, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.HasSuffix(f[0], ".service") {
			running = append(running, f[0])
		}
	}
	for _, u := range ShowUnits(c, running...) {
		if u.Restarts >= 5 {
			why := []string{"it crashes and systemd starts it again (Restart=)"}
			logs, _ := UnitLogs(c, u.ID, 2)
			for _, l := range logs {
				why = append(why, "log: "+l)
			}
			o.Add(core.Finding{ID: "restarts", Severity: core.Warn,
				Title: fmt.Sprintf("%s restarted %d times since boot", u.ID, u.Restarts), Why: why,
				Fix:  []string{"nabd why service " + u.Base(), "journalctl -u " + u.ID + " -b -e"},
				Data: map[string]interface{}{"unit": u.ID, "restarts": u.Restarts}})
		}
	}
	o.OK("%s running, %s failed", core.Plural(len(running), "service", "services"), core.Plural(len(failed), "unit", "units"))
}
