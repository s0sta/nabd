package core

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/linux"
	"github.com/s0sta/nabd/internal/sys"
)

// ---------------------------------------------------------------- processes

// Proc is one process.
type Proc struct {
	linux.ProcStat
	UID int
}

// Procs lists all processes (read once).
func (c *Ctx) Procs() []Proc {
	c.onceProcs.Do(func() { c.procs = ReadProcs(c.Sys) })
	return c.procs
}

// ReadProcs reads /proc/<pid>/stat and the Uid of every process now.
func ReadProcs(s sys.Sys) []Proc {
	var out []Proc
	for _, pid := range PIDs(s) {
		b, err := s.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
		if err != nil {
			continue
		}
		st, err := linux.ParseProcStat(b)
		if err != nil {
			continue
		}
		p := Proc{ProcStat: st, UID: -1}
		if isDigits(p.Comm) {
			// a process that renamed itself to a number: the program name is clearer
			if cb, err := s.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline"); err == nil {
				if argv0 := strings.SplitN(string(cb), "\x00", 2)[0]; argv0 != "" {
					p.Comm = path.Base(strings.Fields(argv0 + " x")[0])
				}
			}
		}
		if sb, err := s.ReadFile("/proc/" + strconv.Itoa(pid) + "/status"); err == nil {
			if f := strings.Fields(linux.Status(sb)["Uid"]); len(f) > 0 {
				p.UID, _ = strconv.Atoi(f[0])
			}
		}
		out = append(out, p)
	}
	return out
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// PIDs lists the process ids in /proc.
func PIDs(s sys.Sys) []int {
	ents, err := s.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var out []int
	for _, e := range ents {
		if n, err := strconv.Atoi(e.Name()); err == nil {
			out = append(out, n)
		}
	}
	sort.Ints(out)
	return out
}

// ProcName is the program name of a process: the cmdline basename when it is
// short and clear, else the kernel comm.
func (c *Ctx) ProcName(pid int) string {
	b, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	name := strings.TrimSpace(string(b))
	if err != nil || name == "" {
		return "pid " + strconv.Itoa(pid)
	}
	return name
}

// Cmdline is the command line of a process, or "".
func (c *Ctx) Cmdline(pid int) string {
	b, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
}

// UnitOf returns the systemd unit (or container) that a process belongs to.
func (c *Ctx) UnitOf(pid int) (unit, container string) {
	b, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/cgroup")
	if err != nil {
		return "", ""
	}
	return linux.CgroupUnit(b)
}

// Owner is a short "nginx (pid 812, nginx.service)" description of a process.
func (c *Ctx) Owner(pid int) string {
	if pid <= 0 {
		return "an unknown process"
	}
	s := c.ProcName(pid) + " (pid " + strconv.Itoa(pid)
	unit, cont := c.UnitOf(pid)
	switch {
	case unit != "":
		s += ", " + unit
	case cont != "":
		s += ", " + cont + " container"
	}
	return s + ")"
}

// ---------------------------------------------------------------- kernel log

// KLine is one kernel log line.
type KLine struct {
	Time time.Time
	Text string
}

// KernelLog is the kernel log since boot.
type KernelLog struct {
	Lines   []KLine
	Source  string
	Limited bool // could not read it (needs root or the adm / systemd-journal group)
}

// Kernel reads the kernel log of this boot (once).
func (c *Ctx) Kernel() KernelLog {
	c.onceKlog.Do(func() { c.klog = readKernelLog(c) })
	return c.klog
}

var (
	isoRe    = regexp.MustCompile(`^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:[.,]\d+)?(Z|[+-]\d\d:?\d\d)?$`)
	syslogRe = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d) \S+ kernel: (?:\[\s*[\d.]+\] )?(.*)$`)
)

// ParseISO reads the timestamps of journalctl -o short-iso, dmesg --time-format iso and rsyslog.
func ParseISO(s string) (time.Time, bool) {
	m := isoRe.FindStringSubmatch(s)
	if m == nil {
		return time.Time{}, false
	}
	zone := m[2]
	switch {
	case zone == "":
		t, err := time.ParseInLocation("2006-01-02T15:04:05", m[1], time.Local)
		return t, err == nil
	case zone == "Z":
		zone = "+00:00"
	case !strings.Contains(zone, ":"):
		zone = zone[:3] + ":" + zone[3:]
	}
	t, err := time.Parse("2006-01-02T15:04:05-07:00", m[1]+zone)
	return t, err == nil
}

func readKernelLog(c *Ctx) KernelLog {
	s := c.Sys
	if c.Facts.Systemd || s.Has("journalctl") {
		r := s.Run(10*time.Second, "journalctl", "-k", "-b", "-o", "short-iso", "--no-pager", "-q")
		if r.OK() && strings.TrimSpace(r.Stdout) != "" {
			var out []KLine
			for _, l := range strings.Split(r.Stdout, "\n") {
				f := strings.SplitN(l, " ", 3)
				if len(f) < 3 {
					continue
				}
				t, ok := ParseISO(f[0])
				if !ok {
					continue
				}
				text := f[2]
				if i := strings.Index(text, "kernel: "); i >= 0 && i < 12 {
					text = text[i+8:]
				}
				out = append(out, KLine{t, text})
			}
			if len(out) > 0 {
				return KernelLog{Lines: out, Source: "journalctl -k -b"}
			}
		}
	}
	if r := s.Run(5*time.Second, "dmesg", "--time-format", "iso"); r.OK() && strings.TrimSpace(r.Stdout) != "" {
		var out []KLine
		for _, l := range strings.Split(r.Stdout, "\n") {
			ts, text, ok := strings.Cut(l, " ")
			if !ok {
				continue
			}
			if t, ok := ParseISO(ts); ok {
				out = append(out, KLine{t, text})
			}
		}
		if len(out) > 0 {
			return KernelLog{Lines: out, Source: "dmesg"}
		}
	}
	for _, p := range []string{"/var/log/kern.log", "/var/log/messages", "/var/log/syslog"} {
		b, err := s.ReadFile(p)
		if err != nil {
			continue
		}
		if len(b) > 32<<20 {
			b = b[len(b)-32<<20:]
		}
		var out []KLine
		year := s.Now().Year()
		for _, l := range linux.Lines(b) {
			if m := syslogRe.FindStringSubmatch(l); m != nil {
				t, err := time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(year)+" "+m[1], time.Local)
				if err != nil {
					continue
				}
				if t.After(s.Now().Add(24 * time.Hour)) {
					t = t.AddDate(-1, 0, 0)
				}
				if t.Before(c.Facts.BootTime.Add(-time.Minute)) {
					continue
				}
				out = append(out, KLine{t, m[2]})
				continue
			}
			ts, rest, ok := strings.Cut(l, " ")
			if !ok || !strings.Contains(rest, " kernel: ") {
				continue
			}
			t, ok := ParseISO(ts)
			if !ok || t.Before(c.Facts.BootTime.Add(-time.Minute)) {
				continue
			}
			text := rest[strings.Index(rest, " kernel: ")+9:]
			if strings.HasPrefix(text, "[") {
				if i := strings.Index(text, "] "); i > 0 {
					text = text[i+2:]
				}
			}
			out = append(out, KLine{t, text})
		}
		return KernelLog{Lines: out, Source: p}
	}
	return KernelLog{Limited: !c.Facts.Root}
}

// Grep returns the kernel lines that match re.
func (k KernelLog) Grep(re *regexp.Regexp) []KLine {
	var out []KLine
	for _, l := range k.Lines {
		if re.MatchString(l.Text) {
			out = append(out, l)
		}
	}
	return out
}

// ---------------------------------------------------------------- mounts

// MountUsage is a local file system with its size.
type MountUsage struct {
	linux.Mount
	St       sys.Statfs
	Err      string
	Pct      float64 // like df: used / (used + available)
	InodePct float64
}

// Used is the used space in bytes.
func (m MountUsage) Used() uint64 {
	if m.St.Size < m.St.Free {
		return 0
	}
	return m.St.Size - m.St.Free
}

var realFS = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true, "xfs": true, "btrfs": true, "zfs": true, "f2fs": true,
	"jfs": true, "reiserfs": true, "vfat": true, "exfat": true, "ntfs": true, "ntfs3": true,
	"bcachefs": true, "fuseblk": true,
}

// Mounts lists the local file systems with their usage (read once).
func (c *Ctx) Mounts() []MountUsage {
	c.onceMounts.Do(func() { c.mounts = readMounts(c) })
	return c.mounts
}

// AllMounts reads the mount table.
func (c *Ctx) AllMounts() []linux.Mount {
	if b, err := c.Sys.ReadFile("/proc/self/mountinfo"); err == nil {
		if ms := linux.Mountinfo(b); len(ms) > 0 {
			return ms
		}
	}
	b, _ := c.Sys.ReadFile("/proc/mounts")
	return linux.Mounts(b)
}

func readMounts(c *Ctx) []MountUsage {
	var picked []linux.Mount
	seen := map[string]int{}
	for _, m := range c.AllMounts() {
		ok := realFS[m.FSType] || (m.FSType == "overlay" && m.Point == "/")
		if !ok {
			continue
		}
		if strings.HasPrefix(m.Point, "/proc") || strings.HasPrefix(m.Point, "/sys") ||
			strings.HasPrefix(m.Point, "/dev") || strings.HasPrefix(m.Point, "/run") ||
			strings.HasPrefix(m.Point, "/snap/") || strings.HasPrefix(m.Point, "/var/lib/docker/") ||
			strings.HasPrefix(m.Point, "/var/lib/containers/storage/") {
			continue
		}
		key := m.Dev
		if m.FSType == "btrfs" || m.FSType == "zfs" {
			key = m.Source
		}
		if i, ok := seen[key]; ok {
			if len(m.Point) < len(picked[i].Point) {
				picked[i] = m
			}
			continue
		}
		seen[key] = len(picked)
		picked = append(picked, m)
	}
	out := make([]MountUsage, len(picked))
	done := make(chan int, len(picked))
	for i := range picked {
		out[i].Mount = picked[i]
		go func(i int) {
			st, err := c.Sys.Statfs(out[i].Point)
			if err != nil {
				out[i].Err = err.Error()
			} else {
				out[i].St = st
			}
			done <- i
		}(i)
	}
	timeout := time.After(4 * time.Second)
	answered := map[int]bool{}
wait:
	for len(answered) < len(picked) {
		select {
		case i := <-done:
			answered[i] = true
		case <-timeout:
			break wait
		}
	}
	var res []MountUsage
	for i := range out {
		m := out[i]
		if !answered[i] {
			m = MountUsage{Mount: picked[i], Err: "did not answer in 4 s"}
		} else if m.Err == "" {
			used := m.Used()
			if d := used + m.St.Avail; d > 0 {
				m.Pct = float64(used) * 100 / float64(d)
			}
			if m.St.Files > 0 {
				m.InodePct = float64(m.St.Files-m.St.FilesFree) * 100 / float64(m.St.Files)
			}
		}
		res = append(res, m)
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Point < res[j].Point })
	return res
}

// MountOf finds the mount that holds path (longest matching mount point).
func MountOf(ms []linux.Mount, p string) linux.Mount {
	var best linux.Mount
	for _, m := range ms {
		if m.Point == p || m.Point == "/" || strings.HasPrefix(p, strings.TrimSuffix(m.Point, "/")+"/") {
			if len(m.Point) > len(best.Point) {
				best = m
			}
		}
	}
	return best
}

// ---------------------------------------------------------------- sockets

// Listener is a listening socket and the process behind it.
type Listener struct {
	linux.Socket
	PID       int
	Process   string
	Unit      string
	Container string
}

// Listeners lists listening sockets (read once). full is false when some
// sockets belong to processes this user cannot see.
func (c *Ctx) Listeners() (ls []Listener, full bool) {
	c.onceSock.Do(func() { c.socks, c.sockFull = readListeners(c) })
	return c.socks, c.sockFull
}

func readListeners(c *Ctx) ([]Listener, bool) {
	var socks []linux.Socket
	for _, p := range []string{"tcp", "tcp6", "udp", "udp6"} {
		if b, err := c.Sys.ReadFile("/proc/net/" + p); err == nil {
			for _, s := range linux.NetSockets(p, b) {
				if s.Listening() {
					socks = append(socks, s)
				}
			}
		}
	}
	want := map[uint64]bool{}
	for _, s := range socks {
		want[s.Inode] = true
	}
	owner := map[uint64]int{}
	for _, pid := range PIDs(c.Sys) {
		dir := "/proc/" + strconv.Itoa(pid) + "/fd"
		ents, err := c.Sys.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range ents {
			t, err := c.Sys.Readlink(dir + "/" + e.Name())
			if err != nil || !strings.HasPrefix(t, "socket:[") {
				continue
			}
			ino, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimPrefix(t, "socket:["), "]"), 10, 64)
			if want[ino] {
				if _, ok := owner[ino]; !ok {
					owner[ino] = pid
				}
			}
		}
	}
	full := true
	var out []Listener
	for _, s := range socks {
		l := Listener{Socket: s}
		if pid, ok := owner[s.Inode]; ok {
			l.PID = pid
			l.Process = c.ProcName(pid)
			l.Unit, l.Container = c.UnitOf(pid)
		} else if s.Inode != 0 {
			full = false
		}
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Port != out[j].Port {
			return out[i].Port < out[j].Port
		}
		return out[i].Proto < out[j].Proto
	})
	return out, full
}

// ---------------------------------------------------------------- package history

// PkgEvent is one package change from the package manager logs.
type PkgEvent struct {
	Time   time.Time `json:"time"`
	Action string    `json:"action"` // install, upgrade, downgrade, remove, reinstall
	Name   string    `json:"name"`
	From   string    `json:"from,omitempty"`
	To     string    `json:"to,omitempty"`
}

// PkgEvents reads the package history from the logs (once), oldest first.
func (c *Ctx) PkgEvents() ([]PkgEvent, string) {
	c.oncePkg.Do(func() { c.pkgEvents, c.pkgSource = ReadPkgEvents(c.Sys) })
	return c.pkgEvents, c.pkgSource
}

// ReadPkgEvents parses dnf, dpkg, pacman and zypper logs (with rotated copies).
func ReadPkgEvents(s sys.Sys) ([]PkgEvent, string) {
	type src struct {
		files []string
		parse func([]byte) []PkgEvent
		name  string
	}
	srcs := []src{
		{[]string{"/var/log/dnf.rpm.log"}, ParseDnfLog, "dnf"},
		{[]string{"/var/log/dpkg.log"}, ParseDpkgLog, "dpkg"},
		{[]string{"/var/log/pacman.log"}, ParsePacmanLog, "pacman"},
		{[]string{"/var/log/zypp/history"}, ParseZyppHistory, "zypper"},
	}
	var all []PkgEvent
	var names []string
	for _, sc := range srcs {
		var got []PkgEvent
		for _, f := range sc.files {
			for _, cand := range rotated(s, f) {
				if b := readMaybeGz(s, cand); b != nil {
					got = append(got, sc.parse(b)...)
				}
			}
		}
		if len(got) > 0 {
			all = append(all, got...)
			names = append(names, sc.name)
		}
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].Time.Before(all[j].Time) })
	return all, strings.Join(names, ", ")
}

func rotated(s sys.Sys, f string) []string {
	out := []string{}
	dir, base := path.Split(f)
	if ents, err := s.ReadDir(dir); err == nil {
		for _, e := range ents {
			n := e.Name()
			if n != base && strings.HasPrefix(n, base) && len(out) < 4 {
				out = append(out, dir+n)
			}
		}
	}
	return append(out, f)
}

func readMaybeGz(s sys.Sys, p string) []byte {
	b, err := s.ReadFile(p)
	if err != nil {
		return nil
	}
	if strings.HasSuffix(p, ".gz") {
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return nil
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, 64<<20))
		if err != nil && len(out) == 0 {
			return nil
		}
		return out
	}
	return b
}

var dnfRe = regexp.MustCompile(`^(\S+) \S+ (Upgrade|Upgraded|Installed|Install|Erase|Downgrade|Downgraded|Reinstall|Reinstalled|Obsoleted|Obsolete): (\S+)`)

// ParseDnfLog parses /var/log/dnf.rpm.log. "Upgraded:" lines carry the old version.
func ParseDnfLog(b []byte) []PkgEvent {
	var out []PkgEvent
	pendingFrom := map[string]string{}
	for _, l := range linux.Lines(b) {
		m := dnfRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		t, ok := ParseISO(m[1])
		if !ok {
			continue
		}
		name, ver := splitNEVRA(m[3])
		switch m[2] {
		case "Upgraded", "Downgraded", "Obsoleted":
			pendingFrom[name] = ver
			for i := len(out) - 1; i >= 0 && i >= len(out)-50; i-- {
				if out[i].Name == name && out[i].From == "" && (out[i].Action == "upgrade" || out[i].Action == "downgrade") {
					out[i].From = ver
					delete(pendingFrom, name)
					break
				}
			}
			continue
		case "Upgrade":
			out = append(out, PkgEvent{t, "upgrade", name, pendingFrom[name], ver})
		case "Downgrade":
			out = append(out, PkgEvent{t, "downgrade", name, pendingFrom[name], ver})
		case "Install", "Installed":
			out = append(out, PkgEvent{t, "install", name, "", ver})
		case "Erase":
			out = append(out, PkgEvent{t, "remove", name, ver, ""})
		case "Reinstall", "Reinstalled":
			out = append(out, PkgEvent{t, "reinstall", name, "", ver})
		}
		delete(pendingFrom, name)
	}
	return out
}

// splitNEVRA turns "nginx-1:1.26.1-1.el9.x86_64" into ("nginx", "1.26.1-1.el9").
func splitNEVRA(s string) (string, string) {
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		arch := s[i+1:]
		switch arch {
		case "x86_64", "noarch", "aarch64", "i686", "ppc64le", "s390x", "armv7hl", "riscv64", "src":
			s = s[:i]
		}
	}
	// name-[epoch:]version-release: the version starts after the second-last dash.
	j := strings.LastIndexByte(s, '-')
	if j <= 0 {
		return s, ""
	}
	k := strings.LastIndexByte(s[:j], '-')
	if k <= 0 {
		return s, ""
	}
	ver := s[k+1:]
	if c := strings.IndexByte(ver, ':'); c >= 0 {
		ver = ver[c+1:]
	}
	return s[:k], ver
}

// ParseDpkgLog parses /var/log/dpkg.log.
func ParseDpkgLog(b []byte) []PkgEvent {
	var out []PkgEvent
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) < 6 {
			continue
		}
		var act string
		switch f[2] {
		case "install":
			act = "install"
			if f[4] != "<none>" {
				act = "upgrade"
			}
		case "upgrade":
			act = "upgrade"
		case "remove", "purge":
			act = "remove"
		default:
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0]+" "+f[1], time.Local)
		if err != nil {
			continue
		}
		name := f[3]
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		from, to := f[4], f[5]
		if from == "<none>" {
			from = ""
		}
		if to == "<none>" {
			to = ""
		}
		if act == "upgrade" && from == to {
			act = "reinstall"
		}
		out = append(out, PkgEvent{t, act, name, from, to})
	}
	return out
}

var pacRe = regexp.MustCompile(`^\[([^\]]+)\] \[ALPM\] (installed|upgraded|downgraded|removed|reinstalled) (\S+) \((.*)\)$`)

// ParsePacmanLog parses /var/log/pacman.log.
func ParsePacmanLog(b []byte) []PkgEvent {
	var out []PkgEvent
	for _, l := range linux.Lines(b) {
		m := pacRe.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		t, ok := ParseISO(m[1])
		if !ok {
			var err error
			t, err = time.ParseInLocation("2006-01-02 15:04", m[1], time.Local)
			if err != nil {
				continue
			}
		}
		e := PkgEvent{Time: t, Name: m[3]}
		from, to, two := strings.Cut(m[4], " -> ")
		switch m[2] {
		case "installed":
			e.Action, e.To = "install", m[4]
		case "removed":
			e.Action, e.From = "remove", m[4]
		case "reinstalled":
			e.Action, e.To = "reinstall", m[4]
		default:
			e.Action = strings.TrimSuffix(m[2], "d")
			if m[2] == "upgraded" {
				e.Action = "upgrade"
			} else {
				e.Action = "downgrade"
			}
			if two {
				e.From, e.To = from, to
			}
		}
		out = append(out, e)
	}
	return out
}

// ParseZyppHistory parses /var/log/zypp/history.
func ParseZyppHistory(b []byte) []PkgEvent {
	var out []PkgEvent
	for _, l := range linux.Lines(b) {
		if strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Split(l, "|")
		if len(f) < 4 {
			continue
		}
		t, err := time.ParseInLocation("2006-01-02 15:04:05", f[0], time.Local)
		if err != nil {
			continue
		}
		switch strings.TrimSpace(f[1]) {
		case "install":
			out = append(out, PkgEvent{t, "install", f[2], "", f[3]})
		case "remove":
			out = append(out, PkgEvent{t, "remove", f[2], f[3], ""})
		}
	}
	return out
}

// ModTimeInside lists files under dir changed between from and to (newest first),
// at most max files and with a time budget.
func ModTimeInside(s sys.Sys, dirs []string, from, to time.Time, max int, budget time.Duration) []FileChange {
	var out []FileChange
	deadline := time.Now().Add(budget)
	for _, d := range dirs {
		_ = s.Walk(d, func(p string, e os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if time.Now().After(deadline) {
				return io.EOF
			}
			if e.IsDir() {
				return nil
			}
			info, err := e.Info()
			if err != nil {
				return nil
			}
			if mt := info.ModTime(); !mt.Before(from) && !mt.After(to) {
				out = append(out, FileChange{Path: p, Time: mt})
			}
			return nil
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

// FileChange is a file and when it changed.
type FileChange struct {
	Path string    `json:"path"`
	Time time.Time `json:"time"`
}
