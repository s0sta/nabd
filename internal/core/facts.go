package core

import (
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/linux"
	"github.com/s0sta/nabd/internal/sys"
)

// Facts are the basic facts about the machine, read once.
type Facts struct {
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	OSID      string    `json:"os_id"`
	OSLike    []string  `json:"os_like,omitempty"`
	OSVersion string    `json:"os_version,omitempty"`
	Kernel    string    `json:"kernel"`
	Arch      string    `json:"arch"`
	Uptime    float64   `json:"uptime_seconds"`
	BootTime  time.Time `json:"boot_time"`
	Container string    `json:"container,omitempty"`
	Systemd   bool      `json:"systemd"`
	Root      bool      `json:"root"`
	CPUs      int       `json:"cpus"`
	PkgMgr    string    `json:"package_manager,omitempty"`
}

// Family is "rhel", "debian", "arch", "suse", "alpine" or "".
func (f Facts) Family() string {
	ids := append([]string{f.OSID}, f.OSLike...)
	for _, id := range ids {
		switch id {
		case "rhel", "fedora", "centos", "rocky", "almalinux", "ol", "amzn":
			return "rhel"
		case "debian", "ubuntu", "linuxmint", "pop", "raspbian":
			return "debian"
		case "arch", "manjaro", "endeavouros":
			return "arch"
		case "suse", "opensuse", "sles", "opensuse-leap", "opensuse-tumbleweed":
			return "suse"
		case "alpine":
			return "alpine"
		}
	}
	switch f.PkgMgr {
	case "dnf", "yum":
		return "rhel"
	case "apt":
		return "debian"
	case "pacman":
		return "arch"
	case "zypper":
		return "suse"
	case "apk":
		return "alpine"
	}
	return ""
}

// ReadFacts reads the facts from the machine.
func ReadFacts(s sys.Sys) Facts {
	f := Facts{Hostname: s.Hostname(), Arch: runtime.GOARCH, Root: s.Uid() == 0, CPUs: runtime.NumCPU()}
	osr := map[string]string{}
	for _, p := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		if b, err := s.ReadFile(p); err == nil {
			osr = linux.OSRelease(b)
			break
		}
	}
	f.OS = osr["PRETTY_NAME"]
	if f.OS == "" {
		f.OS = strings.TrimSpace(osr["NAME"] + " " + osr["VERSION_ID"])
	}
	if f.OS == "" {
		f.OS = "Linux"
	}
	f.OSID = osr["ID"]
	f.OSLike = strings.Fields(osr["ID_LIKE"])
	f.OSVersion = osr["VERSION_ID"]
	if b, err := s.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		f.Kernel = strings.TrimSpace(string(b))
	}
	if b, err := s.ReadFile("/proc/uptime"); err == nil {
		if fs := strings.Fields(string(b)); len(fs) > 0 {
			f.Uptime, _ = strconv.ParseFloat(fs[0], 64)
		}
	}
	f.BootTime = s.Now().Add(-time.Duration(f.Uptime * float64(time.Second))).Truncate(time.Second)
	if st, err := s.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		f.Systemd = true
	}
	f.Container = detectContainer(s)
	if b, err := s.ReadFile("/proc/cpuinfo"); err == nil {
		n := 0
		for _, l := range linux.Lines(b) {
			if strings.HasPrefix(l, "processor") {
				n++
			}
		}
		if f.CPUs <= 0 {
			f.CPUs = n
		}
	}
	for _, pm := range []string{"dnf", "yum", "apt-get", "pacman", "zypper", "apk"} {
		if s.Has(pm) {
			f.PkgMgr = strings.TrimSuffix(pm, "-get")
			break
		}
	}
	return f
}

func detectContainer(s sys.Sys) string {
	if v := s.Env("container"); v != "" {
		return v
	}
	if _, err := s.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	if _, err := s.Stat("/run/.containerenv"); err == nil {
		return "podman"
	}
	if b, err := s.ReadFile("/proc/1/environ"); err == nil {
		for _, kv := range strings.Split(string(b), "\x00") {
			if strings.HasPrefix(kv, "container=") {
				return strings.TrimPrefix(kv, "container=")
			}
		}
	}
	if b, err := s.ReadFile("/proc/1/cgroup"); err == nil {
		t := string(b)
		for _, k := range []string{"docker", "kubepods", "lxc", "containerd", "libpod"} {
			if strings.Contains(t, "/"+k) || strings.Contains(t, k+"-") {
				return k
			}
		}
	}
	return ""
}

// UptimeText is "41 days" / "3 hours".
func (f Facts) UptimeText() string { return Duration(time.Duration(f.Uptime) * time.Second) }

// Summary is one line about the machine.
func (f Facts) Summary() string {
	parts := []string{f.Hostname, f.OS}
	if f.Kernel != "" {
		k := f.Kernel
		if i := strings.IndexAny(k, "-+"); i > 0 && len(k) > 24 {
			k = k[:i]
		}
		parts = append(parts, "kernel "+k)
	}
	if f.Uptime > 0 {
		parts = append(parts, "up "+f.UptimeText())
	}
	if f.Container != "" {
		parts = append(parts, "in a "+f.Container+" container")
	}
	return strings.Join(parts, " · ")
}

// Bytes is a short size: 512 B, 3.4 KB, 12 GB (powers of 1024, short names people know).
func Bytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for m := n / unit; m >= unit && exp < 5; m /= unit {
		div *= unit
		exp++
	}
	v := float64(n) / float64(div)
	suffix := []string{"KB", "MB", "GB", "TB", "PB", "EB"}[exp]
	if v >= 100 {
		return fmt.Sprintf("%.0f %s", v, suffix)
	}
	return fmt.Sprintf("%.1f %s", v, suffix)
}

// Duration is a short human duration: "45 s", "14 min", "3 hours", "41 days".
func Duration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	case d < 48*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", h)
	}
	return fmt.Sprintf("%d days", int(d.Hours()/24))
}

// Ago is "14 min ago".
func Ago(now, t time.Time) string {
	if t.IsZero() {
		return "at an unknown time"
	}
	if t.After(now) {
		return "in " + Duration(t.Sub(now))
	}
	return Duration(now.Sub(t)) + " ago"
}

// Plural is "1 file" / "3 files".
func Plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// Clip cuts a line to n characters.
func Clip(s string, n int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\t", " "))
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// Sudo is "sudo " for normal users and "" for root, for fix commands.
func (c *Ctx) Sudo() string {
	if c.Facts.Root {
		return ""
	}
	return "sudo "
}
