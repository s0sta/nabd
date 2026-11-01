package checks

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Time checks that the clock is synchronised.
var Time = core.Check{
	Name:  "time",
	Title: "Clock",
	Help:  "Is the clock synchronised (systemd-timesyncd, chrony or ntpd)? A wrong clock breaks TLS, Kerberos, logs and cron.",
	Run:   runTime,
}

// Kernel checks the kernel log for disk and hardware errors, and read-only file systems.
var Kernel = core.Check{
	Name:  "kernel",
	Title: "Kernel and hardware",
	Help:  "Disk and file system errors, file systems that turned read-only, hardware (MCE/EDAC) errors and hung tasks in the kernel log of this boot.",
	Run:   runKernel,
}

// Reboot checks if an update needs a reboot.
var Reboot = core.Check{
	Name:  "reboot",
	Title: "Reboot needed",
	Help:  "A newer kernel or core library is installed but not running yet, or the running kernel was removed by an update.",
	Run:   runReboot,
}

// Packages checks the package manager.
var Packages = core.Check{
	Name:  "packages",
	Title: "Package manager",
	Help:  "Interrupted dpkg runs, stale pacman locks, and how long ago updates were installed.",
	Run:   runPackages,
}

func runTime(c *core.Ctx, o *core.Out) {
	if c.Facts.Container != "" {
		o.Skip("a container uses the host's clock")
		return
	}
	sudo := c.Sudo()
	r := c.Sys.Run(5*time.Second, "timedatectl", "show", "--property=NTPSynchronized", "--property=NTP", "--property=Timezone")
	if r.OK() {
		kv := linux.KV(r.Stdout)
		if kv["NTPSynchronized"] == "yes" {
			o.OK("synchronised, time zone %s", kv["Timezone"])
			return
		}
		f := core.Finding{ID: "unsynced", Severity: core.Warn, Title: "the clock is not synchronised",
			Data: map[string]interface{}{"ntp_enabled": kv["NTP"] == "yes"}}
		if kv["NTP"] != "yes" {
			f.Why = []string{"no time sync service is turned on"}
			switch {
			case c.Sys.Has("chronyd"):
				f.Fix = []string{sudo + "systemctl enable --now chronyd"}
			case c.Facts.Family() == "rhel":
				f.Fix = []string{sudo + "dnf install -y chrony", sudo + "systemctl enable --now chronyd"}
			default:
				f.Fix = []string{sudo + "timedatectl set-ntp true"}
			}
		} else {
			f.Why = []string{"time sync is on, but it cannot reach a time server (UDP port 123 blocked, or no server set)"}
			if c.Sys.Has("chronyc") {
				f.Fix = []string{"chronyc sources -v   # which servers answer"}
			} else {
				f.Fix = []string{"timedatectl timesync-status", "journalctl -u systemd-timesyncd -b -e"}
			}
		}
		if off := chronyOffset(c); off != "" {
			f.Why = append(f.Why, "chrony: "+off)
		}
		o.Add(f)
		return
	}
	if c.Sys.Has("chronyc") {
		cr := c.Sys.Run(5*time.Second, "chronyc", "-n", "tracking")
		if cr.OK() {
			if strings.Contains(cr.Stdout, "Not synchronised") {
				o.Add(core.Finding{ID: "unsynced", Severity: core.Warn, Title: "the clock is not synchronised (chrony)",
					Fix: []string{"chronyc sources -v"}})
			} else {
				o.OK("synchronised (chrony)")
			}
			return
		}
	}
	o.Skip("no timedatectl or chronyc to ask")
}

func chronyOffset(c *core.Ctx) string {
	r := c.Sys.Run(5*time.Second, "chronyc", "-n", "tracking")
	if !r.OK() {
		return ""
	}
	for _, l := range strings.Split(r.Stdout, "\n") {
		if strings.HasPrefix(l, "System time") {
			return strings.TrimSpace(strings.TrimPrefix(l, "System time     :"))
		}
	}
	return ""
}

type klogRule struct {
	id, title string
	sev       core.Severity
	re        *regexp.Regexp
	why       []string
	fix       []string
}

var devRe = regexp.MustCompile(`\b(?:dev |device |\()?((?:sd[a-z]+|nvme\d+n\d+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|mmcblk\d+|dm-\d+|md\d+)\d*(?:p\d+)?)\b`)

func klogRules(c *core.Ctx) []klogRule {
	sudo := c.Sudo()
	return []klogRule{
		{"fs-errors", "the kernel reports file system errors", core.Crit,
			regexp.MustCompile(`EXT4-fs error|EXT4-fs \(.*\): (?:error|warning: mounting fs with errors)|XFS \(.*\): (?:Corruption|Metadata (?:corruption|I/O error)|log I/O error|Internal error)|BTRFS (?:error|critical)|F2FS-fs .*error|FAT-fs .*error`),
			[]string{"the file system on this disk has damage; data can be lost"},
			[]string{"# back up the data now", sudo + "smartctl -a /dev/DISK   # disk health (smartmontools)", "# then check the file system in a maintenance window (fsck / xfs_repair)"}},
		{"io-errors", "a disk reports read or write errors", core.Crit,
			regexp.MustCompile(`I/O error, dev |Buffer I/O error|blk_update_request: (?:critical medium|I/O) error|critical medium error|end_request: I/O error|ata\d+(?:\.\d+)?: (?:failed command|exception Emask|error: \{ (?:UNC|IDNF)|SError)|nvme\d+n?\d*: .*(?:I/O|IO) .*error|Medium Error|Unrecovered read error`),
			[]string{"the disk itself, its cable or its controller has a problem"},
			[]string{"# back up the data now", sudo + "smartctl -a /dev/DISK   # look at Reallocated / Pending sectors and errors"}},
		{"readonly", "the kernel made a file system read-only after errors", core.Crit,
			regexp.MustCompile(`[Rr]emounting filesystem read-only|forced to read-only|switching to read-only|shutting down filesystem`),
			[]string{"after an error the kernel protects the data: nothing can be written there now (services that write will fail)"},
			[]string{"# back up, check the disk (smartctl) and repair the file system, then reboot"}},
		{"hardware", "the hardware reports errors (CPU or memory)", core.Warn,
			regexp.MustCompile(`Hardware Error|mce: \[Hardware Error\]|EDAC .*(?:CE|UE) |Machine Check Exception|Corrected error|Uncorrected error`),
			[]string{"memory (ECC) or the CPU reported a fault; more can follow"},
			[]string{"# tell your hardware or cloud provider; on bare metal run a memory test", "journalctl -k -b | grep -iE 'mce|edac|hardware error'"}},
		{"hung", "tasks hung for more than 2 minutes", core.Warn,
			regexp.MustCompile(`blocked for more than \d+ seconds|soft lockup - CPU#|rcu_sched self-detected stall|hung_task`),
			[]string{"a process waited too long for the disk, the network storage (NFS) or the kernel"},
			[]string{"nabd why slow", "journalctl -k -b | grep -B2 -A10 'blocked for more than'"}},
		{"segfaults", "programs crashed (segfault) in this boot", core.Info,
			regexp.MustCompile(`segfault at [0-9a-f]+ ip `),
			[]string{"a program had a bug or a broken library"},
			[]string{"coredumpctl list   # if systemd-coredump is installed"}},
	}
}

func runKernel(c *core.Ctx, o *core.Out) {
	kl := c.Kernel()
	if kl.Limited {
		o.Limit("kernel log")
	}
	now := c.Sys.Now()
	for _, rule := range klogRules(c) {
		hits := kl.Grep(rule.re)
		if len(hits) == 0 {
			continue
		}
		f := core.Finding{ID: rule.id, Severity: rule.sev, Why: append([]string{}, rule.why...), Fix: rule.fix,
			Data: map[string]interface{}{"count": len(hits), "first": hits[0].Time, "last": hits[len(hits)-1].Time}}
		devs := map[string]bool{}
		for _, h := range hits {
			if m := devRe.FindStringSubmatch(h.Text); m != nil {
				devs[m[1]] = true
			}
		}
		var dl []string
		for d := range devs {
			dl = append(dl, d)
		}
		sort.Strings(dl)
		f.Title = fmt.Sprintf("%s (%s, last %s)", rule.title, core.Plural(len(hits), "line", "lines"), core.Ago(now, hits[len(hits)-1].Time))
		if len(dl) > 0 {
			f.Why = append(f.Why, "device: "+strings.Join(dl, ", "))
			f.Data["devices"] = dl
		}
		f.Why = append(f.Why, "kernel: "+core.Clip(hits[len(hits)-1].Text, 150))
		o.Add(f)
	}
	// read-only mounts that should be writable
	if c.Facts.Container == "" {
		if _, err := c.Sys.Stat("/run/ostree-booted"); err != nil {
			for _, m := range c.Mounts() {
				if !m.ReadOnly() {
					continue
				}
				switch m.Point {
				case "/", "/var", "/home", "/srv", "/opt", "/tmp", "/var/lib", "/var/log":
					o.Add(core.Finding{ID: "ro-mount", Severity: core.Crit,
						Title: m.Point + " is mounted read-only",
						Why:   []string{"programs cannot write there; this often follows disk errors (see the kernel log)"},
						Fix:   []string{"journalctl -k -b | grep -iE 'read-only|error'", "# after the cause is fixed: " + c.Sudo() + "mount -o remount,rw " + m.Point}})
				}
			}
		}
	}
	switch {
	case len(kl.Lines) > 0:
		o.OK("%s in the kernel log of this boot, no errors", core.Plural(len(kl.Lines), "line", "lines"))
	case kl.Limited:
		// nothing could be checked: say so, do not report "OK"
		o.Skip("the kernel log needs root (or the adm / systemd-journal group)")
	default:
		o.Skip("no kernel log found")
	}
}

func runReboot(c *core.Ctx, o *core.Out) {
	if c.Facts.Container != "" {
		o.Skip("a container has no own kernel")
		return
	}
	sudo := c.Sudo()
	found := false
	if _, err := c.Sys.Stat("/run/reboot-required"); err == nil {
		f := core.Finding{ID: "required", Severity: core.Warn, Title: "an update needs a reboot",
			Fix: []string{sudo + "reboot   # at a good time"}}
		if b, err := c.Sys.ReadFile("/run/reboot-required.pkgs"); err == nil {
			pk := strings.Fields(string(b))
			if len(pk) > 0 {
				f.Why = []string{"updated: " + strings.Join(uniq(pk), ", ")}
			}
		}
		o.Add(f)
		found = true
	}
	k := c.Facts.Kernel
	if k != "" {
		_, e1 := c.Sys.Stat("/lib/modules/" + k)
		_, e2 := c.Sys.Stat("/usr/lib/modules/" + k)
		if e1 != nil && e2 != nil {
			if _, err := c.Sys.Stat("/usr/lib/modules"); err == nil {
				o.Add(core.Finding{ID: "kernel-gone", Severity: core.Warn,
					Title: "the running kernel " + k + " was removed by an update",
					Why:   []string{"new kernel modules cannot load now (USB disks, file systems, VPN, Wi-Fi)"},
					Fix:   []string{sudo + "reboot   # starts the new kernel"}})
				found = true
			}
		}
		if newest := newestKernel(c); newest != "" && newest != k && !found {
			o.Add(core.Finding{ID: "new-kernel", Severity: core.Info,
				Title: "a newer kernel is installed: " + newest + " (running " + k + ")",
				Why:   []string{"security fixes in the new kernel work only after a reboot"},
				Fix:   []string{sudo + "reboot   # at a good time"}})
			found = true
		}
	}
	if c.Facts.Family() == "rhel" && c.Sys.Has("needs-restarting") && !found {
		r := c.Sys.Run(15*time.Second, "needs-restarting", "-r")
		if r.Code == 1 {
			var why []string
			for _, l := range strings.Split(r.Stdout, "\n") {
				if l = strings.TrimSpace(l); strings.HasPrefix(l, "*") {
					why = append(why, "updated: "+strings.TrimSpace(strings.TrimPrefix(l, "*")))
				}
			}
			o.Add(core.Finding{ID: "required", Severity: core.Warn, Title: "an update needs a reboot (needs-restarting -r)",
				Why: why, Fix: []string{sudo + "reboot   # at a good time"}})
			found = true
		}
	}
	if !found {
		o.OK("running kernel %s is the newest", k)
	}
}

// newestKernel compares the kernel files in /boot by time.
func newestKernel(c *core.Ctx) string {
	ents, err := c.Sys.ReadDir("/boot")
	if err != nil {
		return ""
	}
	var best string
	var bestT time.Time
	for _, e := range ents {
		n := e.Name()
		if !strings.HasPrefix(n, "vmlinuz-") || strings.Contains(n, "rescue") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().After(bestT) {
			best, bestT = strings.TrimPrefix(n, "vmlinuz-"), info.ModTime()
		}
	}
	// only versioned names can be compared with uname -r
	if best == "" || !strings.ContainsAny(best, "0123456789") || best == "linux" || best == "linux-lts" {
		return ""
	}
	return best
}

func runPackages(c *core.Ctx, o *core.Out) {
	sudo := c.Sudo()
	if ents, err := c.Sys.ReadDir("/var/lib/dpkg/updates"); err == nil && len(ents) > 0 {
		o.Add(core.Finding{ID: "dpkg-interrupted", Severity: core.Crit,
			Title: "a package install was interrupted (dpkg)",
			Why:   []string{"apt cannot install or update anything until it is finished"},
			Fix:   []string{sudo + "dpkg --configure -a", sudo + "apt-get -f install"}})
	}
	if _, err := c.Sys.Stat("/var/lib/pacman/db.lck"); err == nil {
		running := false
		for _, p := range c.Procs() {
			if p.Comm == "pacman" || p.Comm == "yay" || p.Comm == "paru" || p.Comm == "pamac" {
				running = true
			}
		}
		if !running {
			o.Add(core.Finding{ID: "pacman-lock", Severity: core.Warn,
				Title: "a stale pacman lock blocks all updates",
				Why:   []string{"/var/lib/pacman/db.lck exists but no pacman is running (an update was stopped)"},
				Fix:   []string{sudo + "rm /var/lib/pacman/db.lck"}})
		}
	}
	evs, src := c.PkgEvents()
	if len(evs) == 0 {
		o.OK("no package history found in the logs")
		return
	}
	last := evs[len(evs)-1]
	age := c.Sys.Now().Sub(last.Time)
	o.OK("last package change %s (%s)", core.Ago(c.Sys.Now(), last.Time), src)
	if age > 90*24*time.Hour {
		var fix string
		switch c.Facts.Family() {
		case "rhel":
			fix = sudo + "dnf upgrade --refresh"
		case "debian":
			fix = sudo + "apt update && " + sudo + "apt upgrade"
		case "arch":
			fix = sudo + "pacman -Syu"
		case "suse":
			fix = sudo + "zypper update"
		}
		f := core.Finding{ID: "old-updates", Severity: core.Warn,
			Title: fmt.Sprintf("no updates were installed for %s", core.Duration(age)),
			Why:   []string{"security fixes are missing; the last change was " + PkgEventText(last)}}
		if fix != "" {
			f.Fix = []string{fix}
		}
		o.Add(f)
	}
}

func uniq(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
