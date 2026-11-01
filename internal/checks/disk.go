// Package checks holds the health checks. Each check reads the machine
// through core.Ctx, never changes it, and explains every problem with its
// cause and the command that fixes it.
package checks

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
	"github.com/s0sta/nabd/internal/sys"
)

// Disk checks the space and inodes of every local file system.
var Disk = core.Check{
	Name:  "disk",
	Title: "Disk space",
	Help:  "Space and inodes on every local file system. For a full one it finds the cause: the journal, package caches, container images, crash dumps, big logs, or deleted files that a process still keeps open.",
	Run:   runDisk,
}

const (
	diskWarn  = 85.0
	diskCrit  = 95.0
	inodeWarn = 85.0
	inodeCrit = 95.0
)

func runDisk(c *core.Ctx, o *core.Out) {
	ms := c.Mounts()
	if len(ms) == 0 {
		o.Skip("no local file systems found")
		return
	}
	var fullest core.MountUsage
	var problems []core.MountUsage
	ro := 0
	for _, m := range ms {
		if m.ReadOnly() {
			ro++ // a read-only file system cannot fill up (snaps, images, recovery mounts)
			continue
		}
		if m.Err != "" {
			o.Add(core.Finding{ID: "unreadable", Severity: core.Unknown,
				Title: fmt.Sprintf("%s could not be read: %s", m.Point, m.Err),
				Data:  map[string]interface{}{"mount": m.Point}})
			continue
		}
		if m.Pct > fullest.Pct || fullest.Point == "" {
			fullest = m
		}
		if m.Pct >= diskWarn || m.InodePct >= inodeWarn {
			problems = append(problems, m)
		}
	}
	if fullest.Point == "" {
		o.Skip("only read-only file systems here")
		return
	}
	o.OK("%s, fullest %s %.0f%%", core.Plural(len(ms)-ro, "file system", "file systems"), fullest.Point, fullest.Pct)
	if len(problems) == 0 {
		return
	}
	deadline := time.Now().Add(6 * time.Second)
	deleted, full := DeletedOpenFiles(c)
	if !full {
		o.Limit("deleted files held open by other users' processes")
	}
	all := c.AllMounts()
	for _, m := range problems {
		if m.Pct >= diskWarn {
			o.Add(SpaceFinding(c, m, all, deleted, deadline))
		}
		if m.InodePct >= inodeWarn {
			sev := core.Warn
			if m.InodePct >= inodeCrit {
				sev = core.Crit
			}
			o.Add(core.Finding{ID: "inodes", Severity: sev,
				Title: fmt.Sprintf("%s has used %.0f%% of its inodes (one inode per file)", m.Point, m.InodePct),
				Why: []string{fmt.Sprintf("%s files and folders; when inodes run out, no new file can be made, even with free space",
					strconv.FormatUint(m.St.Files-m.St.FilesFree, 10)),
					"usual causes: PHP sessions, mail queues, cache folders, small log files that are never cleaned"},
				Fix:  []string{c.Sudo() + "nabd why disk " + m.Point + "   # shows the folders with the most files"},
				Data: map[string]interface{}{"mount": m.Point, "inode_percent": round(m.InodePct)}})
		}
	}
}

type suspect struct {
	label string
	path  string
	fix   []string
	note  string
}

func suspects(c *core.Ctx) []suspect {
	sudo := c.Sudo()
	var pkg []string
	var pkgPaths []string
	switch c.Facts.Family() {
	case "rhel":
		pm := "dnf"
		if c.Facts.PkgMgr == "yum" {
			pm = "yum"
		}
		pkg, pkgPaths = []string{sudo + pm + " clean all"}, []string{"/var/cache/dnf", "/var/cache/yum"}
	case "debian":
		pkg, pkgPaths = []string{sudo + "apt-get clean"}, []string{"/var/cache/apt/archives"}
	case "arch":
		pkg, pkgPaths = []string{sudo + "pacman -Sc   # keeps the packages you have installed"}, []string{"/var/cache/pacman/pkg"}
	case "suse":
		pkg, pkgPaths = []string{sudo + "zypper clean --all"}, []string{"/var/cache/zypp"}
	}
	out := []suspect{
		{"journal logs", "/var/log/journal", []string{sudo + "journalctl --vacuum-size=500M",
			"# for good: SystemMaxUse=500M in /etc/systemd/journald.conf, then restart systemd-journald"}, ""},
	}
	for _, p := range pkgPaths {
		out = append(out, suspect{"package cache", p, pkg, ""})
	}
	out = append(out,
		suspect{"Docker images and containers", "/var/lib/docker", []string{"docker system df", "docker system prune   # deletes stopped containers, unused networks and dangling images"}, "review before you prune"},
		suspect{"Podman images and containers", "/var/lib/containers", []string{"podman system df", "podman system prune"}, "review before you prune"},
		suspect{"containerd images", "/var/lib/containerd", []string{sudo + "crictl rmi --prune"}, "review first"},
		suspect{"crash dumps", "/var/lib/systemd/coredump", []string{"coredumpctl list", sudo + "rm /var/lib/systemd/coredump/*"}, "keep a dump if you still need to debug the crash"},
		suspect{"crash reports", "/var/crash", []string{"ls -lh /var/crash", sudo + "rm /var/crash/*"}, "keep a report if you still need it"},
		suspect{"old snap versions", "/var/lib/snapd/snaps", []string{sudo + "snap set system refresh.retain=2", "snap list --all   # 'disabled' rows are old versions: " + sudo + "snap remove NAME --revision=REV"}, ""},
		suspect{"Flatpak runtimes", "/var/lib/flatpak", []string{"flatpak uninstall --unused"}, ""},
		suspect{"temporary files", "/var/tmp", []string{sudo + "du -xsh /var/tmp/* | sort -h | tail"}, "check what they are before you delete"},
		suspect{"temporary files", "/tmp", []string{sudo + "du -xsh /tmp/* | sort -h | tail"}, "check what they are before you delete"},
	)
	return out
}

// SpaceFinding explains a full file system: what fills it and the commands that free space.
func SpaceFinding(c *core.Ctx, m core.MountUsage, all []linux.Mount, deleted []OpenDeleted, deadline time.Time) core.Finding {
	sev := core.Warn
	if m.Pct >= diskCrit {
		sev = core.Crit
	}
	f := core.Finding{ID: "full", Severity: sev,
		Title: fmt.Sprintf("%s is %.0f%% full (%s free of %s)", m.Point, m.Pct, core.Bytes(m.St.Avail), core.Bytes(m.St.Size)),
		Data: map[string]interface{}{"mount": m.Point, "percent": round(m.Pct), "free_bytes": m.St.Avail,
			"size_bytes": m.St.Size, "fstype": m.FSType, "device": m.Source}}
	min := uint64(200 << 20)
	if p := m.St.Size / 50; p > min {
		min = p // 2% of the file system
	}
	type found struct {
		s    suspect
		size uint64
	}
	var hits []found
	for _, s := range suspects(c) {
		if core.MountOf(all, s.path).Point != m.Point {
			continue
		}
		if _, err := c.Sys.Stat(s.path); err != nil {
			continue
		}
		size, _ := DirSize(c.Sys, s.path, deadline)
		if size >= min {
			hits = append(hits, found{s, size})
		}
	}
	// one big log file is a classic
	if core.MountOf(all, "/var/log").Point == m.Point {
		for _, bf := range BigFiles(c.Sys, "/var/log", 1<<30, 3, deadline) {
			if strings.HasPrefix(bf.Path, "/var/log/journal/") || strings.HasSuffix(bf.Path, ".journal") || strings.HasSuffix(bf.Path, ".journal~") {
				continue // the journal has its own fix; never truncate its files
			}
			hits = append(hits, found{suspect{"one log file", bf.Path, []string{
				"# if you do not need the old lines: " + c.Sudo() + "truncate -s 0 " + bf.Path,
				"# and rotate it: add it to /etc/logrotate.d/"}, "copy it first if you need the old lines"}, bf.Size})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].size > hits[j].size })
	seen := map[string]bool{}
	for _, h := range hits {
		f.Why = append(f.Why, fmt.Sprintf("%s in %s (%s)", core.Bytes(h.size), h.s.label, h.s.path))
		for _, x := range h.s.fix {
			if !seen[x] {
				f.Fix = append(f.Fix, x)
				seen[x] = true
			}
		}
		if h.s.note != "" && f.Note == "" {
			f.Note = h.s.note
		}
	}
	// deleted files that a process keeps open still use the space
	byPID := map[int]uint64{}
	var total uint64
	for _, d := range deleted {
		if core.MountOf(all, d.Path).Point == m.Point {
			byPID[d.PID] += d.Size
			total += d.Size
		}
	}
	if total >= min {
		pids := make([]int, 0, len(byPID))
		for p := range byPID {
			pids = append(pids, p)
		}
		sort.Slice(pids, func(i, j int) bool { return byPID[pids[i]] > byPID[pids[j]] })
		for i, pid := range pids {
			if i == 3 {
				break
			}
			f.Why = append(f.Why, fmt.Sprintf("%s in deleted files that %s still keeps open (the space comes back when it closes them)",
				core.Bytes(byPID[pid]), c.Owner(pid)))
			if unit, _ := c.UnitOf(pid); unit != "" {
				f.Fix = append(f.Fix, c.Sudo()+"systemctl restart "+unit)
			} else {
				f.Fix = append(f.Fix, "# restart "+c.ProcName(pid)+" (pid "+strconv.Itoa(pid)+") to free the space")
			}
		}
	}
	if m.Point == "/boot" || m.Point == "/boot/efi" {
		if n := countKernels(c.Sys); n >= 3 {
			f.Why = append(f.Why, fmt.Sprintf("%d kernels are installed; each one needs space in /boot", n))
			switch c.Facts.Family() {
			case "rhel":
				f.Fix = append(f.Fix, c.Sudo()+"dnf remove --oldinstallonly --setopt installonly_limit=2")
			case "debian":
				f.Fix = append(f.Fix, c.Sudo()+"apt autoremove --purge")
			}
		}
	}
	if len(f.Why) == 0 {
		f.Why = []string{"no known big folder found; look for the biggest folders"}
	}
	f.Fix = append(f.Fix, c.Sudo()+"nabd why disk "+m.Point+"   # the biggest folders and files")
	return f
}

func countKernels(s sys.Sys) int {
	ents, err := s.ReadDir("/boot")
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "vmlinuz-") && !strings.Contains(e.Name(), "rescue") {
			n++
		}
	}
	return n
}

// DirSize adds up the space used under dir on its own file system,
// until the deadline. complete is false when time ran out.
func DirSize(s sys.Sys, dir string, deadline time.Time) (size uint64, complete bool) {
	root, err := s.Lstat(dir)
	if err != nil {
		return 0, true
	}
	dev := devOf(root)
	complete = true
	_ = s.Walk(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			complete = false
			return io.EOF
		}
		info, err := e.Info()
		if err != nil {
			return nil
		}
		if e.IsDir() && p != dir && devOf(info) != dev {
			return skipDir
		}
		size += allocated(info)
		return nil
	})
	return size, complete
}

var skipDir = fs.SkipDir

// File is a path and its size.
type File struct {
	Path string `json:"path"`
	Size uint64 `json:"size"`
}

// BigFiles finds files larger than min under dir (at most max, biggest first).
func BigFiles(s sys.Sys, dir string, min uint64, max int, deadline time.Time) []File {
	var out []File
	root, err := s.Lstat(dir)
	if err != nil {
		return nil
	}
	dev := devOf(root)
	_ = s.Walk(dir, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if time.Now().After(deadline) {
			return io.EOF
		}
		info, err := e.Info()
		if err != nil {
			return nil
		}
		if e.IsDir() {
			if p != dir && devOf(info) != dev {
				return skipDir
			}
			return nil
		}
		if sz := allocated(info); sz >= min && info.Mode().IsRegular() {
			out = append(out, File{p, sz})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Size > out[j].Size })
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func devOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Dev)
	}
	return 0
}

func allocated(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Blocks > 0 {
		return uint64(st.Blocks) * 512
	}
	if fi.Size() > 0 {
		return uint64(fi.Size())
	}
	return 0
}

// OpenDeleted is a deleted file that a process still has open.
type OpenDeleted struct {
	PID  int    `json:"pid"`
	Path string `json:"path"`
	Size uint64 `json:"size"`
}

// DeletedOpenFiles finds deleted files that processes keep open. full is
// false when some processes could not be read (not root).
func DeletedOpenFiles(c *core.Ctx) ([]OpenDeleted, bool) {
	full := true
	seen := map[[2]uint64]bool{}
	var out []OpenDeleted
	for _, pid := range core.PIDs(c.Sys) {
		dir := "/proc/" + strconv.Itoa(pid) + "/fd"
		ents, err := c.Sys.ReadDir(dir)
		if err != nil {
			if os.IsPermission(err) {
				full = false
			}
			continue
		}
		for _, e := range ents {
			t, err := c.Sys.Readlink(dir + "/" + e.Name())
			if err != nil || !strings.HasSuffix(t, " (deleted)") || !strings.HasPrefix(t, "/") ||
				strings.HasPrefix(t, "/dev/") || strings.HasPrefix(t, "/memfd:") {
				continue
			}
			info, err := c.Sys.Stat(dir + "/" + e.Name())
			if err != nil || !info.Mode().IsRegular() {
				continue
			}
			key := [2]uint64{devOf(info), inodeOf(info)}
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, OpenDeleted{pid, strings.TrimSuffix(t, " (deleted)"), allocated(info)})
		}
	}
	return out, full
}

func inodeOf(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Ino)
	}
	return 0
}

func round(f float64) float64 { return float64(int(f*10+0.5)) / 10 }
