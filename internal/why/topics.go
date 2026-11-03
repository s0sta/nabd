package why

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/checks"
	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// ---------------------------------------------------------------- disk

// Disk explains what fills a file system (the fullest one, or the one of path).
func Disk(c *core.Ctx, target string, budget time.Duration) Answer {
	a := Answer{Topic: "disk", Subject: target}
	ms := c.Mounts()
	if len(ms) == 0 {
		a.Severity, a.Verdict = core.Unknown, "no local file systems found"
		return a
	}
	var m core.MountUsage
	if target != "" {
		mp := core.MountOf(c.AllMounts(), target).Point
		for _, x := range ms {
			if x.Point == mp {
				m = x
			}
		}
		if m.Point == "" {
			a.Severity, a.Verdict = core.Unknown, target+" is not on a local file system nabd checks"
			return a
		}
		if m.ReadOnly() {
			where := target + " is on " + m.Point + ", a read-only file system"
			if target == m.Point {
				where = m.Point + " is a read-only file system"
			}
			a.Severity, a.Verdict = core.OK, fmt.Sprintf("%s (%.0f%% used): it cannot fill up, nothing can write there", where, m.Pct)
			return a
		}
	} else {
		for _, x := range ms {
			if x.Err == "" && !x.ReadOnly() && (m.Point == "" || x.Pct > m.Pct) {
				m = x
			}
		}
		if m.Point == "" {
			a.Severity, a.Verdict = core.OK, "there are only read-only file systems here"
			return a
		}
		a.Subject = m.Point
	}
	if target == "" {
		target = m.Point
	}
	a.Severity = core.OK
	if m.Pct >= 85 || m.InodePct >= 85 {
		a.Severity = core.Warn
	}
	if m.Pct >= 95 || m.InodePct >= 95 {
		a.Severity = core.Crit
	}
	a.Verdict = fmt.Sprintf("%s is %.0f%% full: %s used, %s free of %s", m.Point, m.Pct, core.Bytes(m.Used()), core.Bytes(m.St.Avail), core.Bytes(m.St.Size))
	a.add("File system", fmt.Sprintf("%s on %s (%s), inodes %.0f%% used", m.Point, m.Source, m.FSType, m.InodePct))

	deadline := time.Now().Add(budget)
	tree, files, counts, complete, denied := scan(c, target, deadline)
	if denied {
		a.limit("folders that only root can read")
	}
	var lines []string
	for _, d := range drill(tree, target, 3) {
		lines = append(lines, d)
	}
	if !complete {
		lines = append(lines, fmt.Sprintf("(stopped after %s; sizes are at least this big — use --timeout for more)", budget))
	}
	a.add("Biggest folders", lines...)
	var fl []string
	for _, f := range files {
		fl = append(fl, fmt.Sprintf("%8s  %s", core.Bytes(f.Size), f.Path))
	}
	a.add("Biggest files", fl...)
	if m.InodePct >= 50 {
		type kv struct {
			p string
			n int
		}
		var cs []kv
		for p, n := range counts {
			cs = append(cs, kv{p, n})
		}
		sort.Slice(cs, func(i, j int) bool { return cs[i].n > cs[j].n })
		var cl []string
		for i, x := range cs {
			if i == 6 {
				break
			}
			cl = append(cl, fmt.Sprintf("%8d files  %s", x.n, x.p))
		}
		a.add("Folders with the most files (inodes)", cl...)
	}
	deleted, full := checks.DeletedOpenFiles(c)
	if !full {
		a.limit("deleted files held open by other users' processes")
	}
	all := c.AllMounts()
	var dl []string
	for _, d := range deleted {
		if core.MountOf(all, d.Path).Point == m.Point && d.Size >= 10<<20 {
			dl = append(dl, fmt.Sprintf("%8s  %s — held by %s", core.Bytes(d.Size), d.Path, c.Owner(d.PID)))
		}
	}
	a.add("Deleted files that still use space", dl...)
	if m.Pct >= 70 {
		f := checks.SpaceFinding(c, m, all, deleted, time.Now().Add(5*time.Second))
		for _, x := range f.Fix {
			if !strings.Contains(x, "nabd why disk") {
				a.fix(x)
			}
		}
		a.Note = f.Note
		if len(a.Fix) == 0 {
			// no usual suspect: point at the folder that holds most of the space
			if p := heaviest(tree, target); p != target {
				a.fix("du -xh --max-depth=1 "+p+" | sort -h | tail   # what inside "+p+" is big",
					"# delete or move what is not needed; for growing logs, set up rotation (logrotate)")
			}
		}
	}
	return a
}

// heaviest follows the biggest folder down while it holds most of its parent.
func heaviest(n *dirNode, base string) string {
	p := base
	for depth := 0; n != nil && depth < 4; depth++ {
		var best *dirNode
		name := ""
		for k, ch := range n.children {
			if best == nil || ch.size > best.size {
				best, name = ch, k
			}
		}
		if best == nil || best.size*2 < n.size {
			break
		}
		p = strings.TrimSuffix(p, "/") + "/" + name
		n = best
	}
	return p
}

type dirNode struct {
	size     uint64
	children map[string]*dirNode
}

// scan walks the folder on its own file system and adds up sizes per folder (3 levels).
func scan(c *core.Ctx, root string, deadline time.Time) (*dirNode, []checks.File, map[string]int, bool, bool) {
	top := &dirNode{children: map[string]*dirNode{}}
	counts := map[string]int{}
	var files []checks.File
	complete, denied := true, false
	rootInfo, err := c.Sys.Lstat(root)
	if err != nil {
		return top, nil, counts, true, false
	}
	dev := devOf(rootInfo)
	rootClean := strings.TrimSuffix(root, "/")
	_ = c.Sys.Walk(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			if os.IsPermission(err) {
				denied = true
			}
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
		if e.IsDir() {
			if p != root && devOf(info) != dev {
				return skipDir
			}
			return nil
		}
		size := allocated(info)
		rel := strings.TrimPrefix(strings.TrimPrefix(p, rootClean), "/")
		parts := strings.Split(rel, "/")
		node := top
		node.size += size
		for i := 0; i < len(parts)-1 && i < 3; i++ {
			ch, ok := node.children[parts[i]]
			if !ok {
				ch = &dirNode{children: map[string]*dirNode{}}
				node.children[parts[i]] = ch
			}
			ch.size += size
			node = ch
		}
		if len(parts) > 1 {
			counts[rootClean+"/"+path.Dir(rel)]++
		}
		if size >= 100<<20 && info.Mode().IsRegular() {
			files = append(files, checks.File{Path: p, Size: size})
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool { return files[i].Size > files[j].Size })
	if len(files) > 8 {
		files = files[:8]
	}
	return top, files, counts, complete, denied
}

// drill lists the biggest folders and goes into the biggest one, like du.
func drill(n *dirNode, base string, depth int) []string {
	var out []string
	prefix := strings.TrimSuffix(base, "/")
	indent := ""
	for d := 0; d < depth && n != nil && len(n.children) > 0; d++ {
		type kv struct {
			name string
			node *dirNode
		}
		var kids []kv
		for k, v := range n.children {
			kids = append(kids, kv{k, v})
		}
		sort.Slice(kids, func(i, j int) bool { return kids[i].node.size > kids[j].node.size })
		limit := 6
		if d > 0 {
			limit = 4
		}
		for i, k := range kids {
			if i == limit {
				break
			}
			mark := "  "
			if i == 0 && len(k.node.children) > 0 && d < depth-1 {
				mark = "▸ "
			}
			pct := 0.0
			if n.size > 0 {
				pct = 100 * float64(k.node.size) / float64(n.size)
			}
			out = append(out, fmt.Sprintf("%s%s%8s %3.0f%%  %s/%s", indent, mark, core.Bytes(k.node.size), pct, prefix, k.name))
		}
		if len(kids) == 0 {
			break
		}
		prefix += "/" + kids[0].name
		n = kids[0].node
		indent += "    "
	}
	return out
}

// ---------------------------------------------------------------- slow

// Slow finds what slows the machine down right now.
func Slow(c *core.Ctx) Answer {
	a := Answer{Topic: "slow"}
	ioBefore := readProcIO(c)
	diskBefore := readDiskstats(c)
	t0 := time.Now()
	s := c.Sample()
	secs := time.Since(t0).Seconds()
	if secs < 0.2 {
		secs = 1
	}
	ioAfter := readProcIO(c)
	diskAfter := readDiskstats(c)
	cpus := c.Facts.CPUs
	if cpus < 1 {
		cpus = 1
	}
	var l5 float64
	if b, err := c.Sys.ReadFile("/proc/loadavg"); err == nil {
		_, l5, _, _ = linux.Loadavg(b)
	}
	psi := map[string]float64{}
	for _, k := range []string{"cpu", "memory", "io"} {
		if p, ok := c.PSI(k); ok {
			psi[k+".some"] = p["some"]["avg10"]
			psi[k+".full"] = p["full"]["avg10"]
		}
	}
	mi := map[string]uint64{}
	if b, err := c.Sys.ReadFile("/proc/meminfo"); err == nil {
		mi = linux.Meminfo(b)
	}
	freePct := 0.0
	if mi["MemTotal"] > 0 {
		freePct = 100 * float64(mi["MemAvailable"]) / float64(mi["MemTotal"])
	}
	swapRate := float64(s.SwapIn+s.SwapOut) / secs
	// busiest disk
	type du struct {
		dev  string
		util float64
	}
	var disks []du
	for dev, b := range diskAfter {
		if a0, ok := diskBefore[dev]; ok && b >= a0 {
			disks = append(disks, du{dev, 100 * float64(b-a0) / (secs * 1000)})
		}
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].util > disks[j].util })
	busiest := du{}
	if len(disks) > 0 {
		busiest = disks[0]
		if busiest.util > 100 {
			busiest.util = 100
		}
	}
	// top I/O processes
	type pio struct {
		pid   int
		bytes uint64
	}
	var ios []pio
	for pid, after := range ioAfter {
		if before, ok := ioBefore[pid]; ok && after >= before {
			if d := after - before; d > 0 {
				ios = append(ios, pio{pid, d})
			}
		}
	}
	sort.Slice(ios, func(i, j int) bool { return ios[i].bytes > ios[j].bytes })
	if len(ioAfter) == 0 && !c.Facts.Root {
		a.limit("disk I/O per process")
	}

	var cpuLines []string
	cpuLines = append(cpuLines, fmt.Sprintf("CPU %.0f%% busy, iowait %.0f%%, steal %.0f%% on %d CPUs; load %.2f (%.1f per CPU)", s.Busy, s.Iowait, s.Steal, cpus, l5, l5/float64(cpus)))
	for i, p := range s.Top {
		if i == 5 {
			break
		}
		cpuLines = append(cpuLines, fmt.Sprintf("%5.0f%%  %s", p.Percent, c.Owner(p.PID)))
	}
	a.add("CPU", cpuLines...)
	memLines := []string{fmt.Sprintf("%.0f%% available (%s of %s), swap activity %.0f pages/s", freePct, core.Bytes(mi["MemAvailable"]), core.Bytes(mi["MemTotal"]), swapRate)}
	for _, p := range c.TopMemory(3) {
		memLines = append(memLines, fmt.Sprintf("%8s  %s", core.Bytes(p.RSS), c.Owner(p.PID)))
	}
	a.add("Memory", memLines...)
	var dLines []string
	for i, d := range disks {
		if i == 3 || d.util < 1 {
			break
		}
		dLines = append(dLines, fmt.Sprintf("%-10s %3.0f%% busy", d.dev, d.util))
	}
	for i, p := range ios {
		if i == 5 {
			break
		}
		dLines = append(dLines, fmt.Sprintf("%8s/s  %s", core.Bytes(uint64(float64(p.bytes)/secs)), c.Owner(p.pid)))
	}
	if len(s.DState) > 0 {
		var names []string
		for i, pid := range s.DState {
			if i == 5 {
				break
			}
			names = append(names, c.Owner(pid))
		}
		dLines = append(dLines, "waiting for I/O (D state): "+strings.Join(names, ", "))
	}
	a.add("Disk", dLines...)
	if len(psi) > 0 {
		a.add("Pressure (PSI, last 10 s)", fmt.Sprintf("cpu %.0f%%, memory %.0f%% (full %.0f%%), io %.0f%% (full %.0f%%)",
			psi["cpu.some"], psi["memory.some"], psi["memory.full"], psi["io.some"], psi["io.full"]))
	}
	top := func() string {
		if len(s.Top) > 0 {
			return c.Owner(s.Top[0].PID)
		}
		return "no single process"
	}
	switch {
	case psi["memory.full"] >= 10 || swapRate >= 200 || freePct < 5:
		a.Severity, a.Verdict = core.Crit, "memory is the bottleneck: the kernel is busy finding free memory (swap / reclaim)"
		a.fix("nabd why memory")
	case s.Iowait >= 20 || busiest.util >= 80 || psi["io.full"] >= 10:
		a.Severity = core.Warn
		if busiest.util >= 50 {
			who := ""
			if len(ios) > 0 {
				who = "; most I/O: " + c.Owner(ios[0].pid)
			}
			a.Verdict = fmt.Sprintf("the disk is the bottleneck: %s is %.0f%% busy%s", busiest.dev, busiest.util, who)
			a.fix(c.Sudo()+"iotop -o   # if installed: live I/O per process", "nabd why disk")
			break
		}
		// programs wait, but no local disk is busy
		wait := fmt.Sprintf("io pressure %.0f%%", psi["io.full"])
		if _, ok := psi["io.full"]; !ok || s.Iowait > psi["io.full"] {
			wait = fmt.Sprintf("iowait %.0f%%", s.Iowait)
		}
		var remote []string
		for _, m := range c.AllMounts() {
			if remoteFS(m.FSType) {
				remote = append(remote, m.Point+"  ("+m.FSType+", "+m.Source+")")
			}
		}
		if len(remote) > 0 {
			a.Verdict = "programs wait for I/O (" + wait + "), but no local disk is busy: the wait is probably on a network or FUSE file system"
			a.add("Network and FUSE file systems", first(remote, 6)...)
			a.fix("# a slow or hung server behind one of these mounts makes every program that touches it wait",
				"cat /proc/*/wchan 2>/dev/null | sort | uniq -c | sort -rn | head   # where waiting programs sleep")
		} else {
			a.Verdict = "programs wait for I/O (" + wait + "), but no disk here is busy: the storage under this machine may be slow"
			a.fix("# in a VM: check the disk limits (IOPS, burst credits) in the cloud console")
		}
	case s.Steal >= 10:
		a.Severity, a.Verdict = core.Warn, fmt.Sprintf("the hypervisor takes %.0f%% of the CPU (steal): this VM gets less CPU than it wants", s.Steal)
		a.fix("# check CPU credits / noisy neighbours in your cloud console")
	case s.Busy >= 85 || l5/float64(cpus) >= 1.5:
		a.Severity, a.Verdict = core.Warn, fmt.Sprintf("the CPU is the bottleneck (%.0f%% busy); top: %s", s.Busy, top())
		if len(s.Top) > 0 {
			if unit, _ := c.UnitOf(s.Top[0].PID); unit != "" {
				a.fix("nabd why service " + strings.TrimSuffix(unit, ".service"))
			}
		}
	default:
		a.Severity = core.OK
		a.Verdict = fmt.Sprintf("this machine is not busy now (CPU %.0f%%, disk %.0f%%, %.0f%% memory free): the slowness is probably elsewhere", s.Busy, busiest.util, freePct)
		a.add("Look next at", "the network or a remote service (database, API, DNS): nabd why dns", "a busy time that has passed: load averages above show the last 1/5/15 minutes")
	}
	return a
}

func readProcIO(c *core.Ctx) map[int]uint64 {
	out := map[int]uint64{}
	for _, pid := range core.PIDs(c.Sys) {
		b, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/io")
		if err != nil {
			continue
		}
		var r, w uint64
		for _, l := range linux.Lines(b) {
			if strings.HasPrefix(l, "read_bytes: ") {
				r, _ = strconv.ParseUint(strings.TrimPrefix(l, "read_bytes: "), 10, 64)
			}
			if strings.HasPrefix(l, "write_bytes: ") {
				w, _ = strconv.ParseUint(strings.TrimPrefix(l, "write_bytes: "), 10, 64)
			}
		}
		out[pid] = r + w
	}
	return out
}

var diskDevRe = regexp.MustCompile(`^(sd[a-z]+|nvme\d+n\d+|vd[a-z]+|xvd[a-z]+|hd[a-z]+|mmcblk\d+|md\d+)$`)

func readDiskstats(c *core.Ctx) map[string]uint64 {
	out := map[string]uint64{}
	b, err := c.Sys.ReadFile("/proc/diskstats")
	if err != nil {
		return out
	}
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) < 13 || !diskDevRe.MatchString(f[2]) {
			continue
		}
		ticks, _ := strconv.ParseUint(f[12], 10, 64)
		out[f[2]] = ticks
	}
	return out
}

// ---------------------------------------------------------------- memory

var oomLineRe = regexp.MustCompile(`(?:[Kk]illed process (\d+) \(([^)]+)\)[^\n]*?(?:anon-rss:(\d+)kB)?|task=([^,]+),pid=(\d+))`)

// Memory explains who uses the memory.
func Memory(c *core.Ctx) Answer {
	a := Answer{Topic: "memory"}
	b, err := c.Sys.ReadFile("/proc/meminfo")
	if err != nil {
		a.Severity, a.Verdict = core.Unknown, "cannot read /proc/meminfo"
		return a
	}
	mi := linux.Meminfo(b)
	total, avail := mi["MemTotal"], mi["MemAvailable"]
	cache := mi["Cached"] + mi["Buffers"] + mi["SReclaimable"]
	pct := 0.0
	if total > 0 {
		pct = 100 * float64(avail) / float64(total)
	}
	a.Severity = core.OK
	if pct < 10 {
		a.Severity = core.Warn
	}
	if pct < 5 {
		a.Severity = core.Crit
	}
	a.Verdict = fmt.Sprintf("%s of %s is available (%.0f%%)", core.Bytes(avail), core.Bytes(total), pct)
	a.add("Overview",
		fmt.Sprintf("used by programs  %s", core.Bytes(total-avail)),
		fmt.Sprintf("page cache        %s  (the kernel frees it when programs need memory)", core.Bytes(cache)),
		fmt.Sprintf("swap              %s used of %s", core.Bytes(mi["SwapTotal"]-mi["SwapFree"]), core.Bytes(mi["SwapTotal"])))
	if mi["SUnreclaim"] > total/5 {
		a.add("Overview", fmt.Sprintf("kernel memory     %s cannot be freed (SUnreclaim): a driver or the kernel may leak", core.Bytes(mi["SUnreclaim"])))
	}
	// group by program name
	type grp struct {
		name  string
		rss   uint64
		count int
	}
	groups := map[string]*grp{}
	page := uint64(os.Getpagesize())
	for _, p := range c.Procs() {
		if p.RSSPages <= 0 {
			continue
		}
		g, ok := groups[p.Comm]
		if !ok {
			g = &grp{name: p.Comm}
			groups[p.Comm] = g
		}
		g.rss += uint64(p.RSSPages) * page
		g.count++
	}
	var gl []*grp
	for _, g := range groups {
		gl = append(gl, g)
	}
	sort.Slice(gl, func(i, j int) bool { return gl[i].rss > gl[j].rss })
	var lines []string
	for i, g := range gl {
		if i == 8 {
			break
		}
		n := ""
		if g.count > 1 {
			n = fmt.Sprintf(" ×%d", g.count)
		}
		lines = append(lines, fmt.Sprintf("%8s  %s%s", core.Bytes(g.rss), g.name, n))
	}
	a.add("Programs (RSS, shared pages counted for each process)", lines...)
	// tmpfs lives in memory
	var tl []string
	for _, m := range c.AllMounts() {
		if m.FSType != "tmpfs" {
			continue
		}
		if st, err := c.Sys.Statfs(m.Point); err == nil && st.Size > st.Free {
			if used := st.Size - st.Free; used >= 100<<20 {
				tl = append(tl, fmt.Sprintf("%8s  %s (tmpfs: files there use RAM)", core.Bytes(used), m.Point))
			}
		}
	}
	a.add("Files in memory", tl...)
	kl := c.Kernel()
	if kl.Limited {
		a.limit("kernel log (OOM kills)")
	}
	var ol []string
	for _, l := range kl.Grep(oomLineRe) {
		if !strings.Contains(strings.ToLower(l.Text), "kill") {
			continue
		}
		m := oomLineRe.FindStringSubmatch(l.Text)
		name, pid := m[2], m[1]
		if name == "" {
			name, pid = m[4], m[5]
		}
		line := fmt.Sprintf("%s  %s (pid %s)", l.Time.Format("Jan _2 15:04"), name, pid)
		if m[3] != "" {
			kb, _ := strconv.ParseUint(m[3], 10, 64)
			line += " used " + core.Bytes(kb*1024)
		}
		if strings.Contains(l.Text, "memcg") || strings.Contains(l.Text, "Memory cgroup") {
			line += " — hit its own limit (cgroup MemoryMax)"
		}
		ol = append(ol, line)
	}
	if len(ol) > 8 {
		ol = ol[len(ol)-8:]
	}
	if len(ol) > 0 {
		a.add("Killed by the OOM killer (this boot)", ol...)
		if a.Severity == core.OK {
			a.Severity = core.Warn
		}
		a.fix("# limit the program that grows: " + c.Sudo() + "systemctl edit SERVICE  → [Service] MemoryMax=2G")
	}
	if p, ok := c.PSI("memory"); ok {
		a.add("Pressure (PSI)", fmt.Sprintf("some %.0f%%, full %.0f%% in the last 60 s", p["some"]["avg60"], p["full"]["avg60"]))
	}
	if len(gl) > 0 && a.Severity != core.OK {
		a.Verdict += "; the biggest user is " + gl[0].name + " (" + core.Bytes(gl[0].rss) + ")"
	}
	return a
}

// ---------------------------------------------------------------- service

// Service explains one systemd service.
func Service(c *core.Ctx, name string) Answer {
	a := Answer{Topic: "service", Subject: name}
	if !c.Facts.Systemd {
		a.Severity, a.Verdict = core.Unknown, "this machine does not run systemd"
		return a
	}
	id := name
	if !strings.Contains(id, ".") {
		id += ".service"
	}
	us := checks.ShowUnits(c, id)
	if len(us) == 0 || us[0].LoadState == "not-found" {
		a.Severity, a.Verdict = core.Unknown, "there is no unit called "+id
		a.fix("systemctl list-unit-files '*" + strings.TrimSuffix(name, ".service") + "*'")
		return a
	}
	u := us[0]
	now := c.Sys.Now()
	state := u.ActiveState
	if u.SubState != "" && u.SubState != u.ActiveState {
		state += " (" + u.SubState + ")"
	}
	info := []string{fmt.Sprintf("%s — %s", u.ID, u.Description), "state: " + state, "at boot: " + nz(u.FileState, "unknown")}
	if u.ActiveState == "active" && !u.ActiveSince.IsZero() {
		info = append(info, "running since "+core.Ago(now, u.ActiveSince))
	}
	if u.MainPID > 0 {
		info = append(info, "main process: "+c.Owner(u.MainPID))
	}
	if u.Memory > 0 && u.Memory < 1<<62 {
		info = append(info, "memory now: "+core.Bytes(u.Memory))
	}
	if u.Restarts > 0 {
		info = append(info, fmt.Sprintf("restarted %d times since boot", u.Restarts))
	}
	if u.Fragment != "" {
		info = append(info, "unit file: "+u.Fragment)
	}
	for _, d := range u.DropIns {
		info = append(info, "drop-in: "+d)
	}
	a.add("Status", info...)

	why, fix, ct, lim := checks.Explain(c, u)
	for _, l := range lim {
		a.limit(l)
	}
	var logs, cause []string
	for _, w := range why {
		if strings.HasPrefix(w, "log: ") {
			logs = append(logs, strings.TrimPrefix(w, "log: "))
		} else {
			cause = append(cause, w)
		}
	}
	more, _ := checks.UnitLogs(c, u.ID, 10)
	if len(more) > len(logs) {
		logs = more
	}
	switch u.ActiveState {
	case "failed":
		a.Severity = core.Crit
		a.Verdict = u.ID + " failed " + core.Ago(now, u.FailedAt)
		if len(cause) > 0 {
			a.Verdict += ": " + cause[0]
			cause = cause[1:]
		}
	case "active":
		a.Severity = core.OK
		a.Verdict = u.ID + " is running"
		if u.Restarts >= 5 {
			a.Severity = core.Warn
			a.Verdict += fmt.Sprintf(", but it restarted %d times since boot", u.Restarts)
		}
		cause = nil
		for _, ch := range checks.ChangesBefore(c, u, now) {
			cause = append(cause, fmt.Sprintf("%s %s ago (%s)", ch.What, core.Duration(now.Sub(ch.Time)), ch.Time.Format("15:04")))
		}
		if len(cause) > 0 {
			a.add("Changed in the last 24 hours", cause...)
			cause = nil
		}
		if ct != nil && !ct.OK {
			a.Severity = core.Warn
			a.Verdict += ", but its config test fails: the next restart will fail"
		}
		fix = nil
		if ct != nil && !ct.OK {
			fix = append(fix, c.Sudo()+ct.Command)
		}
	default:
		a.Severity = core.Info
		a.Verdict = u.ID + " is " + state
		if u.Result != "" && u.Result != "success" {
			a.Severity = core.Warn
		}
	}
	a.add("Why", cause...)
	if ct != nil {
		if ct.OK {
			a.add("Config test", ct.Command+": OK")
		} else {
			a.add("Config test", append([]string{ct.Command + ": FAILED"}, ct.Errors...)...)
		}
	}
	ls, _ := c.Listeners()
	var pl []string
	for _, l := range ls {
		if l.Unit == u.ID {
			pl = append(pl, l.Proto+" "+l.Addr())
		}
	}
	a.add("Listening on", pl...)
	a.add("Last log lines", logs...)
	a.fix(fix...)
	return a
}

// remoteFS is true for network and FUSE file systems, where a slow server makes programs wait.
func remoteFS(t string) bool {
	switch t {
	case "nfs", "nfs4", "cifs", "smb3", "smbfs", "9p", "virtiofs", "ceph", "glusterfs", "afs", "lustre", "davfs", "sshfs", "fuse":
		return true
	}
	return strings.HasPrefix(t, "fuse.") && t != "fuse.lxcfs" && t != "fuse.portal" && t != "fuse.gvfsd-fuse"
}

func nz(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ---------------------------------------------------------------- port

var portCfgRe = `(?i)(?:^|[\s:"'=])(?:listen|port|bind|http_port|listen_addresses|bind-address|ListenStream)\b[^\n]*?\b%d\b`

// Port explains who listens on a port and who can reach it.
func Port(c *core.Ctx, port int) Answer {
	a := Answer{Topic: "port", Subject: strconv.Itoa(port)}
	ls, full := c.Listeners()
	if !full && !c.Facts.Root {
		a.limit("the process behind other users' sockets")
	}
	svc := serviceName(c, port)
	fw := checks.DetectFirewall(c)
	var mine []core.Listener
	for _, l := range ls {
		if l.Port == port {
			mine = append(mine, l)
		}
	}
	if len(mine) == 0 {
		a.Severity = core.Warn
		a.Verdict = fmt.Sprintf("nothing listens on port %d%s", port, svc)
		var hits []string
		re := regexp.MustCompile(fmt.Sprintf(portCfgRe, port))
		for _, dir := range []string{"/etc/nginx", "/etc/httpd", "/etc/apache2", "/etc/haproxy", "/etc/ssh", "/etc/redis",
			"/etc/redis.conf", "/etc/my.cnf", "/etc/my.cnf.d", "/etc/mysql", "/etc/postgresql", "/etc/systemd/system", "/etc/caddy",
			"/etc/varnish", "/etc/squid", "/etc/docker", "/etc/containers/systemd"} {
			_ = c.Sys.Walk(dir, func(p string, e os.DirEntry, err error) error {
				if err != nil || e.IsDir() || len(hits) >= 6 {
					return nil
				}
				b, err := c.Sys.ReadFile(p)
				if err != nil || len(b) > 1<<20 {
					return nil
				}
				for i, l := range linux.Lines(b) {
					t := strings.TrimSpace(l)
					if strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";") {
						continue
					}
					if re.MatchString(l) {
						hits = append(hits, fmt.Sprintf("%s:%d  %s", p, i+1, core.Clip(t, 80)))
					}
				}
				return nil
			})
		}
		if len(hits) > 0 {
			a.add("Config that mentions this port", hits...)
			a.Verdict += ", but a config file says something should"
			a.fix("# is the service running? nabd checks failed services:", "nabd --only services")
		} else {
			a.add("Config that mentions this port", "none found in the usual folders")
		}
	} else {
		a.Severity = core.OK
		var who []string
		exposed := false
		hidden := "a process this user cannot see"
		if c.Facts.Root {
			hidden = "a process outside this PID namespace (another container or the host)"
		}
		for _, l := range mine {
			scope := "only this machine can connect"
			switch {
			case l.Wildcard():
				scope, exposed = "all addresses: other machines can connect", true
			case !l.Loopback():
				scope, exposed = "address "+l.IP.String()+": machines on that network can connect", true
			}
			owner := hidden
			if l.PID > 0 {
				owner = c.Owner(l.PID)
			}
			who = append(who, fmt.Sprintf("%s %s — %s — %s", l.Proto, l.Addr(), owner, scope))
			if l.PID > 0 && len(who) <= 2 {
				if exe, err := c.Sys.Readlink("/proc/" + strconv.Itoa(l.PID) + "/exe"); err == nil {
					who = append(who, "    program: "+exe+packageOf(c, exe))
				}
			}
		}
		a.add("Listening", who...)
		first := mine[0]
		owner := hidden
		if first.PID > 0 {
			owner = c.Owner(first.PID)
		}
		a.Verdict = fmt.Sprintf("%s listens on port %d%s", owner, port, svc)
		if exposed {
			a.Verdict += ", open to the network"
		} else {
			a.Verdict += ", only for this machine"
		}
		// the same verdict as the ports check of `nabd`
		for _, l := range mine {
			if f, risky := checks.PortRisk(c, l, fw); risky {
				a.Severity, a.Verdict = f.Severity, f.Title
				a.add("Risk", f.Why...)
				a.fix(f.Fix...)
				break
			}
		}
		{
			d := net.Dialer{Timeout: time.Second}
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
			if conn, err := d.Dial("tcp", addr); err == nil {
				conn.Close()
				a.add("Test", "a TCP connect to "+addr+" works")
			} else if strings.HasPrefix(first.Proto, "tcp") && (first.Wildcard() || first.IP.String() == "127.0.0.1") {
				a.add("Test", "a TCP connect to "+addr+" fails: "+err.Error())
			}
		}
	}
	if !fw.Active {
		a.add("Firewall", "no active firewall found: if something listens on all addresses, every machine that can reach this one can connect")
	} else {
		a.add("Firewall", firewallSays(c, fw, port)...)
	}
	return a
}

func serviceName(c *core.Ctx, port int) string {
	b, err := c.Sys.ReadFile("/etc/services")
	if err != nil {
		return ""
	}
	needle := strconv.Itoa(port) + "/tcp"
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[1] == needle && !strings.HasPrefix(f[0], "#") {
			return " (" + f[0] + ")"
		}
	}
	return ""
}

func packageOf(c *core.Ctx, file string) string {
	var r struct {
		out string
		ok  bool
	}
	switch c.Facts.Family() {
	case "rhel", "suse":
		x := c.Sys.Run(5*time.Second, "rpm", "-qf", "--qf", "%{NAME}", file)
		r.out, r.ok = strings.TrimSpace(x.Stdout), x.OK()
	case "debian":
		x := c.Sys.Run(5*time.Second, "dpkg", "-S", file)
		if x.OK() {
			r.out, r.ok = strings.TrimSpace(strings.SplitN(x.Stdout, ":", 2)[0]), true
		}
	case "arch":
		x := c.Sys.Run(5*time.Second, "pacman", "-Qoq", file)
		r.out, r.ok = strings.TrimSpace(x.Stdout), x.OK()
	}
	if r.ok && r.out != "" && !strings.Contains(r.out, " ") {
		return " (package " + r.out + ")"
	}
	return ""
}

func firewallSays(c *core.Ctx, fw checks.Firewall, port int) []string {
	p := strconv.Itoa(port)
	out := []string{fw.Name + " is on"}
	switch fw.Name {
	case "firewalld":
		z := c.Sys.Run(5*time.Second, "firewall-cmd", "--get-default-zone")
		if !z.OK() {
			out = append(out, "could not ask firewalld (run with sudo): "+c.Sudo()+"firewall-cmd --list-all")
			return out
		}
		zone := strings.TrimSpace(z.Stdout)
		lp := c.Sys.Run(5*time.Second, "firewall-cmd", "--zone="+zone, "--list-ports")
		ls := c.Sys.Run(5*time.Second, "firewall-cmd", "--zone="+zone, "--list-services")
		open := strings.Contains(" "+lp.Stdout+" ", " "+p+"/tcp ")
		svc := strings.Trim(serviceName(c, port), " ()")
		if svc != "" && strings.Contains(" "+strings.TrimSpace(ls.Stdout)+" ", " "+svc+" ") {
			open = true
		}
		if open {
			out = append(out, "zone "+zone+": port "+p+" is open")
		} else {
			out = append(out, "zone "+zone+": port "+p+" is closed (other machines are blocked)",
				"to open it: "+c.Sudo()+"firewall-cmd --zone="+zone+" --add-port="+p+"/tcp --permanent && "+c.Sudo()+"firewall-cmd --reload")
		}
	case "ufw":
		r := c.Sys.Run(5*time.Second, "ufw", "status")
		if !r.OK() {
			out = append(out, "could not ask ufw (run with sudo)")
			return out
		}
		if regexp.MustCompile(`(?m)^` + p + `(/tcp)?\s+ALLOW`).MatchString(r.Stdout) {
			out = append(out, "ufw allows port "+p)
		} else {
			out = append(out, "ufw has no allow rule for port "+p, "to open it: "+c.Sudo()+"ufw allow "+p+"/tcp")
		}
	default:
		out = append(out, "check the rules: "+c.Sudo()+"nft list ruleset | grep -w "+p)
	}
	return out
}

// ---------------------------------------------------------------- dns

// DNS checks name resolution. It sends DNS queries to the configured servers.
func DNS(c *core.Ctx, name string) Answer {
	defaultName := name == ""
	if defaultName {
		name = "example.com"
	}
	a := Answer{Topic: "dns", Subject: name, Note: "this check sends DNS queries for " + name + " to your DNS servers"}
	b, err := c.Sys.ReadFile("/etc/resolv.conf")
	if err != nil {
		a.Severity, a.Verdict = core.Crit, "/etc/resolv.conf is missing: no DNS servers"
		return a
	}
	var servers, search []string
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
		if len(f) >= 2 && (f[0] == "search" || f[0] == "domain") {
			search = append(search, f[1:]...)
		}
	}
	setup := []string{"servers: " + strings.Join(servers, ", ")}
	if len(search) > 0 {
		setup = append(setup, "search domains: "+strings.Join(search, " "))
	}
	if t, err := c.Sys.Readlink("/etc/resolv.conf"); err == nil {
		setup = append(setup, "/etc/resolv.conf is a link to "+t)
	}
	for _, l := range linux.Lines(b) {
		if strings.HasPrefix(l, "#") && (strings.Contains(l, "NetworkManager") || strings.Contains(l, "systemd-resolved") || strings.Contains(l, "netconfig") || strings.Contains(l, "resolvconf")) {
			setup = append(setup, "managed by: "+core.Clip(strings.TrimLeft(l, "# "), 70))
			break
		}
	}
	if nb, err := c.Sys.ReadFile("/etc/nsswitch.conf"); err == nil {
		for _, l := range linux.Lines(nb) {
			if strings.HasPrefix(strings.TrimSpace(l), "hosts:") {
				setup = append(setup, "lookup order (nsswitch): "+strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "hosts:")))
			}
		}
	}
	a.add("Setup", setup...)
	if hb, err := c.Sys.ReadFile("/etc/hosts"); err == nil {
		for _, l := range linux.Lines(hb) {
			f := strings.Fields(l)
			for _, h := range f[1:] {
				if len(f) > 1 && h == name && !strings.HasPrefix(f[0], "#") {
					a.add("/etc/hosts", "has "+name+" → "+f[0]+" (this wins over DNS)")
				}
			}
		}
	}
	ok, nx := 0, 0
	var tests []string
	for _, s := range servers {
		srv := s
		r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 2 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(srv, "53"))
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		t0 := time.Now()
		ips, err := r.LookupHost(ctx, name)
		cancel()
		ms := time.Since(t0).Milliseconds()
		if err != nil {
			var de *net.DNSError
			if errors.As(err, &de) && de.IsNotFound {
				nx++
				tests = append(tests, fmt.Sprintf("%-15s answers in %d ms: no such name", srv, ms))
				continue
			}
			tests = append(tests, fmt.Sprintf("%-15s NO ANSWER after %d ms: %s", srv, ms, shortErr(err)))
			continue
		}
		ok++
		tests = append(tests, fmt.Sprintf("%-15s %s in %d ms", srv, strings.Join(first(ips, 3), ", "), ms))
	}
	a.add("Ask each server for "+name, tests...)
	t0 := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	ips, err := net.DefaultResolver.LookupHost(ctx, name)
	cancel()
	sysLine := fmt.Sprintf("the system finds %s in %d ms", strings.Join(first(ips, 3), ", "), time.Since(t0).Milliseconds())
	if err != nil {
		sysLine = "the system cannot find " + name + ": " + shortErr(err)
	}
	a.add("System lookup", sysLine)
	switch {
	case len(servers) == 0:
		a.Severity, a.Verdict = core.Crit, "no DNS server is set in /etc/resolv.conf"
	case ok == 0 && nx == 0:
		a.Severity, a.Verdict = core.Crit, "no DNS server answers: names cannot be found"
		a.fix("# check the network to the DNS servers (UDP/TCP port 53) or set other servers")
	case ok == 0 && defaultName:
		a.Severity, a.Verdict = core.Crit, "the DNS servers answer, but say that example.com does not exist (it always exists): they block or filter names"
		a.fix("# a proxy, a sandbox or a filtering DNS service is in the way; set other servers or ask the network team")
	case ok == 0:
		a.Severity, a.Verdict = core.Warn, "every DNS server says that "+name+" does not exist: check the name and its DNS records"
		a.fix("# test another name: nabd why dns example.com")
	case nx > 0:
		a.Severity, a.Verdict = core.Warn, fmt.Sprintf("the DNS servers do not agree: %d find %s, %d say it does not exist", ok, name, nx)
		a.fix("# a server with old or filtered data: remove it or fix it")
	case ok < len(servers):
		a.Severity, a.Verdict = core.Warn, fmt.Sprintf("%d of %d DNS servers do not answer: lookups can be slow (the system waits before it tries the next)", len(servers)-ok, len(servers))
		a.fix("# remove or fix the server that fails")
	case err != nil:
		a.Severity, a.Verdict = core.Warn, "the DNS servers answer, but the system lookup fails"
	default:
		a.Severity, a.Verdict = core.OK, "DNS works: "+name+" was found by every server"
	}
	return a
}

func shortErr(err error) string {
	s := err.Error()
	if i := strings.LastIndex(s, ": "); i > 0 {
		s = s[i+2:]
	}
	return s
}

func first(s []string, n int) []string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// ---------------------------------------------------------------- boot

// Boot explains the last boot.
func Boot(c *core.Ctx) Answer {
	a := Answer{Topic: "boot"}
	now := c.Sys.Now()
	a.Severity = core.OK
	a.Verdict = "booted " + core.Ago(now, c.Facts.BootTime) + " (" + c.Facts.BootTime.Format("Mon 2006-01-02 15:04") + ")"
	a.add("Boot", "kernel "+c.Facts.Kernel, "up "+c.Facts.UptimeText())
	if !c.Facts.Systemd {
		return a
	}
	if r := c.Sys.Run(8*time.Second, "systemd-analyze"); r.OK() {
		a.add("Boot", strings.TrimSpace(strings.Split(r.Stdout, "\n")[0]))
	}
	if r := c.Sys.Run(8*time.Second, "systemd-analyze", "blame", "--no-pager"); r.OK() {
		var bl []string
		for i, l := range strings.Split(strings.TrimSpace(r.Stdout), "\n") {
			if i == 5 {
				break
			}
			bl = append(bl, strings.TrimSpace(l))
		}
		a.add("Slowest units", bl...)
	}
	r := c.Sys.Run(8*time.Second, "systemctl", "list-units", "--failed", "--all", "--plain", "--no-legend", "--no-pager")
	var failed []string
	for _, l := range strings.Split(r.Stdout, "\n") {
		if f := strings.Fields(l); len(f) > 0 && strings.Contains(f[0], ".") {
			failed = append(failed, f[0])
		}
	}
	if len(failed) > 0 {
		a.add("Failed units", failed...)
		a.Severity = core.Warn
		a.fix("nabd --only services")
	}
	prev := c.Sys.Run(8*time.Second, "journalctl", "-b", "-1", "-n", "30", "-o", "short-iso", "--no-pager", "-q")
	switch {
	case prev.OK() && strings.TrimSpace(prev.Stdout) != "":
		t := prev.Stdout
		clean := strings.Contains(t, "Journal stopped") || strings.Contains(t, "systemd-shutdown") ||
			strings.Contains(t, "Reached target") && (strings.Contains(t, "Power-Off") || strings.Contains(t, "Reboot") || strings.Contains(t, "Shutdown"))
		lines := strings.Split(strings.TrimSpace(t), "\n")
		last := lines[len(lines)-1]
		if clean {
			a.add("Previous boot", "ended with a clean shutdown", "last line: "+core.Clip(last, 120))
		} else {
			a.add("Previous boot", "did NOT end with a clean shutdown: a crash, a power loss, a hard reset or a kernel panic",
				"last line before the end: "+core.Clip(last, 120))
			a.Severity = core.Warn
			a.Verdict += "; the boot before it ended without a clean shutdown"
			a.fix("journalctl -b -1 -e   # the end of the previous boot", "journalctl -k -b -1 | tail -50   # kernel messages before it stopped")
		}
	case !c.Facts.Root:
		a.limit("the log of the previous boot")
	default:
		a.add("Previous boot", "no log of the previous boot (the journal is not stored on disk: Storage=persistent in journald.conf keeps it)")
	}
	return a
}
