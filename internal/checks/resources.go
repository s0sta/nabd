package checks

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Memory checks free memory, swap, memory pressure and OOM kills.
var Memory = core.Check{
	Name:  "memory",
	Title: "Memory",
	Help:  "Available memory (or the container limit), swap, memory pressure (PSI) and processes the kernel killed because memory ran out.",
	Run:   runMemory,
}

// CPU checks load, CPU use, I/O wait, VM steal and CPU pressure.
var CPU = core.Check{
	Name:  "cpu",
	Title: "CPU and load",
	Help:  "Load per CPU, CPU use, time spent waiting for the disk (iowait), CPU taken by the hypervisor (steal) and CPU pressure (PSI), with the busiest processes.",
	Run:   runCPU,
}

var oomRe = regexp.MustCompile(`(?i)out of memory: kill|oom-kill:|killed process \d+ \(|memory cgroup out of memory`)
var oomVictimRe = regexp.MustCompile(`(?:[Kk]illed process (\d+) \(([^)]+)\)|task=([^,]+),pid=(\d+))`)

func runMemory(c *core.Ctx, o *core.Out) {
	b, err := c.Sys.ReadFile("/proc/meminfo")
	if err != nil {
		o.Skip("no /proc/meminfo")
		return
	}
	mi := linux.Meminfo(b)
	total, avail := mi["MemTotal"], mi["MemAvailable"]
	if _, ok := mi["MemAvailable"]; !ok {
		avail = mi["MemFree"] + mi["Buffers"] + mi["Cached"]
	}
	scope := "this machine"
	if lim, used, ok := cgroupMemory(c); ok {
		total, avail, scope = lim, 0, "this container"
		if lim > used {
			avail = lim - used
		}
	}
	if total == 0 {
		o.Skip("memory size unknown")
		return
	}
	pct := 100 * float64(avail) / float64(total)
	o.OK("%s of %s available", core.Bytes(avail), core.Bytes(total))

	top := c.TopMemory(3)
	topWhy := func() []string {
		var w []string
		for _, p := range top {
			w = append(w, fmt.Sprintf("%s uses %s", c.Owner(p.PID), core.Bytes(p.RSS)))
		}
		return w
	}
	psi, havePSI := c.PSI("memory")
	full60 := psi["full"]["avg60"]
	if pct < 10 {
		sev := core.Warn
		if pct < 5 {
			sev = core.Crit
		}
		f := core.Finding{ID: "low", Severity: sev,
			Title: fmt.Sprintf("only %s of %s memory is free in %s (%.0f%%)", core.Bytes(avail), core.Bytes(total), scope, pct),
			Why:   topWhy(),
			Fix:   []string{"nabd why memory   # who uses it, and OOM kills"},
			Data:  map[string]interface{}{"available_bytes": avail, "total_bytes": total, "percent_free": round(pct)}}
		if havePSI && full60 >= 1 {
			f.Why = append(f.Why, fmt.Sprintf("all programs were stalled waiting for memory %.0f%% of the last minute", full60))
		}
		o.Add(f)
	} else if havePSI && full60 >= 10 {
		o.Add(core.Finding{ID: "pressure", Severity: core.Warn,
			Title: fmt.Sprintf("programs were stalled waiting for memory %.0f%% of the last minute", full60),
			Why:   append([]string{"memory is not empty, but the kernel works hard to find free pages (reclaim and swap)"}, topWhy()...),
			Fix:   []string{"nabd why memory"}})
	}
	if st, sf := mi["SwapTotal"], mi["SwapFree"]; st > 0 && scope == "this machine" {
		used := st - sf
		if sp := 100 * float64(used) / float64(st); sp >= 80 {
			o.Add(core.Finding{ID: "swap", Severity: core.Warn,
				Title: fmt.Sprintf("swap is %.0f%% used (%s of %s)", sp, core.Bytes(used), core.Bytes(st)),
				Why:   []string{"when swap is full as well, the kernel must kill a process (OOM killer)"},
				Fix:   []string{"nabd why memory"}})
		}
	}
	kl := c.Kernel()
	if kl.Limited {
		o.Limit("kernel log")
	}
	ooms := kl.Grep(oomRe)
	var victims []string
	seen := map[string]bool{}
	for i := len(ooms) - 1; i >= 0 && len(victims) < 5; i-- {
		m := oomVictimRe.FindStringSubmatch(ooms[i].Text)
		if m == nil {
			continue
		}
		pid, name := m[1], m[2]
		if name == "" {
			pid, name = m[4], m[3]
		}
		key := pid + name
		if seen[key] {
			continue
		}
		seen[key] = true
		victims = append(victims, fmt.Sprintf("%s: %s (pid %s), %s", ooms[i].Time.Format("15:04"), name, pid, core.Ago(c.Sys.Now(), ooms[i].Time)))
	}
	if len(victims) > 0 {
		o.Add(core.Finding{ID: "oom", Severity: core.Warn,
			Title: fmt.Sprintf("the kernel killed %s because memory ran out (since boot)", core.Plural(len(seen), "process", "processes")),
			Why:   victims,
			Fix: []string{"nabd why memory",
				"# stop one service from taking all memory: " + c.Sudo() + "systemctl edit SERVICE  → [Service] MemoryMax=2G"},
			Data: map[string]interface{}{"oom_kills": len(seen)}})
	}
}

// cgroupMemory reads the memory limit of a container (cgroup v2).
func cgroupMemory(c *core.Ctx) (limit, used uint64, ok bool) {
	if c.Facts.Container == "" {
		return 0, 0, false
	}
	mb, err := c.Sys.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0, 0, false
	}
	ms := strings.TrimSpace(string(mb))
	if ms == "max" {
		return 0, 0, false
	}
	limit, err = strconv.ParseUint(ms, 10, 64)
	if err != nil {
		return 0, 0, false
	}
	cb, err := c.Sys.ReadFile("/sys/fs/cgroup/memory.current")
	if err != nil {
		return 0, 0, false
	}
	used, _ = strconv.ParseUint(strings.TrimSpace(string(cb)), 10, 64)
	if sb, err := c.Sys.ReadFile("/sys/fs/cgroup/memory.stat"); err == nil {
		for _, l := range linux.Lines(sb) {
			if f := strings.Fields(l); len(f) == 2 && f[0] == "inactive_file" {
				n, _ := strconv.ParseUint(f[1], 10, 64)
				if n < used {
					used -= n // page cache the kernel can drop
				}
			}
		}
	}
	return limit, used, true
}

func runCPU(c *core.Ctx, o *core.Out) {
	s := c.Sample()
	cpus := c.Facts.CPUs
	if cpus < 1 {
		cpus = 1
	}
	topWhy := func(n int) []string {
		var w []string
		for i, p := range s.Top {
			if i == n {
				break
			}
			w = append(w, fmt.Sprintf("%s uses %.0f%% CPU", c.Owner(p.PID), p.Percent))
		}
		return w
	}
	if s.Valid {
		o.OK("%.0f%% busy on %d CPUs", s.Busy, cpus)
	}
	if c.Facts.Container == "" {
		if b, err := c.Sys.ReadFile("/proc/loadavg"); err == nil {
			if l1, l5, l15, err := linux.Loadavg(b); err == nil {
				per := l5 / float64(cpus)
				o.OK("load %.2f %.2f %.2f", l1, l5, l15)
				if per >= 1.5 {
					sev := core.Warn
					if per >= 3 {
						sev = core.Crit
					}
					f := core.Finding{ID: "load", Severity: sev,
						Title: fmt.Sprintf("load is %.1f on %d CPUs (%.1f per CPU, 5-minute average)", l5, cpus, per),
						Data:  map[string]interface{}{"load1": l1, "load5": l5, "load15": l15, "cpus": cpus}}
					switch {
					case s.Valid && s.Busy >= 80:
						f.Why = append([]string{fmt.Sprintf("the CPUs are %.0f%% busy: there is more work than CPU", s.Busy)}, topWhy(3)...)
					case s.Valid && len(s.DState) > 0:
						f.Why = []string{fmt.Sprintf("%s wait for the disk or network storage (D state); load counts them too",
							core.Plural(len(s.DState), "process", "processes"))}
					case s.Valid:
						f.Why = append([]string{fmt.Sprintf("the CPUs are only %.0f%% busy now: the load came from a short burst or from waiting for I/O", s.Busy)}, topWhy(2)...)
					}
					f.Fix = []string{"nabd why slow"}
					o.Add(f)
				}
			}
		}
	}
	if s.Valid && s.Iowait >= 20 {
		o.Add(core.Finding{ID: "iowait", Severity: core.Warn,
			Title: fmt.Sprintf("the CPUs wait for the disk %.0f%% of the time (iowait)", s.Iowait),
			Why:   []string{"a disk is too slow for the work, a disk is failing, or something reads or writes a lot"},
			Fix:   []string{c.Sudo() + "nabd why slow   # the processes that read and write the most"}})
	}
	if s.Valid && s.Steal >= 10 && c.Facts.Container == "" {
		o.Add(core.Finding{ID: "steal", Severity: core.Warn,
			Title: fmt.Sprintf("the hypervisor takes %.0f%% of this VM's CPU time (steal)", s.Steal),
			Why: []string{"this virtual machine gets less CPU than it wants",
				"common causes: busy neighbours on the same host, or burst CPU credits are used up (AWS t2/t3/t4g, Azure B-series)"},
			Fix: []string{"# check the CPU credit balance in your cloud console, or move to a size with fixed CPU"}})
	}
	if psi, ok := c.PSI("cpu"); ok {
		if v := psi["some"]["avg60"]; v >= 40 {
			o.Add(core.Finding{ID: "pressure", Severity: core.Warn,
				Title: fmt.Sprintf("programs waited for a free CPU %.0f%% of the last minute", v),
				Why:   topWhy(3),
				Fix:   []string{"nabd why slow"}})
		}
	}
}
