package core

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/linux"
)

// clkTck is USER_HZ, 100 on every Linux architecture nabd supports.
const clkTck = 100.0

// ProcCPU is the CPU use of one process during the sample.
type ProcCPU struct {
	PID     int     `json:"pid"`
	Name    string  `json:"name"`
	Percent float64 `json:"percent"` // 100 = one full CPU
}

// CPUSample is what the CPU did during a short sample.
type CPUSample struct {
	Seconds float64   `json:"seconds"`
	Busy    float64   `json:"busy_percent"`
	Iowait  float64   `json:"iowait_percent"`
	Steal   float64   `json:"steal_percent"`
	Top     []ProcCPU `json:"top"`
	DState  []int     `json:"d_state_pids,omitempty"` // in D state at the start and at the end
	Valid   bool      `json:"valid"`
	SwapIn  uint64    `json:"swap_in_pages"`
	SwapOut uint64    `json:"swap_out_pages"`
}

// Sample measures the CPU for SampleTime (once per run).
func (c *Ctx) Sample() CPUSample {
	c.onceSample.Do(func() { c.sample = takeSample(c) })
	return c.sample
}

func takeSample(c *Ctx) CPUSample {
	read := func() (linux.CPUTimes, map[int]linux.ProcStat, map[string]uint64, bool) {
		b, err := c.Sys.ReadFile("/proc/stat")
		if err != nil {
			return linux.CPUTimes{}, nil, nil, false
		}
		t, err := linux.ProcStatCPU(b)
		if err != nil {
			return linux.CPUTimes{}, nil, nil, false
		}
		procs := map[int]linux.ProcStat{}
		for _, pid := range PIDs(c.Sys) {
			if pb, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil {
				if st, err := linux.ParseProcStat(pb); err == nil {
					procs[pid] = st
				}
			}
		}
		vm := map[string]uint64{}
		if vb, err := c.Sys.ReadFile("/proc/vmstat"); err == nil {
			for _, l := range linux.Lines(vb) {
				f := strings.Fields(l)
				if len(f) == 2 && (f[0] == "pswpin" || f[0] == "pswpout") {
					vm[f[0]], _ = strconv.ParseUint(f[1], 10, 64)
				}
			}
		}
		return t, procs, vm, true
	}
	t0, p0, v0, ok := read()
	if !ok {
		return CPUSample{}
	}
	start := time.Now()
	if c.SampleTime > 0 {
		time.Sleep(c.SampleTime)
	}
	t1, p1, v1, ok := read()
	if !ok {
		return CPUSample{}
	}
	secs := time.Since(start).Seconds()
	if c.SampleTime == 0 {
		secs = 1 // tests: the fake files hold one second of ticks
	}
	s := CPUSample{Seconds: secs, Valid: true}
	dt := float64(t1.Total() - t0.Total())
	if dt > 0 {
		idle := float64((t1.Idle - t0.Idle) + (t1.Iowait - t0.Iowait))
		s.Busy = 100 * (dt - idle) / dt
		s.Iowait = 100 * float64(t1.Iowait-t0.Iowait) / dt
		s.Steal = 100 * float64(t1.Steal-t0.Steal) / dt
	}
	for pid, b := range p1 {
		a, ok := p0[pid]
		if !ok || a.StartTime != b.StartTime {
			continue
		}
		used := float64((b.UTime + b.STime) - (a.UTime + a.STime))
		if pct := 100 * used / clkTck / secs; pct >= 1 {
			s.Top = append(s.Top, ProcCPU{pid, b.Comm, pct})
		}
		if a.State == 'D' && b.State == 'D' {
			s.DState = append(s.DState, pid)
		}
	}
	sort.Slice(s.Top, func(i, j int) bool { return s.Top[i].Percent > s.Top[j].Percent })
	if len(s.Top) > 10 {
		s.Top = s.Top[:10]
	}
	sort.Ints(s.DState)
	s.SwapIn, s.SwapOut = v1["pswpin"]-v0["pswpin"], v1["pswpout"]-v0["pswpout"]
	return s
}

// PSI reads pressure stall information for cpu, memory or io. In a container
// it prefers the container's own cgroup file.
func (c *Ctx) PSI(kind string) (map[string]map[string]float64, bool) {
	paths := []string{"/proc/pressure/" + kind}
	if c.Facts.Container != "" {
		paths = append([]string{"/sys/fs/cgroup/" + kind + ".pressure"}, paths...)
	}
	for _, p := range paths {
		if b, err := c.Sys.ReadFile(p); err == nil {
			if v := linux.Pressure(b); len(v) > 0 {
				return v, true
			}
		}
	}
	return nil, false
}

// TopMemory lists the processes that use the most memory (RSS), biggest first.
func (c *Ctx) TopMemory(n int) []ProcMem {
	var out []ProcMem
	page := uint64(pageSize())
	for _, p := range c.Procs() {
		if p.RSSPages > 0 {
			out = append(out, ProcMem{p.PID, p.Comm, uint64(p.RSSPages) * page})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RSS > out[j].RSS })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ProcMem is the memory of one process.
type ProcMem struct {
	PID  int    `json:"pid"`
	Name string `json:"name"`
	RSS  uint64 `json:"rss_bytes"`
}
