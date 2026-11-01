// Package core holds the types every check uses: findings, the shared
// context with caches, and the runner that runs checks in parallel.
package core

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/s0sta/nabd/internal/sys"
)

// Severity of a finding. The numbers are not the exit codes; see ExitCode.
type Severity int

const (
	OK Severity = iota
	Info
	Warn
	Crit
	Unknown
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warn:
		return "warn"
	case Crit:
		return "crit"
	case Unknown:
		return "unknown"
	}
	return "ok"
}

// MarshalJSON writes the name, not the number.
func (s Severity) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Rank orders severities for sorting: crit > warn > unknown > info > ok.
func (s Severity) Rank() int {
	switch s {
	case Crit:
		return 4
	case Warn:
		return 3
	case Unknown:
		return 2
	case Info:
		return 1
	}
	return 0
}

// ExitCode follows the Nagios plugin rule: 0 ok, 1 warning, 2 critical, 3 unknown.
func ExitCode(s Severity) int {
	switch s {
	case Warn:
		return 1
	case Crit:
		return 2
	case Unknown:
		return 3
	}
	return 0
}

// Finding is one problem (or note) with its cause and the fix.
type Finding struct {
	ID       string                 `json:"id"`
	Check    string                 `json:"check"`
	Severity Severity               `json:"severity"`
	Title    string                 `json:"title"`
	Why      []string               `json:"why,omitempty"`
	Fix      []string               `json:"fix,omitempty"`
	Note     string                 `json:"note,omitempty"`
	Data     map[string]interface{} `json:"data,omitempty"`
}

// CheckResult is the state of one check after it ran.
type CheckResult struct {
	Name    string `json:"name"`
	Title   string `json:"title"`
	Status  string `json:"status"` // ok, info, warn, crit, unknown, skipped
	Detail  string `json:"detail,omitempty"`
	Limited string `json:"limited,omitempty"`
	Millis  int64  `json:"ms"`
}

// Check is one area of the machine.
type Check struct {
	Name  string
	Title string
	Help  string
	Run   func(c *Ctx, o *Out)
}

// Out collects what one check found.
type Out struct {
	check    string
	findings []Finding
	ok       []string
	skip     string
	limited  []string
	mu       sync.Mutex
}

// Add records a finding.
func (o *Out) Add(f Finding) {
	o.mu.Lock()
	defer o.mu.Unlock()
	f.Check = o.check
	if !strings.Contains(f.ID, ".") {
		f.ID = o.check + "." + f.ID
	}
	o.findings = append(o.findings, f)
}

// OK records a short note of what was fine ("12 mounts, fullest / 61%").
func (o *Out) OK(format string, a ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.ok = append(o.ok, fmt.Sprintf(format, a...))
}

// Skip marks the check as not useful on this machine.
func (o *Out) Skip(format string, a ...interface{}) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.skip = fmt.Sprintf(format, a...)
}

// Limit notes what the check could not see without root.
func (o *Out) Limit(what string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, l := range o.limited {
		if l == what {
			return
		}
	}
	o.limited = append(o.limited, what)
}

// Options change how checks behave.
type Options struct {
	Only    map[string]bool
	Skip    map[string]bool
	Timeout time.Duration // per check
}

// Ctx is shared by all checks of one run. Expensive reads are cached.
type Ctx struct {
	Sys   sys.Sys
	Facts Facts

	onceProcs  sync.Once
	procs      []Proc
	onceKlog   sync.Once
	klog       KernelLog
	onceMounts sync.Once
	mounts     []MountUsage
	onceSock   sync.Once
	socks      []Listener
	sockFull   bool
	oncePkg    sync.Once
	pkgEvents  []PkgEvent
	pkgSource  string
	onceSample sync.Once
	sample     CPUSample

	// SampleTime is how long the CPU sample waits (1 s; tests use 0).
	SampleTime time.Duration
}

// NewCtx reads the basic facts of the machine.
func NewCtx(s sys.Sys) *Ctx {
	return &Ctx{Sys: s, Facts: ReadFacts(s), SampleTime: time.Second}
}

// Run runs the checks in parallel and returns their results and all findings,
// sorted by severity (worst first).
func Run(c *Ctx, checks []Check, opt Options) ([]CheckResult, []Finding) {
	if opt.Timeout <= 0 {
		opt.Timeout = 15 * time.Second
	}
	type done struct {
		res CheckResult
		fs  []Finding
	}
	results := make([]done, len(checks))
	var wg sync.WaitGroup
	for i := range checks {
		ch := checks[i]
		if len(opt.Only) > 0 && !opt.Only[ch.Name] || opt.Skip[ch.Name] {
			continue
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i] = runOne(c, ch, opt.Timeout)
		}(i)
	}
	wg.Wait()
	var res []CheckResult
	var all []Finding
	for _, d := range results {
		if d.res.Name == "" {
			continue
		}
		res = append(res, d.res)
		all = append(all, d.fs...)
	}
	SortFindings(all)
	return res, all
}

func runOne(c *Ctx, ch Check, timeout time.Duration) (d struct {
	res CheckResult
	fs  []Finding
}) {
	o := &Out{check: ch.Name}
	start := time.Now()
	finished := make(chan struct{})
	var panicked interface{}
	go func() {
		defer close(finished)
		defer func() { panicked = recover() }()
		ch.Run(c, o)
	}()
	timedOut := false
	select {
	case <-finished:
	case <-time.After(timeout):
		timedOut = true
	}
	d.res = CheckResult{Name: ch.Name, Title: ch.Title, Millis: time.Since(start).Milliseconds()}
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case timedOut:
		d.fs = []Finding{{ID: ch.Name + ".timeout", Check: ch.Name, Severity: Unknown,
			Title: fmt.Sprintf("the %s check did not finish in %s", ch.Name, timeout),
			Why:   []string{"a program or a file system did not answer (a hung network mount can do this)"}}}
		d.res.Status = "unknown"
		return d
	case panicked != nil:
		d.fs = []Finding{{ID: ch.Name + ".error", Check: ch.Name, Severity: Unknown,
			Title: fmt.Sprintf("the %s check failed: %v", ch.Name, panicked),
			Why:   []string{"this is a bug in nabd; please report it with `nabd --json` output"}}}
		d.res.Status = "unknown"
		return d
	}
	d.fs = append(d.fs, o.findings...)
	d.res.Limited = strings.Join(o.limited, ", ")
	worst := OK
	for _, f := range o.findings {
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	switch {
	case o.skip != "" && len(o.findings) == 0:
		d.res.Status, d.res.Detail = "skipped", o.skip
	case worst == OK:
		d.res.Status, d.res.Detail = "ok", strings.Join(o.ok, "; ")
	default:
		d.res.Status, d.res.Detail = worst.String(), strings.Join(o.ok, "; ")
	}
	return d
}

// SortFindings puts the worst first, then by check name.
func SortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		return fs[i].Check < fs[j].Check
	})
}

// Overall is the worst severity that counts for the exit code (info does not).
func Overall(fs []Finding) Severity {
	worst := OK
	for _, f := range fs {
		if f.Severity == Info {
			continue
		}
		if f.Severity.Rank() > worst.Rank() {
			worst = f.Severity
		}
	}
	return worst
}
