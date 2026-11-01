package sys

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Fake is a machine for tests: files live under Root (a temporary folder),
// commands answer from Cmds. Unknown programs are "not installed".
type Fake struct {
	Real
	Cmds     map[string]Result // key: "name arg1 arg2"; "name arg1 *" matches any further arguments
	Programs map[string]bool   // installed programs without a canned answer
	Fs       map[string]Statfs // mount point -> sizes
	UID      int
	Host     string
	Clock    time.Time
	Vars     map[string]string

	mu    sync.Mutex
	calls []string
}

// NewFake makes a fake machine in dir.
func NewFake(dir string) *Fake {
	return &Fake{
		Real:     Real{Root: dir},
		Cmds:     map[string]Result{},
		Programs: map[string]bool{},
		Fs:       map[string]Statfs{},
		Host:     "test-host",
		Clock:    time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC),
		Vars:     map[string]string{},
	}
}

// File writes a file of the fake machine.
func (f *Fake) File(path, content string) {
	full := filepath.Join(f.Root, path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		panic(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		panic(err)
	}
}

// Dir makes a folder of the fake machine.
func (f *Fake) Dir(path string) {
	if err := os.MkdirAll(filepath.Join(f.Root, path), 0o755); err != nil {
		panic(err)
	}
}

// Touch sets the modification time of a fake file.
func (f *Fake) Touch(path string, t time.Time) {
	if err := os.Chtimes(filepath.Join(f.Root, path), t, t); err != nil {
		panic(err)
	}
}

// Symlink makes a link inside the fake machine.
func (f *Fake) Symlink(target, path string) {
	full := filepath.Join(f.Root, path)
	_ = os.MkdirAll(filepath.Dir(full), 0o755)
	if err := os.Symlink(target, full); err != nil {
		panic(err)
	}
}

// Cmd sets the answer of a command line.
func (f *Fake) Cmd(line string, code int, stdout string) {
	f.Cmds[line] = Result{Code: code, Stdout: stdout}
	f.Programs[strings.Fields(line)[0]] = true
}

func (f *Fake) Run(timeout time.Duration, name string, args ...string) Result {
	key := strings.TrimSpace(name + " " + strings.Join(args, " "))
	f.mu.Lock()
	f.calls = append(f.calls, key)
	f.mu.Unlock()
	if r, ok := f.Cmds[key]; ok {
		return r
	}
	// the longest "prefix *" pattern wins
	best, found := "", false
	for k := range f.Cmds {
		if !strings.HasSuffix(k, " *") {
			continue
		}
		prefix := strings.TrimSuffix(k, "*")
		if strings.HasPrefix(key+" ", prefix) && len(k) > len(best) {
			best, found = k, true
		}
	}
	if found {
		return f.Cmds[best]
	}
	if f.Programs[name] {
		return Result{Code: 1, Stderr: "fake: no answer for: " + key}
	}
	return Result{NotFound: true, Code: -1, Err: fmt.Errorf("%s: not installed", name)}
}

// Calls lists the command lines that ran, sorted.
func (f *Fake) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]string(nil), f.calls...)
	sort.Strings(out)
	return out
}

func (f *Fake) Has(program string) bool {
	if f.Programs[program] {
		return true
	}
	for k := range f.Cmds {
		if strings.Fields(k)[0] == program {
			return true
		}
	}
	return false
}

func (f *Fake) Statfs(path string) (Statfs, error) {
	if s, ok := f.Fs[path]; ok {
		return s, nil
	}
	return Statfs{}, fmt.Errorf("statfs %s: no such mount", path)
}

func (f *Fake) Now() time.Time         { return f.Clock }
func (f *Fake) Uid() int               { return f.UID }
func (f *Fake) Hostname() string       { return f.Host }
func (f *Fake) Env(name string) string { return f.Vars[name] }
