// Package sys is the only place where nabd touches the machine.
//
// Every check reads files and runs programs through the Sys interface, so the
// tests can give it a fake machine (a folder with /proc, /etc … and canned
// command output). nabd never writes to the system: there is no write method.
package sys

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Result is the outcome of one program run.
type Result struct {
	Code     int
	Stdout   string
	Stderr   string
	NotFound bool // the program is not installed
	TimedOut bool
	Err      error
}

// OK is true when the program ran and exited with 0.
func (r Result) OK() bool { return r.Err == nil && r.Code == 0 && !r.NotFound && !r.TimedOut }

// Output is stdout and stderr together, trimmed.
func (r Result) Output() string {
	return strings.TrimSpace(strings.TrimSpace(r.Stdout) + "\n" + strings.TrimSpace(r.Stderr))
}

// Statfs is the size of a mounted file system in bytes and inodes.
type Statfs struct {
	Size, Free, Avail uint64
	Files, FilesFree  uint64
}

// Sys is a read-only view of the machine.
type Sys interface {
	ReadFile(path string) ([]byte, error)
	ReadDir(path string) ([]fs.DirEntry, error)
	Stat(path string) (fs.FileInfo, error)
	Lstat(path string) (fs.FileInfo, error)
	Readlink(path string) (string, error)
	Statfs(path string) (Statfs, error)
	// Walk is filepath.WalkDir with machine paths.
	Walk(root string, fn fs.WalkDirFunc) error
	Run(timeout time.Duration, name string, args ...string) Result
	Has(program string) bool
	Now() time.Time
	Uid() int
	Hostname() string
	Env(name string) string
}

// Real is the running machine. Root is "/" in normal use.
type Real struct{ Root string }

// extra folders for programs: normal users often have no sbin in PATH,
// but sshd, nginx -t and needs-restarting live there.
var sbinDirs = []string{"/usr/local/sbin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/bin", "/bin"}

func (r Real) p(path string) string {
	if r.Root == "" || r.Root == "/" {
		return path
	}
	return filepath.Join(r.Root, path)
}

func (r Real) ReadFile(path string) ([]byte, error)       { return os.ReadFile(r.p(path)) }
func (r Real) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(r.p(path)) }
func (r Real) Stat(path string) (fs.FileInfo, error)      { return os.Stat(r.p(path)) }
func (r Real) Lstat(path string) (fs.FileInfo, error)     { return os.Lstat(r.p(path)) }
func (r Real) Readlink(path string) (string, error)       { return os.Readlink(r.p(path)) }
func (r Real) Now() time.Time                             { return time.Now() }
func (r Real) Uid() int                                   { return os.Getuid() }
func (r Real) Env(name string) string                     { return os.Getenv(name) }

func (r Real) Hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return h
}

func (r Real) Statfs(path string) (Statfs, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(r.p(path), &st); err != nil {
		return Statfs{}, err
	}
	bs := uint64(st.Frsize)
	if bs == 0 {
		bs = uint64(st.Bsize)
	}
	return Statfs{
		Size:      uint64(st.Blocks) * bs,
		Free:      uint64(st.Bfree) * bs,
		Avail:     uint64(st.Bavail) * bs,
		Files:     uint64(st.Files),
		FilesFree: uint64(st.Ffree),
	}, nil
}

func (r Real) Walk(root string, fn fs.WalkDirFunc) error {
	base := r.p(root)
	return filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if r.Root != "" && r.Root != "/" {
			path = "/" + strings.TrimPrefix(strings.TrimPrefix(path, r.Root), "/")
		}
		return fn(path, d, err)
	})
}

func (r Real) lookPath(name string) (string, bool) {
	if strings.Contains(name, "/") {
		if st, err := os.Stat(name); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return name, true
		}
		return "", false
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, true
	}
	for _, d := range sbinDirs {
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() && st.Mode()&0o111 != 0 {
			return p, true
		}
	}
	return "", false
}

// Has is true when the program is installed.
func (r Real) Has(program string) bool {
	_, ok := r.lookPath(program)
	return ok
}

// Run runs a program with a time limit, the C locale (stable output to parse)
// and no pager or colours. On timeout the whole process group is killed.
func (r Real) Run(timeout time.Duration, name string, args ...string) Result {
	path, ok := r.lookPath(name)
	if !ok {
		return Result{NotFound: true, Code: -1, Err: errors.New(name + ": not installed")}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.Command(path, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "SYSTEMD_COLORS=0", "SYSTEMD_PAGER=",
		"SYSTEMD_LESS=", "PAGER=cat", "NO_COLOR=1", "TERM=dumb")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var out, errb limitedBuffer
	out.max, errb.max = 4<<20, 1<<20
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Start(); err != nil {
		return Result{Code: -1, Err: err}
	}
	running.Store(cmd.Process.Pid, struct{}{})
	defer running.Delete(cmd.Process.Pid)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	timedOut := false
	select {
	case err = <-done:
	case <-ctx.Done():
		timedOut = true
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		select {
		case err = <-done:
		case <-time.After(2 * time.Second):
		}
	}
	res := Result{Stdout: out.String(), Stderr: errb.String()}
	if timedOut {
		res.TimedOut, res.Code, res.Err = true, -1, context.DeadlineExceeded
		return res
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			res.Code = ee.ExitCode()
		} else {
			res.Code, res.Err = -1, err
		}
	}
	return res
}

// running holds the process groups of programs that still run.
var running sync.Map

// KillRunning kills every program nabd started that still runs. main calls it
// on Ctrl-C: the programs are in their own process groups, so the terminal
// signal does not reach them.
func KillRunning() {
	running.Range(func(k, _ interface{}) bool {
		_ = syscall.Kill(-k.(int), syscall.SIGKILL)
		return true
	})
}

// limitedBuffer keeps at most max bytes, so a chatty program cannot use all memory.
type limitedBuffer struct {
	bytes.Buffer
	max int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if room := b.max - b.Len(); room > 0 {
		if len(p) > room {
			p = p[:room]
		}
		b.Buffer.Write(p)
	}
	return n, nil
}
