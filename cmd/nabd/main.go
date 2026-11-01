// Command nabd is a doctor for Linux servers. One command checks the whole
// machine, says in plain words what is wrong and why, and gives the command
// that fixes it. It only reads: it never changes the system.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/s0sta/nabd/internal/changes"
	"github.com/s0sta/nabd/internal/checks"
	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
	"github.com/s0sta/nabd/internal/snapshot"
	"github.com/s0sta/nabd/internal/sys"
	"github.com/s0sta/nabd/internal/why"
)

// version is set by the build: -ldflags "-X main.version=1.2.3". Without it,
// "go install …@vX.Y.Z" gives the module version, else releaseVersion is used.
var version = ""

// releaseVersion is the version of this source tree (a distro build without
// ldflags still reports the right version).
const releaseVersion = "0.1.0"

func init() {
	if version != "" {
		return
	}
	if bi, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(bi.Main.Version, "v") {
		version = strings.TrimPrefix(bi.Main.Version, "v")
		return
	}
	version = releaseVersion
}

// exit codes for errors of nabd itself (bad options, unreadable files).
const exitUnknown = 3

// stdout and machine are variables so the tests can use a fake machine.
var (
	stdout  io.Writer = os.Stdout
	stderr  io.Writer = os.Stderr
	machine           = func() sys.Sys { return sys.Real{} }
)

const usageText = `nabd — a doctor for Linux servers

Usage:
  nabd [check] [options]       check the machine (the default command)
  nabd why TOPIC [ARG]         explain one problem in depth
  nabd changes [--since 24h]   what changed: packages, /etc, SSH keys, cron, logins, services
  nabd snapshot [--keep N]     save the security state: users, admins, SUID files, ports, keys …
  nabd diff [OLD [NEW]]        compare two snapshots, or the last snapshot with now
  nabd checks                  list the checks
  nabd version                 print the version

Topics for "nabd why":
  disk [PATH] · slow · memory · service NAME · port N · dns [NAME] · boot
  short forms work too: nabd why nginx · nabd why 443 · nabd why /var

Output:
  --json             JSON for scripts (schema nabd/1)
  --md               Markdown for a ticket or a chat
  --nagios           Nagios / Icinga plugin output (check)
  --prometheus       Prometheus text format (check)
  -o, --output FILE  write to FILE (atomic) instead of the terminal
  -v, --verbose      show every check, also the ones that are OK
  -q, --quiet        show only problems, no notes
  --color WHEN       auto, always or never (NO_COLOR is respected)
  --ascii            plain ASCII symbols

Options:
  --only LIST        run only these checks (comma list; see nabd checks)
  --skip LIST        do not run these checks
  --timeout DUR      time limit for each check (default 15s)
  --since WHEN       for changes and diff: 2h, 3d, 1w, today, yesterday, boot, 2026-11-01
  --keep N           snapshot: keep only the newest N snapshots
  --list             snapshot: list the saved snapshots
  --dir DIR          snapshot and diff: the snapshot folder

Exit status: 0 healthy · 1 warning · 2 critical · 3 unknown (the Nagios rule)
             changes and diff: 0 nothing changed · 1 changes · 2 critical change

nabd only reads. It never changes the system; "nabd snapshot" writes only into its own folder.
More: man nabd · https://github.com/s0sta/nabd
`

// ---------------------------------------------------------------- options

type options struct {
	format  string // human, json, md, nagios, prometheus
	output  string
	verbose bool
	quiet   bool
	ascii   bool
	color   string
	only    string
	skip    string
	timeout time.Duration
	since   string
	keep    int
	list    bool
	dir     string
	help    bool
	args    []string
}

type usageError struct{ msg string }

func (e usageError) Error() string { return e.msg }

func badUsage(format string, a ...interface{}) error { return usageError{fmt.Sprintf(format, a...)} }

var formats = map[string]string{"--json": "json", "--md": "md", "--markdown": "md", "--nagios": "nagios", "--prometheus": "prometheus", "--prom": "prometheus"}

var boolFlags = map[string]func(o *options){
	"-v": func(o *options) { o.verbose = true }, "--verbose": func(o *options) { o.verbose = true },
	"-q": func(o *options) { o.quiet = true }, "--quiet": func(o *options) { o.quiet = true },
	"--ascii": func(o *options) { o.ascii = true }, "--no-color": func(o *options) { o.color = "never" },
	"--no-colour": func(o *options) { o.color = "never" }, "--list": func(o *options) { o.list = true },
	"-h": func(o *options) { o.help = true }, "--help": func(o *options) { o.help = true },
}

var valueFlags = map[string]func(o *options, v string) error{
	"-o": func(o *options, v string) error { o.output = v; return nil }, "--output": func(o *options, v string) error { o.output = v; return nil },
	"--color": setColor, "--colour": setColor,
	"--only":  func(o *options, v string) error { o.only = v; return nil },
	"--skip":  func(o *options, v string) error { o.skip = v; return nil },
	"--since": func(o *options, v string) error { o.since = v; return nil },
	"--dir":   func(o *options, v string) error { o.dir = v; return nil },
	"--timeout": func(o *options, v string) error {
		d, err := parseDuration(v)
		if err != nil || d <= 0 {
			return badUsage("--timeout wants a time like 30s or 2m, not %q", v)
		}
		o.timeout = d
		return nil
	},
	"--keep": func(o *options, v string) error {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return badUsage("--keep wants a number of 1 or more, not %q", v)
		}
		o.keep = n
		return nil
	},
}

func setColor(o *options, v string) error {
	switch v {
	case "auto", "always", "never":
		o.color = v
		return nil
	case "yes", "on", "force":
		o.color = "always"
		return nil
	case "no", "off", "none":
		o.color = "never"
		return nil
	}
	return badUsage("--color wants auto, always or never, not %q", v)
}

// parse reads options anywhere on the line: "nabd why disk --json" and
// "nabd --json why disk" are the same.
func parse(argv []string) (options, error) {
	o := options{color: "auto"}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			o.args = append(o.args, argv[i+1:]...)
			break
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			o.args = append(o.args, a)
			continue
		}
		name, val, hasVal := strings.Cut(a, "=")
		if f, ok := formats[name]; ok && !hasVal {
			if o.format != "" && o.format != f {
				return o, badUsage("choose one output: %s or %s", flagOf(o.format), name)
			}
			o.format = f
			continue
		}
		if set, ok := boolFlags[name]; ok && !hasVal {
			set(&o)
			continue
		}
		if set, ok := valueFlags[name]; ok {
			if !hasVal {
				if i+1 >= len(argv) {
					return o, badUsage("%s needs a value", name)
				}
				i++
				val = argv[i]
			}
			if err := set(&o, val); err != nil {
				return o, err
			}
			continue
		}
		// -vq style
		if len(a) > 2 && a[1] != '-' && !hasVal {
			okAll := true
			for _, r := range a[1:] {
				if _, ok := boolFlags["-"+string(r)]; !ok {
					okAll = false
				}
			}
			if okAll {
				for _, r := range a[1:] {
					boolFlags["-"+string(r)](&o)
				}
				continue
			}
		}
		if a == "--version" || a == "-V" {
			o.args = append([]string{"version"}, o.args...)
			continue
		}
		return o, badUsage("unknown option %s%s", name, suggest(name, allFlags()))
	}
	if o.format == "" {
		o.format = "human"
	}
	return o, nil
}

func flagOf(format string) string {
	for k, v := range formats {
		if v == format && k != "--markdown" && k != "--prom" {
			return k
		}
	}
	return format
}

func allFlags() []string {
	var out []string
	for k := range formats {
		out = append(out, k)
	}
	for k := range boolFlags {
		out = append(out, k)
	}
	for k := range valueFlags {
		out = append(out, k)
	}
	return append(out, "--version")
}

// closest is the choice with the smallest edit distance (dashes ignored).
func closest(got string, choices []string) (string, int) {
	best, bestD := "", 1<<30
	for _, c := range choices {
		if d := distance(strings.TrimLeft(got, "-"), strings.TrimLeft(c, "-")); d < bestD {
			best, bestD = c, d
		}
	}
	return best, bestD
}

// suggest returns " (did you mean X?)" for a near miss.
func suggest(got string, choices []string) string {
	if best, d := closest(got, choices); best != "" && d <= 2 {
		return " (did you mean " + best + "?)"
	}
	return ""
}

// distance is the edit distance with swapped neighbours counted as one
// edit (optimal string alignment), so "slwo" is one step from "slow".
func distance(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	d := make([][]int, len(ra)+1)
	for i := range d {
		d[i] = make([]int, len(rb)+1)
		d[i][0] = i
	}
	for j := range d[0] {
		d[0][j] = j
	}
	for i := 1; i <= len(ra); i++ {
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d[i][j] = minInt(minInt(d[i-1][j]+1, d[i][j-1]+1), d[i-1][j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d[i][j] = minInt(d[i][j], d[i-2][j-2]+1)
			}
		}
	}
	return d[len(ra)][len(rb)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// parseDuration also knows days (d) and weeks (w).
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	for _, u := range []struct {
		suffix string
		d      time.Duration
	}{{"w", 7 * 24 * time.Hour}, {"d", 24 * time.Hour}} {
		if strings.HasSuffix(s, u.suffix) {
			n, err := strconv.ParseFloat(strings.TrimSuffix(s, u.suffix), 64)
			if err != nil || n < 0 {
				return 0, fmt.Errorf("bad time %q", s)
			}
			return time.Duration(n * float64(u.d)), nil
		}
	}
	return time.ParseDuration(s)
}

// parseSince turns --since into a time and a label.
func parseSince(s string, now, boot time.Time) (time.Time, string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "":
		return now.Add(-24 * time.Hour), "last 24 hours", nil
	case "boot", "reboot", "start":
		return boot, "since boot (" + boot.In(time.Local).Format("Mon 2 Jan 15:04") + ")", nil
	case "today":
		t := now.In(time.Local)
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local), "today", nil
	case "yesterday":
		t := now.In(time.Local).AddDate(0, 0, -1)
		return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.Local), "since yesterday", nil
	}
	if d, err := parseDuration(s); err == nil {
		if d <= 0 {
			return now, "", badUsage("--since wants a time in the past, not %q", s)
		}
		return now.Add(-d), "last " + core.Duration(d), nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02T15:04", "2006-01-02 15:04:05", "2006-01-02 15:04", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			if t.After(now) {
				return now, "", badUsage("--since %s is in the future", s)
			}
			return t, "since " + t.In(time.Local).Format("Mon 2 Jan 2006 15:04"), nil
		}
	}
	return now, "", badUsage("--since wants 2h, 3d, 1w, today, yesterday, boot or a date like 2026-11-01, not %q", s)
}

// ---------------------------------------------------------------- output

func (o options) style() render.Style {
	color := o.color
	if o.output != "" && color == "auto" {
		color = "never"
	}
	st := render.AutoStyle(color, o.ascii)
	st.Verbose, st.Quiet = o.verbose, o.quiet
	return st
}

// emit writes to stdout, or atomically to --output.
func (o options) emit(write func(w io.Writer) error) error {
	if o.output == "" || o.output == "-" {
		return write(stdout)
	}
	var buf bytes.Buffer
	if err := write(&buf); err != nil {
		return err
	}
	dir := filepath.Dir(o.output)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(o.output)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), o.output)
}

func (o options) needFormat(cmd string, allowed ...string) error {
	if o.format == "human" {
		return nil
	}
	for _, a := range allowed {
		if a == o.format {
			return nil
		}
	}
	return badUsage("nabd %s has no %s output (it has: human, %s)", cmd, flagOf(o.format), strings.Join(allowedFlags(allowed), ", "))
}

func allowedFlags(f []string) []string {
	out := make([]string, len(f))
	for i, x := range f {
		out[i] = flagOf(x)
	}
	return out
}

// spinner shows that nabd works, on a terminal only. stop clears the line.
func spinner(o options, text string) (stop func()) {
	if o.format != "human" || o.output != "" || !isTTY(os.Stderr) || !isTTY(os.Stdout) || os.Getenv("TERM") == "dumb" {
		return func() {}
	}
	frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	if o.ascii || os.Getenv("TERM") == "linux" {
		frames = []string{"|", "/", "-", `\`}
	}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		t := time.NewTicker(80 * time.Millisecond)
		defer t.Stop()
		for i := 0; ; i++ {
			fmt.Fprintf(os.Stderr, "\r %s %s", frames[i%len(frames)], text)
			select {
			case <-done:
				fmt.Fprint(os.Stderr, "\r\x1b[K")
				return
			case <-t.C:
			}
		}
	}()
	return func() {
		close(done)
		<-finished
	}
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// ---------------------------------------------------------------- main

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		s := <-sig
		sys.KillRunning()
		if isTTY(os.Stderr) {
			fmt.Fprint(os.Stderr, "\r\x1b[K")
		}
		if s == os.Interrupt {
			os.Exit(130)
		}
		os.Exit(143)
	}()
	os.Exit(run(os.Args[1:]))
}

var commands = []string{"check", "why", "changes", "snapshot", "diff", "checks", "version", "help"}

func run(argv []string) int {
	o, err := parse(argv)
	if err != nil {
		return fail(err)
	}
	cmd := "check"
	if len(o.args) > 0 {
		switch a := o.args[0]; a {
		case "check", "why", "changes", "snapshot", "diff", "checks", "version", "help":
			cmd, o.args = a, o.args[1:]
		case "doctor", "status":
			cmd, o.args = "check", o.args[1:]
		case "change", "changed", "timeline":
			cmd, o.args = "changes", o.args[1:]
		case "snap":
			cmd, o.args = "snapshot", o.args[1:]
		case "list":
			cmd, o.args = "checks", o.args[1:]
		default:
			return fail(badUsage("unknown command %q%s — run: nabd help", a, suggest(a, commands)))
		}
	}
	if o.help {
		return help(cmd)
	}
	switch cmd {
	case "help":
		if len(o.args) > 0 {
			return help(o.args[0])
		}
		return help("")
	case "version":
		return cmdVersion(o)
	case "checks":
		return cmdChecks(o)
	case "why":
		return cmdWhy(o)
	case "changes":
		return cmdChanges(o)
	case "snapshot":
		return cmdSnapshot(o)
	case "diff":
		return cmdDiff(o)
	}
	return cmdCheck(o)
}

func fail(err error) int {
	var ue usageError
	if errors.As(err, &ue) {
		fmt.Fprintf(stderr, "nabd: %s\n", ue.msg)
		return exitUnknown
	}
	fmt.Fprintf(stderr, "nabd: %v\n", err)
	return exitUnknown
}

func help(topic string) int {
	switch topic {
	case "why":
		fmt.Fprint(stdout, "nabd why — explain one problem in depth\n\nUsage: nabd why TOPIC [ARG] [--json|--md]\n\n")
		for _, t := range why.Topics {
			fmt.Fprintf(stdout, "  %-16s %s\n", t.Name+" "+t.Args, t.Help)
		}
		fmt.Fprint(stdout, "\nShort forms: nabd why nginx (a service) · nabd why 443 (a port) · nabd why /var (a disk)\n")
	case "changes":
		fmt.Fprint(stdout, `nabd changes — what changed on this machine

Usage: nabd changes [--since WHEN] [--json|--md]

Reads package logs, file times in /etc, SSH keys, cron tables, logins, boots
and failed services. It needs no earlier snapshot. Changes that touch
security (users, sudo, SSH, PAM, cron …) are marked with !.

  --since WHEN   2h, 3d, 1w, today, yesterday, boot or a date (default: 24h)
`)
	case "snapshot", "diff":
		fmt.Fprint(stdout, `nabd snapshot — save the security state of this machine
nabd diff     — compare two states

Usage: nabd snapshot [--keep N] [--list] [--dir DIR]
       nabd diff [OLD [NEW]] [--since WHEN] [--json|--md]

A snapshot holds users, admin group members, SUID/SGID files, open ports,
enabled services, packages, the firewall and SELinux state, kernel settings
and a hash of every file in /etc, SSH authorized_keys and cron tables.
Run it as root for the full picture; the timer in the package does it daily.

OLD and NEW are a snapshot file or name, or: last, prev, first, now.
  nabd diff               the last snapshot → now
  nabd diff prev last     the two newest snapshots
  nabd diff --since 7d    the state of about 7 days ago → now

Snapshots are kept in /var/lib/nabd/snapshots (as root) or in
~/.local/state/nabd/snapshots. diff exits 0 (same), 1 (changes) or 2 (a
critical change: a new UID 0 user or a SUID file in /tmp, /home …).
`)
	case "checks", "check", "":
		fmt.Fprint(stdout, usageText)
		if topic == "checks" || topic == "check" {
			fmt.Fprintln(stdout)
			for _, c := range checks.All() {
				fmt.Fprintf(stdout, "  %-9s %s\n", c.Name, c.Help)
			}
		}
	default:
		return fail(badUsage("no help for %q%s", topic, suggest(topic, commands)))
	}
	return 0
}

// ---------------------------------------------------------------- commands

func cmdVersion(o options) int {
	if o.format == "json" {
		_ = json.NewEncoder(stdout).Encode(map[string]string{"version": version, "go": runtime.Version(), "os": runtime.GOOS, "arch": runtime.GOARCH})
		return 0
	}
	fmt.Fprintf(stdout, "nabd %s (%s, %s/%s)\n", version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return 0
}

func cmdChecks(o options) int {
	all := checks.All()
	if o.format == "json" {
		type row struct{ Name, Title, Help string }
		var rows []row
		for _, c := range all {
			rows = append(rows, row{c.Name, c.Title, c.Help})
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return 0
	}
	st := o.style()
	for _, c := range all {
		name := c.Name
		if st.Color {
			name = "\x1b[1m" + fmt.Sprintf("%-9s", name) + "\x1b[0m"
		} else {
			name = fmt.Sprintf("%-9s", name)
		}
		fmt.Fprintf(stdout, "  %s %s\n", name, c.Help)
	}
	return 0
}

func checkSet(list string) (map[string]bool, error) {
	if list == "" {
		return nil, nil
	}
	known := map[string]bool{}
	var names []string
	for _, c := range checks.All() {
		known[c.Name] = true
		names = append(names, c.Name)
	}
	out := map[string]bool{}
	for _, n := range strings.Split(list, ",") {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if !known[n] {
			return nil, badUsage("there is no check %q%s — run: nabd checks", n, suggest(n, names))
		}
		out[n] = true
	}
	return out, nil
}

func cmdCheck(o options) int {
	if len(o.args) > 0 {
		return fail(badUsage("nabd check takes no arguments (got %q) — did you mean: nabd why %s", o.args[0], o.args[0]))
	}
	only, err := checkSet(o.only)
	if err != nil {
		return fail(err)
	}
	skip, err := checkSet(o.skip)
	if err != nil {
		return fail(err)
	}
	c := core.NewCtx(machine())
	start := time.Now()
	stop := spinner(o, "checking "+c.Facts.Hostname+" …")
	res, fs := core.Run(c, checks.All(), core.Options{Only: only, Skip: skip, Timeout: o.timeout})
	stop()
	r := render.Report{Version: version, Facts: c.Facts, Time: start, Duration: time.Since(start), Checks: res, Findings: fs, Status: core.Overall(fs)}
	st := o.style()
	err = o.emit(func(w io.Writer) error {
		switch o.format {
		case "json":
			return render.JSON(w, r)
		case "md":
			render.Markdown(w, r)
		case "nagios":
			render.Nagios(w, r)
		case "prometheus":
			render.Prometheus(w, r)
		default:
			render.Human(w, r, st)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	return core.ExitCode(r.Status)
}

var whyAlias = map[string]string{"mem": "memory", "ram": "memory", "oom": "memory", "swap": "memory",
	"svc": "service", "unit": "service", "cpu": "slow", "load": "slow", "perf": "slow", "io": "slow",
	"ports": "port", "space": "disk", "df": "disk", "full": "disk", "resolve": "dns", "startup": "boot", "reboot": "boot"}

func cmdWhy(o options) int {
	if err := o.needFormat("why", "json", "md"); err != nil {
		return fail(err)
	}
	if len(o.args) == 0 {
		return help("why")
	}
	topic, rest := strings.ToLower(o.args[0]), o.args[1:]
	if t, ok := whyAlias[topic]; ok {
		topic = t
	}
	known := map[string]bool{}
	var names []string
	for _, t := range why.Topics {
		known[t.Name] = true
		names = append(names, t.Name)
	}
	switch {
	case known[topic]:
	case isPort(o.args[0]):
		topic, rest = "port", o.args[:1]
	case strings.HasPrefix(o.args[0], "/") || strings.HasPrefix(o.args[0], "."):
		topic, rest = "disk", o.args[:1]
	default:
		// a typo of a topic ("slwo") is an error; any other word is a service name
		if best, d := closest(topic, names); len(topic) >= 3 && d <= 1 {
			return fail(badUsage("unknown topic %q (did you mean %s?)", o.args[0], best))
		}
		topic, rest = "service", o.args[:1] // nabd why nginx
	}
	if len(rest) > 1 {
		return fail(badUsage("nabd why %s takes one argument, got %d", topic, len(rest)))
	}
	arg := ""
	if len(rest) == 1 {
		arg = rest[0]
	}
	c := core.NewCtx(machine())
	stop := spinner(o, "looking at "+topic+" …")
	if topic == "disk" && arg != "" {
		if abs, err := filepath.Abs(arg); err == nil {
			arg = abs
		}
		if _, err := c.Sys.Stat(arg); err != nil {
			stop()
			if os.IsNotExist(err) {
				return fail(fmt.Errorf("%s: there is no such file or folder", arg))
			}
			return fail(err)
		}
	}
	var a why.Answer
	switch topic {
	case "disk":
		budget := 20 * time.Second
		if o.timeout > 0 {
			budget = o.timeout
		}
		a = why.Disk(c, arg, budget)
	case "slow":
		a = why.Slow(c)
	case "memory":
		a = why.Memory(c)
	case "service":
		if arg == "" {
			stop()
			return fail(badUsage("nabd why service needs a name, like: nabd why service nginx"))
		}
		a = why.Service(c, arg)
	case "port":
		n, err := strconv.Atoi(strings.TrimPrefix(arg, ":"))
		if err != nil || n < 1 || n > 65535 {
			stop()
			return fail(badUsage("nabd why port needs a port number from 1 to 65535, like: nabd why port 443"))
		}
		a = why.Port(c, n)
	case "dns":
		a = why.DNS(c, arg)
	case "boot":
		a = why.Boot(c)
	}
	stop()
	st := o.style()
	err := o.emit(func(w io.Writer) error {
		switch o.format {
		case "json":
			return why.JSON(w, a, c.Facts, version)
		case "md":
			why.Markdown(w, a, c.Facts)
		default:
			why.Human(w, a, st, c.Facts)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	return core.ExitCode(a.Severity)
}

func isPort(s string) bool {
	s = strings.TrimPrefix(s, ":")
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

func cmdChanges(o options) int {
	if err := o.needFormat("changes", "json", "md"); err != nil {
		return fail(err)
	}
	if len(o.args) > 0 {
		return fail(badUsage("nabd changes takes no arguments; use --since, like: nabd changes --since 3d"))
	}
	c := core.NewCtx(machine())
	now := c.Sys.Now()
	since, label, err := parseSince(o.since, now, c.Facts.BootTime)
	if err != nil {
		return fail(err)
	}
	stop := spinner(o, "reading logs …")
	r := changes.Collect(c, since)
	stop()
	st := o.style()
	err = o.emit(func(w io.Writer) error {
		switch o.format {
		case "json":
			return changes.JSON(w, r, c.Facts, version)
		case "md":
			changes.Markdown(w, r, c.Facts, label)
		default:
			changes.Human(w, r, st, c.Facts, now, label)
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	if len(r.Events) == 0 {
		return 0
	}
	return 1
}

func snapDir(o options) string {
	if o.dir != "" {
		return o.dir
	}
	return snapshot.Dir(os.Geteuid() == 0)
}

func cmdSnapshot(o options) int {
	if err := o.needFormat("snapshot", "json"); err != nil {
		return fail(err)
	}
	if len(o.args) > 0 {
		return fail(badUsage("nabd snapshot takes no arguments (to compare, run: nabd diff)"))
	}
	dir := snapDir(o)
	if o.list {
		return listSnapshots(o, dir)
	}
	c := core.NewCtx(machine())
	stop := spinner(o, "reading the state of "+c.Facts.Hostname+" …")
	s := snapshot.Take(c, version)
	stop()
	before, _ := snapshot.List(dir)
	path, err := snapshot.Save(dir, s, o.keep)
	if err != nil {
		if os.IsPermission(err) {
			return fail(fmt.Errorf("cannot write %s: %v — run it with sudo, or choose a folder with --dir", dir, err))
		}
		return fail(err)
	}
	var prev *snapshot.State
	if len(before) > 0 {
		if p, err := snapshot.Load(before[len(before)-1]); err == nil && p.Host == s.Host {
			prev = &p
		}
	}
	if o.format == "json" {
		out := map[string]interface{}{"schema": render.Schema, "version": version, "kind": "snapshot", "file": path,
			"time": s.Time, "host": s.Host, "root": s.Root, "counts": counts(s)}
		if prev != nil {
			r := snapshot.Report{From: snapshot.SideOf(*prev, before[len(before)-1]), To: snapshot.SideOf(s, path), Items: snapshot.Diff(*prev, s)}
			out["since_previous"] = map[string]interface{}{"file": before[len(before)-1], "differences": len(r.Items), "status": r.Worst().String()}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}
	n := counts(s)
	fmt.Fprintf(stdout, "saved %s\n  %d users · %d admin members · %d SUID/SGID files · %d open ports · %d enabled services · %d packages · %d files\n",
		path, n["users"], n["admins"], n["suid"], n["ports"], n["services"], n["packages"], n["files"])
	if !s.Root {
		fmt.Fprintln(stdout, "  note: without root some files are not read (SSH keys and cron of other users); run: sudo nabd snapshot")
	}
	if prev != nil {
		r := snapshot.Report{From: snapshot.SideOf(*prev, before[len(before)-1]), To: snapshot.SideOf(s, path), Items: snapshot.Diff(*prev, s)}
		fmt.Fprintln(stdout, "  "+snapshot.Summary(r))
		if len(r.Items) > 0 {
			fmt.Fprintln(stdout, "  details: nabd diff prev last")
		}
	} else {
		fmt.Fprintln(stdout, "  this is the first snapshot; later, run: nabd diff")
	}
	return 0
}

func counts(s snapshot.State) map[string]int {
	return map[string]int{"users": len(s.Users), "admins": len(s.Admins), "suid": len(s.SUID), "ports": len(s.Listeners),
		"services": len(s.Enabled), "packages": len(s.Packages), "files": len(s.Files)}
}

func listSnapshots(o options, dir string) int {
	list, err := snapshot.List(dir)
	if err != nil && !os.IsNotExist(err) {
		return fail(err)
	}
	if o.format == "json" {
		type row struct {
			File string    `json:"file"`
			Time time.Time `json:"time"`
			Host string    `json:"host"`
			Root bool      `json:"root"`
		}
		rows := []row{}
		for _, p := range list {
			if s, err := snapshot.Load(p); err == nil {
				rows = append(rows, row{p, s.Time, s.Host, s.Root})
			}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows)
		return 0
	}
	if len(list) == 0 {
		fmt.Fprintf(stdout, "no snapshots in %s yet — run: %snabd snapshot\n", dir, sudoHint())
		return 0
	}
	now := time.Now()
	fmt.Fprintf(stdout, "%s\n", dir)
	for i, p := range list {
		s, err := snapshot.Load(p)
		if err != nil {
			fmt.Fprintf(stdout, "  %-22s (cannot read: %v)\n", filepath.Base(p), err)
			continue
		}
		tag := ""
		switch i {
		case len(list) - 1:
			tag = "last"
		case len(list) - 2:
			tag = "prev"
		}
		who := "root"
		if !s.Root {
			who = "user"
		}
		fmt.Fprintf(stdout, "  %-22s %-4s %-18s %s · %s\n", filepath.Base(p), tag, s.Time.In(time.Local).Format("Mon 2 Jan 15:04"), core.Ago(now, s.Time), who)
	}
	return 0
}

func sudoHint() string {
	if os.Geteuid() == 0 {
		return ""
	}
	return "sudo "
}

// resolve finds a snapshot by name: a path, a file name, or last/prev/first/now.
func resolve(sel string, list []string, dir string) (string, error) {
	pick := func(i int, what string) (string, error) {
		if i < 0 || i >= len(list) {
			if len(list) == 0 {
				return "", fmt.Errorf("no snapshots in %s yet — run: %snabd snapshot", dir, sudoHint())
			}
			return "", fmt.Errorf("there is no %s snapshot (only %d in %s)", what, len(list), dir)
		}
		return list[i], nil
	}
	switch strings.ToLower(sel) {
	case "now":
		return "", nil
	case "last", "latest", "newest":
		return pick(len(list)-1, "last")
	case "prev", "previous":
		return pick(len(list)-2, "previous")
	case "first", "oldest":
		return pick(0, "first")
	}
	for _, p := range []string{sel, filepath.Join(dir, sel), filepath.Join(dir, sel+".json")} {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("no snapshot %q (use a file, a name from 'nabd snapshot --list', or last, prev, first, now)", sel)
}

func cmdDiff(o options) int {
	if err := o.needFormat("diff", "json", "md"); err != nil {
		return fail(err)
	}
	if len(o.args) > 2 {
		return fail(badUsage("nabd diff takes at most two snapshots: OLD NEW"))
	}
	dir := snapDir(o)
	list, _ := snapshot.List(dir)
	oldSel, newSel := "last", "now"
	switch len(o.args) {
	case 1:
		oldSel = o.args[0]
	case 2:
		oldSel, newSel = o.args[0], o.args[1]
	}
	now := time.Now()
	note := ""
	var oldPath string
	var err error
	if o.since != "" && len(o.args) > 0 {
		return fail(badUsage("use --since or name the snapshots, not both"))
	}
	if o.since != "" {
		since, _, err := parseSince(o.since, now, core.ReadFacts(machine()).BootTime)
		if err != nil {
			return fail(err)
		}
		// the newest snapshot taken before that time
		for _, p := range list {
			if s, err := snapshot.Load(p); err == nil && !s.Time.After(since) {
				oldPath = p
			}
		}
		if oldPath == "" {
			if len(list) == 0 {
				return fail(fmt.Errorf("no snapshots in %s yet — run: %snabd snapshot", dir, sudoHint()))
			}
			oldPath = list[0]
			note = "no snapshot is that old; nabd uses the oldest one"
		}
	} else if oldPath, err = resolve(oldSel, list, dir); err != nil {
		return fail(err)
	}
	newPath, err := resolve(newSel, list, dir)
	if err != nil {
		return fail(err)
	}
	if oldPath == "" && newPath == "" {
		return fail(badUsage("OLD and NEW are both now"))
	}
	load := func(p string) (snapshot.State, error) {
		if p != "" {
			return snapshot.Load(p)
		}
		c := core.NewCtx(machine())
		stop := spinner(o, "reading the state of "+c.Facts.Hostname+" …")
		defer stop()
		return snapshot.Take(c, version), nil
	}
	a, err := load(oldPath)
	if err != nil {
		return fail(err)
	}
	b, err := load(newPath)
	if err != nil {
		return fail(err)
	}
	r := snapshot.Report{From: snapshot.SideOf(a, oldPath), To: snapshot.SideOf(b, newPath), Items: snapshot.Diff(a, b)}
	st := o.style()
	err = o.emit(func(w io.Writer) error {
		switch o.format {
		case "json":
			return snapshot.JSON(w, r, version)
		case "md":
			snapshot.Markdown(w, r, now)
		default:
			snapshot.Human(w, r, st, now)
			if note != "" {
				fmt.Fprintf(w, " note: %s\n\n", note)
			}
		}
		return nil
	})
	if err != nil {
		return fail(err)
	}
	switch {
	case len(r.Items) == 0:
		return 0
	case r.Worst() == core.Crit:
		return 2
	}
	return 1
}
