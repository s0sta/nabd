// Package render turns a report into text: a colour terminal view, JSON,
// Markdown for tickets, a Nagios plugin line and Prometheus metrics.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"
	"unsafe"

	"github.com/s0sta/nabd/internal/core"
)

// Schema is the version of the JSON format. It only changes when a field is
// removed or changes meaning; new fields can be added at any time.
const Schema = "nabd/1"

// Report is one run of the checks.
type Report struct {
	Version  string
	Facts    core.Facts
	Time     time.Time
	Duration time.Duration
	Checks   []core.CheckResult
	Findings []core.Finding
	Status   core.Severity
}

// Style is how the terminal output looks.
type Style struct {
	Color   bool
	ASCII   bool
	Verbose bool
	Quiet   bool
	Width   int
}

// AutoStyle picks colours and symbols for the terminal.
func AutoStyle(color string, ascii bool) Style {
	st := Style{ASCII: ascii, Width: termWidth()}
	tty := isTTY(os.Stdout)
	switch color {
	case "always":
		st.Color = true
	case "never":
		st.Color = false
	default:
		st.Color = tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	}
	if t := os.Getenv("TERM"); t == "linux" || t == "dumb" {
		st.ASCII = st.ASCII || t == "dumb"
	}
	if st.Width <= 0 {
		st.Width = 100
	}
	return st
}

func isTTY(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func termWidth() int {
	if c := os.Getenv("COLUMNS"); c != "" {
		var n int
		fmt.Sscanf(c, "%d", &n)
		if n > 20 {
			return n
		}
	}
	var ws struct{ Row, Col, X, Y uint16 }
	if _, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&ws))); e == 0 && ws.Col > 20 {
		return int(ws.Col)
	}
	return 0
}

// ansi colours
const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	cyan   = "\x1b[36m"
	gray   = "\x1b[90m"
)

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + reset
}

// Mark is the symbol and label of a severity.
func (s Style) Mark(sev core.Severity) string {
	type m struct{ sym, ascii, label, color string }
	var x m
	switch sev {
	case core.Crit:
		x = m{"✖", "x", "CRIT", red + bold}
	case core.Warn:
		x = m{"▲", "!", "WARN", yellow + bold}
	case core.Info:
		x = m{"●", "i", "INFO", blue}
	case core.Unknown:
		x = m{"?", "?", "UNKN", gray}
	default:
		x = m{"✔", "+", "OK", green}
	}
	sym := x.sym
	if s.ASCII {
		sym = x.ascii
	}
	return s.c(x.color, sym+" "+fmt.Sprintf("%-4s", x.label))
}

// Human writes the terminal report.
func Human(w io.Writer, r Report, st Style) {
	fmt.Fprintf(w, "%s %s\n\n", st.c(bold, "nabd "+r.Version), st.c(dim, "· "+r.Facts.Summary()))
	shown := 0
	for _, f := range r.Findings {
		if st.Quiet && f.Severity == core.Info {
			continue
		}
		Finding(w, f, st)
		shown++
	}
	var ok, skipped []core.CheckResult
	var limited []string
	seenLimit := map[string]bool{}
	for _, c := range r.Checks {
		switch c.Status {
		case "ok":
			ok = append(ok, c)
		case "skipped":
			skipped = append(skipped, c)
		}
		for _, l := range strings.Split(c.Limited, ", ") {
			if l != "" && !seenLimit[l] {
				seenLimit[l] = true
				limited = append(limited, l)
			}
		}
	}
	if shown > 0 {
		fmt.Fprintln(w)
	}
	if st.Verbose {
		for _, c := range r.Checks {
			if c.Status == "skipped" {
				continue
			}
			fmt.Fprintf(w, " %s  %-9s %s %s\n", st.Mark(sevOf(c.Status)), c.Name, c.Detail, st.c(gray, fmt.Sprintf("(%d ms)", c.Millis)))
		}
		for _, c := range skipped {
			fmt.Fprintf(w, " %s  %-9s %s\n", st.c(gray, sym(st, "○", "-")+" SKIP"), c.Name, st.c(gray, c.Detail))
		}
	} else {
		if len(ok) > 0 {
			names := make([]string, len(ok))
			for i, c := range ok {
				names[i] = c.Name
			}
			fmt.Fprintf(w, " %s %s\n", st.c(green+bold, sym(st, "✔", "+")+" "+core.Plural(len(ok), "check OK", "checks OK")),
				st.c(dim, " "+strings.Join(names, " · ")))
		}
		if len(skipped) > 0 && !st.Quiet {
			names := make([]string, len(skipped))
			for i, c := range skipped {
				names[i] = c.Name
			}
			fmt.Fprintf(w, " %s %s\n", st.c(gray, sym(st, "○", "-")+" skipped:"), st.c(gray, strings.Join(names, " · ")+"  (nabd -v says why)"))
		}
	}
	if len(limited) > 0 && !st.Quiet {
		if r.Facts.Root {
			fmt.Fprintf(w, " %s %s\n", st.c(blue, sym(st, "○", "-")+" nabd could not read:"), st.c(dim, clipList(limited, 4)))
		} else {
			fmt.Fprintf(w, " %s %s\n", st.c(blue, sym(st, "○", "-")+" without root nabd could not read:"),
				st.c(dim, clipList(limited, 4)+" — run: sudo nabd"))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, " "+Verdict(r, st)+st.c(gray, fmt.Sprintf(" · %.1f s", r.Duration.Seconds())))
	if shown > 0 && !st.Quiet {
		fmt.Fprintln(w, st.c(gray, " more: nabd why disk|slow|memory|service NAME|port N|dns|boot · nabd changes · nabd --json"))
	}
}

func clipList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, "; ")
	}
	return strings.Join(items[:n], "; ") + fmt.Sprintf("; +%d more", len(items)-n)
}

func sym(st Style, u, a string) string {
	if st.ASCII {
		return a
	}
	return u
}

// Verdict is the last line: "2 problems: 1 critical, 1 warning".
func Verdict(r Report, st Style) string {
	n := map[core.Severity]int{}
	for _, f := range r.Findings {
		n[f.Severity]++
	}
	if n[core.Crit]+n[core.Warn]+n[core.Unknown] == 0 {
		msg := "healthy: no problems found"
		if n[core.Info] > 0 {
			msg += " (" + core.Plural(n[core.Info], "note", "notes") + ")"
		}
		return st.c(green+bold, msg)
	}
	var parts []string
	if n[core.Crit] > 0 {
		parts = append(parts, st.c(red+bold, fmt.Sprintf("%d critical", n[core.Crit])))
	}
	if n[core.Warn] > 0 {
		parts = append(parts, st.c(yellow+bold, core.Plural(n[core.Warn], "warning", "warnings")))
	}
	if n[core.Unknown] > 0 {
		parts = append(parts, st.c(gray, fmt.Sprintf("%d unknown", n[core.Unknown])))
	}
	if n[core.Info] > 0 {
		parts = append(parts, st.c(blue, core.Plural(n[core.Info], "note", "notes")))
	}
	total := n[core.Crit] + n[core.Warn] + n[core.Unknown]
	return st.c(bold, core.Plural(total, "problem", "problems")+": ") + strings.Join(parts, ", ")
}

func sevOf(status string) core.Severity {
	switch status {
	case "crit":
		return core.Crit
	case "warn":
		return core.Warn
	case "info":
		return core.Info
	case "unknown":
		return core.Unknown
	}
	return core.OK
}

// Finding writes one finding with its why, fix and note.
func Finding(w io.Writer, f core.Finding, st Style) {
	fmt.Fprintf(w, " %s  %s %s\n", st.Mark(f.Severity), st.c(gray, fmt.Sprintf("%-9s", f.Check)), st.c(bold, f.Title))
	indent := strings.Repeat(" ", 18)
	label := func(l string) string { return st.c(gray, fmt.Sprintf("%-6s", l)) }
	width := st.Width - 24
	if width < 40 {
		width = 40
	}
	for i, x := range f.Why {
		for j, line := range wrap(x, width) {
			l := "      "
			if i == 0 && j == 0 {
				l = label("why")
			}
			fmt.Fprintf(w, "%s%s%s\n", indent, l, line)
		}
	}
	for i, x := range f.Fix {
		l := "      "
		if i == 0 {
			l = label("fix")
		}
		if strings.HasPrefix(x, "#") {
			fmt.Fprintf(w, "%s%s%s\n", indent, l, st.c(gray, x))
			continue
		}
		cmd, comment, _ := strings.Cut(x, "   #")
		line := st.c(cyan, cmd)
		if comment != "" {
			line += st.c(gray, "   #"+comment)
		}
		fmt.Fprintf(w, "%s%s%s\n", indent, l, line)
	}
	if f.Note != "" {
		fmt.Fprintf(w, "%s%s%s\n", indent, label("note"), st.c(yellow, f.Note))
	}
}

func wrap(s string, width int) []string {
	if utf8.RuneCountInString(s) <= width {
		return []string{s}
	}
	var out []string
	var cur strings.Builder
	for _, word := range strings.Fields(s) {
		if cur.Len() > 0 && utf8.RuneCountInString(cur.String())+1+utf8.RuneCountInString(word) > width {
			out = append(out, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(word)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// JSON writes the machine-readable report.
func JSON(w io.Writer, r Report) error {
	n := map[string]int{"crit": 0, "warn": 0, "info": 0, "unknown": 0}
	for _, f := range r.Findings {
		n[f.Severity.String()]++
	}
	okChecks := 0
	for _, c := range r.Checks {
		if c.Status == "ok" {
			okChecks++
		}
	}
	findings := r.Findings
	if findings == nil {
		findings = []core.Finding{}
	}
	out := map[string]interface{}{
		"schema":       Schema,
		"version":      r.Version,
		"generated_at": r.Time.Format(time.RFC3339),
		"host":         r.Facts,
		"status":       r.Status.String(),
		"exit_code":    core.ExitCode(r.Status),
		"summary": map[string]interface{}{"crit": n["crit"], "warn": n["warn"], "info": n["info"], "unknown": n["unknown"],
			"ok_checks": okChecks, "duration_ms": r.Duration.Milliseconds()},
		"findings": findings,
		"checks":   r.Checks,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// Markdown writes a report to paste into a ticket or a chat.
func Markdown(w io.Writer, r Report) {
	icon := map[core.Severity]string{core.Crit: "🔴", core.Warn: "🟠", core.Info: "🔵", core.Unknown: "⚪"}
	st := Style{}
	fmt.Fprintf(w, "## nabd: %s — %s\n\n", r.Facts.Hostname, Verdict(r, st))
	fmt.Fprintf(w, "%s · %s · nabd %s\n\n", r.Facts.Summary(), r.Time.Format("2006-01-02 15:04 MST"), r.Version)
	if len(r.Findings) > 0 {
		fmt.Fprintln(w, "| | Check | Problem |")
		fmt.Fprintln(w, "|---|---|---|")
		for _, f := range r.Findings {
			fmt.Fprintf(w, "| %s %s | %s | %s |\n", icon[f.Severity], f.Severity, f.Check, mdCell(f.Title))
		}
		fmt.Fprintln(w)
		for _, f := range r.Findings {
			fmt.Fprintf(w, "### %s %s\n\n", icon[f.Severity], f.Title)
			for _, x := range f.Why {
				fmt.Fprintf(w, "- %s\n", x)
			}
			if len(f.Fix) > 0 {
				fmt.Fprintf(w, "\n```sh\n%s\n```\n", strings.Join(f.Fix, "\n"))
			}
			if f.Note != "" {
				fmt.Fprintf(w, "\n> %s\n", f.Note)
			}
			fmt.Fprintln(w)
		}
	}
	var ok []string
	for _, c := range r.Checks {
		if c.Status == "ok" {
			ok = append(ok, c.Name)
		}
	}
	sort.Strings(ok)
	if len(ok) > 0 {
		fmt.Fprintf(w, "**OK:** %s\n", strings.Join(ok, ", "))
	}
}

func mdCell(s string) string { return strings.ReplaceAll(s, "|", "\\|") }

// Nagios writes the plugin output: status line, long output and perfdata.
func Nagios(w io.Writer, r Report) {
	label := map[core.Severity]string{core.OK: "OK", core.Warn: "WARNING", core.Crit: "CRITICAL", core.Unknown: "UNKNOWN"}[r.Status]
	n := map[core.Severity]int{}
	var titles []string
	for _, f := range r.Findings {
		n[f.Severity]++
		if f.Severity != core.Info && len(titles) < 3 {
			titles = append(titles, f.Title)
		}
	}
	msg := "no problems"
	if len(titles) > 0 {
		msg = strings.Join(titles, "; ")
		if extra := n[core.Crit] + n[core.Warn] + n[core.Unknown] - len(titles); extra > 0 {
			msg += fmt.Sprintf("; +%d more", extra)
		}
	}
	fmt.Fprintf(w, "NABD %s - %s | crit=%d;;;0 warn=%d;;;0 unknown=%d;;;0 checks=%d;;;0 time=%.3fs;;;0\n",
		label, strings.ReplaceAll(msg, "|", "/"), n[core.Crit], n[core.Warn], n[core.Unknown], len(r.Checks), r.Duration.Seconds())
	for _, f := range r.Findings {
		if f.Severity == core.Info {
			continue
		}
		fmt.Fprintf(w, "[%s] %s: %s\n", strings.ToUpper(f.Severity.String()), f.Check, strings.ReplaceAll(f.Title, "|", "/"))
	}
}

// Prometheus writes metrics in the text format (for the node_exporter textfile collector).
func Prometheus(w io.Writer, r Report) {
	val := map[string]int{"ok": 0, "info": 0, "warn": 1, "crit": 2, "unknown": 3, "skipped": -1}
	fmt.Fprintln(w, "# HELP nabd_status Overall result: 0 ok, 1 warning, 2 critical, 3 unknown.")
	fmt.Fprintln(w, "# TYPE nabd_status gauge")
	fmt.Fprintf(w, "nabd_status %d\n", core.ExitCode(r.Status))
	fmt.Fprintln(w, "# HELP nabd_findings Number of findings by severity.")
	fmt.Fprintln(w, "# TYPE nabd_findings gauge")
	n := map[string]int{}
	for _, f := range r.Findings {
		n[f.Severity.String()]++
	}
	for _, s := range []string{"crit", "warn", "unknown", "info"} {
		fmt.Fprintf(w, "nabd_findings{severity=%q} %d\n", s, n[s])
	}
	fmt.Fprintln(w, "# HELP nabd_check_status Result of each check: 0 ok, 1 warning, 2 critical, 3 unknown, -1 skipped.")
	fmt.Fprintln(w, "# TYPE nabd_check_status gauge")
	for _, c := range r.Checks {
		fmt.Fprintf(w, "nabd_check_status{check=%s} %d\n", promLabel(c.Name), val[c.Status])
	}
	fmt.Fprintln(w, "# HELP nabd_finding A current finding (1 while it exists).")
	fmt.Fprintln(w, "# TYPE nabd_finding gauge")
	for _, f := range r.Findings {
		fmt.Fprintf(w, "nabd_finding{check=%s,id=%s,severity=%s,title=%s} 1\n",
			promLabel(f.Check), promLabel(f.ID), promLabel(f.Severity.String()), promLabel(f.Title))
	}
	fmt.Fprintln(w, "# HELP nabd_last_run_timestamp_seconds When nabd ran.")
	fmt.Fprintln(w, "# TYPE nabd_last_run_timestamp_seconds gauge")
	fmt.Fprintf(w, "nabd_last_run_timestamp_seconds %d\n", r.Time.Unix())
	fmt.Fprintln(w, "# HELP nabd_run_duration_seconds How long the checks took.")
	fmt.Fprintln(w, "# TYPE nabd_run_duration_seconds gauge")
	fmt.Fprintf(w, "nabd_run_duration_seconds %.3f\n", r.Duration.Seconds())
}

func promLabel(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
