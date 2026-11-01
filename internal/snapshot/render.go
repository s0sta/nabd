package snapshot

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
)

// Side describes one side of a comparison.
type Side struct {
	Host  string    `json:"host"`
	Time  time.Time `json:"time"`
	File  string    `json:"file,omitempty"` // empty: the state now
	Root  bool      `json:"root"`
	Files bool      `json:"files_complete"`
}

// SideOf describes a state.
func SideOf(s State, file string) Side {
	return Side{Host: s.Host, Time: s.Time, File: file, Root: s.Root, Files: s.Complete}
}

// Report is the result of "nabd diff".
type Report struct {
	From, To Side
	Items    []Item
}

// Worst is the highest severity of the differences.
func (r Report) Worst() core.Severity {
	w := core.OK
	for _, it := range r.Items {
		if it.Severity.Rank() > w.Rank() {
			w = it.Severity
		}
	}
	return w
}

// Notes are warnings about the comparison itself.
func (r Report) Notes() []string {
	var n []string
	if r.From.Host != r.To.Host {
		n = append(n, fmt.Sprintf("the two states are from different machines (%s and %s)", r.From.Host, r.To.Host))
	}
	if r.From.Root != r.To.Root {
		n = append(n, "one state was taken as root and one without root: some differences come only from that (take both with sudo)")
	} else if !r.To.Root {
		n = append(n, "taken without root: SSH keys and cron tables of other users are not compared")
	}
	if !r.From.Files || !r.To.Files {
		n = append(n, "a file scan stopped at its time limit, so new and removed files are not complete")
	}
	return n
}

func (s Side) label(now time.Time) string {
	if s.File == "" {
		return "now"
	}
	return s.Time.In(time.Local).Format("Mon 2 Jan 15:04") + " (" + core.Ago(now, s.Time) + ")"
}

var changeSym = map[string][2]string{"added": {"+", "+"}, "removed": {"−", "-"}, "changed": {"~", "~"}}

// Human writes the differences for the terminal.
func Human(w io.Writer, r Report, st render.Style, now time.Time) {
	paint := func(code, s string) string {
		if !st.Color {
			return s
		}
		return code + s + "\x1b[0m"
	}
	fmt.Fprintf(w, "%s %s\n", paint("\x1b[1m", "nabd diff"), paint("\x1b[2m", "· "+r.To.Host+" · "+r.From.label(now)+" → "+r.To.label(now)))
	if len(r.Items) == 0 {
		fmt.Fprintf(w, "\n %s\n", paint("\x1b[32;1m", "no differences: users, admin groups, SUID files, open ports, services, files and packages are the same"))
		for _, n := range r.Notes() {
			fmt.Fprintf(w, " %s\n", paint("\x1b[34m", "note: "+n))
		}
		fmt.Fprintln(w)
		return
	}
	area := ""
	shown := map[string]int{}
	hidden := map[string]int{}
	for _, it := range r.Items {
		// low-value areas are long (a big update changes hundreds of packages)
		if !st.Verbose && it.Severity == core.Info && shown[it.Area] >= 8 {
			hidden[it.Area]++
			continue
		}
		if it.Area != area {
			if area != "" && hidden[area] > 0 {
				fmt.Fprintf(w, "     %s\n", paint("\x1b[90m", fmt.Sprintf("… %d more (nabd diff -v shows all)", hidden[area])))
			}
			area = it.Area
			fmt.Fprintf(w, "\n   %s\n", paint("\x1b[1;34m", area))
		}
		s := changeSym[it.Change][0]
		if st.ASCII {
			s = changeSym[it.Change][1]
		}
		fmt.Fprintf(w, "   %s  %s %s\n", st.Mark(it.Severity), s, it.What)
		shown[it.Area]++
	}
	if hidden[area] > 0 {
		fmt.Fprintf(w, "     %s\n", paint("\x1b[90m", fmt.Sprintf("… %d more (nabd diff -v shows all)", hidden[area])))
	}
	n := map[core.Severity]int{}
	for _, it := range r.Items {
		n[it.Severity]++
	}
	var parts []string
	if n[core.Crit] > 0 {
		parts = append(parts, paint("\x1b[31;1m", fmt.Sprintf("%d critical", n[core.Crit])))
	}
	if n[core.Warn] > 0 {
		parts = append(parts, paint("\x1b[33;1m", core.Plural(n[core.Warn], "warning", "warnings")))
	}
	if n[core.Info] > 0 {
		parts = append(parts, paint("\x1b[34m", core.Plural(n[core.Info], "note", "notes")))
	}
	fmt.Fprintf(w, "\n %s %s\n", paint("\x1b[1m", core.Plural(len(r.Items), "difference", "differences")+":"), strings.Join(parts, ", "))
	if n[core.Crit]+n[core.Warn] > 0 {
		fmt.Fprintf(w, " %s\n", paint("\x1b[33m", "check that you or your team made the marked changes; an unknown new admin, SUID file or open port is how attacks look"))
	}
	for _, x := range r.Notes() {
		fmt.Fprintf(w, " %s\n", paint("\x1b[34m", "note: "+x))
	}
	fmt.Fprintln(w)
}

// JSON writes the differences as JSON.
func JSON(w io.Writer, r Report, version string) error {
	n := map[string]int{"crit": 0, "warn": 0, "info": 0}
	for _, it := range r.Items {
		n[it.Severity.String()]++
	}
	items := r.Items
	if items == nil {
		items = []Item{}
	}
	notes := r.Notes()
	if notes == nil {
		notes = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"schema": render.Schema, "version": version, "kind": "diff",
		"from": r.From, "to": r.To, "status": r.Worst().String(), "summary": n, "differences": items, "notes": notes})
}

// Markdown writes the differences for a ticket.
func Markdown(w io.Writer, r Report, now time.Time) {
	fmt.Fprintf(w, "## nabd diff — %s\n\n%s → %s\n\n", r.To.Host, r.From.label(now), r.To.label(now))
	if len(r.Items) == 0 {
		fmt.Fprintln(w, "No differences.")
		return
	}
	fmt.Fprintln(w, "| Severity | Area | Change | What |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, it := range r.Items {
		fmt.Fprintf(w, "| %s | %s | %s | %s |\n", it.Severity, it.Area, it.Change, strings.ReplaceAll(it.What, "|", "\\|"))
	}
	for _, x := range r.Notes() {
		fmt.Fprintf(w, "\n> note: %s\n", x)
	}
}

// Summary is one line for the journal after "nabd snapshot".
func Summary(r Report) string {
	if len(r.Items) == 0 {
		return "no differences since the previous snapshot"
	}
	n := map[core.Severity]int{}
	var top []string
	for _, it := range r.Items {
		n[it.Severity]++
		if it.Severity.Rank() >= core.Warn.Rank() && len(top) < 3 {
			top = append(top, it.Area+": "+changeSym[it.Change][1]+" "+it.What)
		}
	}
	s := core.Plural(len(r.Items), "difference", "differences") + " since the previous snapshot"
	if n[core.Crit]+n[core.Warn] > 0 {
		s += fmt.Sprintf(" (%d critical, %d warnings): %s", n[core.Crit], n[core.Warn], strings.Join(top, "; "))
	}
	return s
}
