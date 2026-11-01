// Package why answers one question in depth: why is the disk full, why is
// the machine slow, why did this service stop, who is on this port …
package why

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/render"
)

// Section is a titled list of lines.
type Section struct {
	Title string   `json:"title"`
	Lines []string `json:"lines"`
}

// Answer is the result of one "nabd why".
type Answer struct {
	Topic    string        `json:"topic"`
	Subject  string        `json:"subject,omitempty"`
	Severity core.Severity `json:"severity"`
	Verdict  string        `json:"verdict"`
	Sections []Section     `json:"sections"`
	Fix      []string      `json:"fix,omitempty"`
	Note     string        `json:"note,omitempty"`
	Limited  []string      `json:"limited,omitempty"`
}

func (a *Answer) add(title string, lines ...string) {
	if len(lines) == 0 {
		return
	}
	for i := range a.Sections {
		if a.Sections[i].Title == title {
			a.Sections[i].Lines = append(a.Sections[i].Lines, lines...)
			return
		}
	}
	a.Sections = append(a.Sections, Section{title, lines})
}

func (a *Answer) limit(what string) {
	for _, l := range a.Limited {
		if l == what {
			return
		}
	}
	a.Limited = append(a.Limited, what)
}

func (a *Answer) fix(cmds ...string) {
	for _, c := range cmds {
		dup := false
		for _, x := range a.Fix {
			if x == c {
				dup = true
			}
		}
		if !dup {
			a.Fix = append(a.Fix, c)
		}
	}
}

// Topics lists what "nabd why" knows.
var Topics = []struct{ Name, Args, Help string }{
	{"disk", "[PATH]", "what fills a file system: biggest folders and files, logs, caches, deleted open files"},
	{"slow", "", "what slows the machine now: CPU, memory, disk or the hypervisor, and which process"},
	{"memory", "", "who uses the memory, OOM kills, swap, tmpfs and kernel memory"},
	{"service", "NAME", "why a service stopped or misbehaves: exit code, config test, changes, logs"},
	{"port", "N", "who listens on a port, who can reach it, and the firewall"},
	{"dns", "[NAME]", "why names do not resolve (this one sends DNS queries)"},
	{"boot", "", "how the last boot went: slow units, failures, was the shutdown clean"},
}

// Human writes an answer for the terminal.
func Human(w io.Writer, a Answer, st render.Style, facts core.Facts) {
	head := "nabd why " + a.Topic
	if a.Subject != "" {
		head += " " + a.Subject
	}
	fmt.Fprintf(w, "%s %s\n\n", paint(st, "\x1b[1m", head), paint(st, "\x1b[2m", "· "+facts.Hostname))
	fmt.Fprintf(w, " %s  %s\n", st.Mark(a.Severity), paint(st, "\x1b[1m", a.Verdict))
	for _, s := range a.Sections {
		fmt.Fprintf(w, "\n   %s\n", paint(st, "\x1b[1;34m", s.Title))
		for _, l := range s.Lines {
			fmt.Fprintf(w, "     %s\n", l)
		}
	}
	if len(a.Fix) > 0 {
		fmt.Fprintf(w, "\n   %s\n", paint(st, "\x1b[1;34m", "What to do"))
		for _, f := range a.Fix {
			if strings.HasPrefix(f, "#") {
				fmt.Fprintf(w, "     %s\n", paint(st, "\x1b[90m", f))
				continue
			}
			cmd, comment, _ := strings.Cut(f, "   #")
			line := paint(st, "\x1b[36m", cmd)
			if comment != "" {
				line += paint(st, "\x1b[90m", "   #"+comment)
			}
			fmt.Fprintf(w, "     %s\n", line)
		}
	}
	if a.Note != "" {
		fmt.Fprintf(w, "\n   %s %s\n", paint(st, "\x1b[33m", "note:"), a.Note)
	}
	if len(a.Limited) > 0 {
		if facts.Root {
			fmt.Fprintf(w, "\n   %s %s\n", paint(st, "\x1b[34m", "nabd could not read:"), strings.Join(a.Limited, "; "))
		} else {
			fmt.Fprintf(w, "\n   %s %s\n", paint(st, "\x1b[34m", "without root nabd could not read:"), strings.Join(a.Limited, "; ")+" — run it with sudo")
		}
	}
	fmt.Fprintln(w)
}

func paint(st render.Style, code, s string) string {
	if !st.Color {
		return s
	}
	return code + s + "\x1b[0m"
}

// JSON writes an answer as JSON.
func JSON(w io.Writer, a Answer, facts core.Facts, version string) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(map[string]interface{}{"schema": render.Schema, "version": version, "host": facts, "why": a})
}

// Markdown writes an answer for a ticket.
func Markdown(w io.Writer, a Answer, facts core.Facts) {
	fmt.Fprintf(w, "## nabd why %s %s — %s\n\n**%s**\n\n", a.Topic, a.Subject, facts.Hostname, a.Verdict)
	for _, s := range a.Sections {
		fmt.Fprintf(w, "### %s\n\n", s.Title)
		for _, l := range s.Lines {
			fmt.Fprintf(w, "- %s\n", l)
		}
		fmt.Fprintln(w)
	}
	if len(a.Fix) > 0 {
		fmt.Fprintf(w, "### What to do\n\n```sh\n%s\n```\n", strings.Join(a.Fix, "\n"))
	}
}
