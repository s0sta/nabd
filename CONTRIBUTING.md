# Contributing

Thank you for helping. The most useful things are:

1. **A false alarm**: nabd reports a problem that is not one. Open an issue with the finding ID and the part of
   `nabd --json` that shows it (remove what is private).
2. **A missed problem**: a real outage that nabd did not see. Tell us what was wrong and which command showed it.
3. **A new check or a better fix text**: see below.

## Build and test

```sh
make          # builds ./nabd (static)
make test     # go vet + go test
./nabd -v
```

You need Go 1.19 or newer. nabd uses the Go standard library only; please do not add dependencies.

## How the code is built

| Folder | What |
|---|---|
| `cmd/nabd` | the command line: options, commands, output |
| `internal/sys` | the **only** place that touches the machine (files, programs, time); `Fake` is a machine for tests |
| `internal/linux` | parsers for `/proc` and system files |
| `internal/core` | findings, the parallel runner with time limits, shared data (processes, mounts, kernel log, packages) |
| `internal/checks` | the 14 checks |
| `internal/why` | `nabd why` topics |
| `internal/changes` | `nabd changes` |
| `internal/snapshot` | `nabd snapshot` and `nabd diff` |
| `internal/render` | text, JSON, Markdown, Nagios, Prometheus |

## Rules for a check

- **Read only.** Use `c.Sys` for every file and program. Never write, never start or stop anything. Commands
  must be read-only (a config test that can create files, like `postfix check`, is not allowed).
- **Explain and fix.** A finding has a short title, the `Why` (what nabd saw, in plain words), and the `Fix`
  (exact commands; a line that starts with `#` is advice, not a command). Use `c.Sudo()` in front of commands
  that need root.
- **No false alarms.** If you are not sure, use `Info` or say nothing. A warning must be worth an admin's time.
- **Work without root.** If something cannot be read, call `o.Limit(...)` instead of failing.
- **Stay fast.** Use the shared data in `core.Ctx` (it is read once). Give every scan a deadline.
- **Stable IDs.** A finding ID (`disk.full`) is an API: do not rename it. Add new ones to `docs/checks.md`.
- **Test with a fake machine.** See `internal/checks/checks_test.go`: build the files and command outputs of
  the situation, run the check, assert the finding.

## Pull requests

- One topic per pull request; `make test` must pass and `gofmt` must be clean.
- Write commit messages and texts in simple English.
- By sending a pull request you agree to license your work under the MIT license.
