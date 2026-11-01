# Changelog

All notable changes are listed here. nabd follows [semantic versioning](https://semver.org/):
the JSON schema (`nabd/1`), the finding IDs and the exit codes only change in a major version.

## 0.1.0 — 2026-11-02

The first release.

- `nabd`: 14 checks (disk, memory, cpu, services, kernel, time, reboot, packages, network, ports, ssh, certs,
  procs, accounts), run in parallel with a time limit, each problem with its cause and fix.
- `nabd why`: disk, slow, memory, service, port, dns and boot, with short forms (`nabd why nginx`, `nabd why 443`,
  `nabd why /var`).
- `nabd changes`: a timeline of packages, `/etc` files, SSH keys, cron tables, logins, boots and failed services.
- `nabd snapshot` and `nabd diff`: the security state of the machine and what changed in it.
- Output as text, JSON (`nabd/1`), Markdown, Nagios plugin output and Prometheus metrics; `-o FILE` writes atomically.
- Man page, bash/zsh/fish completions, systemd units for daily snapshots and for Prometheus.
- Packaging for Debian, Fedora/EPEL, Arch and Alpine; release builds for 7 architectures with build provenance.
