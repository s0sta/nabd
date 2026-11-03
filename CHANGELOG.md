# Changelog

All notable changes are listed here. nabd follows [semantic versioning](https://semver.org/):
the JSON schema (`nabd/1`), the finding IDs and the exit codes only change in a major version.

## Unreleased

- `nabd why port N` gives the same verdict as `nabd`: an open Redis, Docker API, database … on the network is
  CRIT or WARN there too, with the risk and the fix (it said OK before).
- README: examples of real output (a healthy server and one with problems, `nabd -q`, `why disk`, `why nginx`,
  `--nagios`, a script), what each sign and exit code means, and how to tell OK from a problem.

## 0.2.0 — 2026-11-03

- Packaging: AUR packages `nabd` and `nabd-bin` (published by the `aur` workflow), Fedora Copr (`.copr/Makefile`),
  real checksums for Alpine; a `packaging` workflow builds the Debian, RPM, Arch and Alpine packages in their
  distributions and checks them with lintian, rpmlint and namcap.
- A build between releases shows its version as `0.1.0-dev+COMMIT`.
- Every CPU that Go supports on Linux: release files now also for armv5, armv6, ppc64 (big-endian), loong64, mips,
  mipsle, mips64 and mips64le (soft-float, so they run with or without an FPU); 386 is soft-float too (runs on CPUs
  without SSE2). The tests run on all 14 builds in QEMU in CI, and the packages are installed and run on arm64,
  armv5/v6/v7, 386, ppc64le, s390x, riscv64 and loong64 containers.
- CI runs nabd on 31 distribution versions, old and new: CentOS 7, Rocky/Alma/Oracle 8–10, CentOS Stream 9/10,
  Amazon Linux 2/2023, Fedora, Debian 10–13, Ubuntu 16.04–24.04, Alpine 3.14–edge, openSUSE Leap/Tumbleweed, Arch,
  Kali and Gentoo. The packages install with old package tools too (rpm on CentOS 7, dpkg on Ubuntu 16.04).
- README: the install commands pick the file for your machine type (`uname -m`).

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
