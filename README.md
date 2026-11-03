# nabd

[![ci](https://github.com/s0sta/nabd/actions/workflows/ci.yml/badge.svg)](https://github.com/s0sta/nabd/actions/workflows/ci.yml)
[![packaging](https://github.com/s0sta/nabd/actions/workflows/packaging.yml/badge.svg)](https://github.com/s0sta/nabd/actions/workflows/packaging.yml)
[![release](https://img.shields.io/github/v/release/s0sta/nabd)](https://github.com/s0sta/nabd/releases/latest)
[![license](https://img.shields.io/github/license/s0sta/nabd)](LICENSE)

**A doctor for Linux servers.** One command checks the whole machine, tells you in plain words what is wrong and why, and prints the command that fixes it.

<p align="center">
  <img src="docs/demo.svg" width="900" alt="nabd on a server: /var is 96% full because of the journal, Redis is open to the network, nginx failed because of a typo on line 14 of a site file that changed 2 minutes before, a certificate does not renew, and a kernel update waits for a reboot">
</p>
<p align="center"><sub>A demo server from the test suite (<a href="cmd/nabd/demo_test.go"><code>cmd/nabd/demo_test.go</code></a>). Every line is real nabd output.</sub></p>

nabd (نبض, Arabic for *pulse*) looks at disks, memory, CPU, services, the kernel log, time, reboots, packages, network, open ports, SSH, TLS certificates, processes and accounts. The checks run in parallel and take about a second. nabd only reads: it never changes your system.

## Why nabd

When a server is in trouble, the answer is spread over a dozen tools: `df`, `du`, `free`, `systemctl`, `journalctl`, `ss`, `openssl`, `dmesg`, `last` … You must know which one to ask, and how to read its answer. nabd asks all of them and connects the dots:

> **nginx.service failed 25 min ago.** The config test says `unknown directive "servr"` in `/etc/nginx/sites-enabled/shop`, line 14. That file changed 2 minutes before the failure.

- **Answers, not data.** Every problem comes with its cause and the exact fix. Healthy areas take one line.
- **Safe on production.** Read-only. No daemon, no agent, no config file, no network traffic (only `nabd why dns` sends DNS queries, and it tells you).
- **No root needed.** As a normal user it shows what it could not see. `sudo nabd` sees everything.
- **One static binary.** About 5 MB, no dependencies: Go standard library only. Debian, Ubuntu, RHEL, Rocky, Alma, Fedora, Arch, openSUSE, Alpine; with or without systemd; VM, bare metal or container.
- **Never hangs.** Every check has a time limit. A dead NFS mount gives you a finding, not a frozen terminal.
- **Made for automation too.** Nagios exit codes, stable JSON, Prometheus metrics, Markdown for tickets.

## Install

From the [latest release](https://github.com/s0sta/nabd/releases/latest): packages and static binaries for every CPU that
Linux runs on with Go: amd64, arm64, armv7, armv6, armv5, 386, ppc64le, ppc64, s390x, riscv64, loong64, mips, mipsle,
mips64 and mips64le. One static binary, no libraries: it runs on any distribution and version with Linux 3.2 or newer
(RHEL/CentOS 7 and newer, Debian 8+, Ubuntu 14.04+, Alpine, Amazon Linux, openSUSE, Arch, Raspberry Pi OS …).

```sh
# Fedora, RHEL, Rocky, Alma, openSUSE
sudo rpm -Uvh https://github.com/s0sta/nabd/releases/latest/download/nabd_$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/ -e 's/armv\([5-7]\).*/armv\1/' -e 's/i[3-6]86/386/' -e s/loongarch64/loong64/).rpm

# Debian, Ubuntu
curl -fL -o /tmp/nabd.deb https://github.com/s0sta/nabd/releases/latest/download/nabd_$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/ -e 's/armv\([5-7]\).*/armv\1/' -e 's/i[3-6]86/386/' -e s/loongarch64/loong64/).deb && sudo apt install /tmp/nabd.deb

# Alpine
curl -fL -o /tmp/nabd.apk https://github.com/s0sta/nabd/releases/latest/download/nabd_$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/ -e 's/armv\([5-7]\).*/armv\1/' -e 's/i[3-6]86/386/' -e s/loongarch64/loong64/).apk && sudo apk add --allow-untrusted /tmp/nabd.apk

# Any Linux: one static binary
curl -fL https://github.com/s0sta/nabd/releases/latest/download/nabd_linux_$(uname -m | sed -e s/x86_64/amd64/ -e s/aarch64/arm64/ -e 's/armv\([5-7]\).*/armv\1/' -e 's/i[3-6]86/386/' -e s/loongarch64/loong64/).tar.gz | tar -xz nabd && sudo install -m 755 nabd /usr/local/bin/
```

Each line picks the file for your machine by itself (`x86_64` → `amd64`, `aarch64` → `arm64`, `armv7l` → `armv7`). On MIPS
`uname -m` does not show the byte order: use `mips`/`mips64` (big-endian) or `mipsle`/`mips64le` (little-endian). Every file is listed in `SHA256SUMS` and has a signed build provenance:

```sh
gh attestation verify nabd_amd64.deb --repo s0sta/nabd
```

From source (Go 1.19 or newer):

```sh
go install github.com/s0sta/nabd/cmd/nabd@latest
# or, with the man page, completions and systemd units:
git clone https://github.com/s0sta/nabd && cd nabd && make && sudo make install
```

## Use it

What the output looks like, and how to tell OK from a problem: [Examples](#examples-what-you-will-see).

### Check everything

```sh
nabd          # the report
sudo nabd     # see everything: other users' processes, /etc/shadow, sshd -T …
nabd -v       # also list the checks that are OK
nabd -q       # only problems, no notes
```

### Ask why

| Command | What it answers |
|---|---|
| `nabd why disk [PATH]` | What fills the disk: the biggest folders and files, logs, caches, container images, deleted files that a process still holds open |
| `nabd why slow` | What slows the machine **now**: CPU, memory, the disk, a network file system or the hypervisor (steal), and which process |
| `nabd why memory` | Who uses the memory, OOM kills, swap, tmpfs |
| `nabd why service NAME` | Why a service stopped: what the exit code means, the config test, what changed just before, the last log lines |
| `nabd why port N` | Who listens, from which package, which config sets it, who can connect, the firewall |
| `nabd why dns [NAME]` | Asks every DNS server and shows which one fails and how |
| `nabd why boot` | Slow units, failures, and whether the last shutdown was clean |

Short forms work too: `nabd why nginx`, `nabd why 443`, `nabd why /var`.

### What changed?

`nabd changes` builds a timeline from logs and file times: packages, files in `/etc`, SSH keys, cron tables, logins, reboots and failed services. Changes that touch security are marked with `!`. It needs no setup and no earlier snapshot.

```console
$ nabd changes --since 2d
nabd changes · last 2 days · web-prod-1

 Sat 31 Oct
  09:12   pkg    openssl upgraded 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5
  09:12   pkg    libssl3t64 upgraded 3.0.13-0ubuntu3.4 → 3.0.13-0ubuntu3.5
  09:12   file   3 files in /etc changed by the package update
  23:40 ! key    SSH keys of root changed (/root/.ssh/authorized_keys)

 Sun 1 Nov
  14:33   file   /etc/nginx/sites-enabled/shop
  14:35 x svc    nginx.service failed: the program stopped with an error (exit code 1); its log lines say which

 2 packages · 2 files · 1 SSH key change · 1 service failure
 1 change marked ! touches security: check that you or your team made it
```

### Catch drift and intruders

A snapshot keeps what matters for security: users, admin group members, SUID files, open ports, enabled services, packages, firewall and SELinux state, kernel settings, and a hash of every file in `/etc`, SSH `authorized_keys` and cron tables.

```sh
sudo nabd snapshot                               # save the state now
sudo nabd diff                                   # what is different since then
sudo nabd diff --since 7d                        # compared with about a week ago
sudo systemctl enable --now nabd-snapshot.timer  # one snapshot a day
```

A new UID 0 account or a SUID file in `/tmp` or `/home` is critical. A new admin, open port, SSH key, sudoers change, enabled service, or a firewall that went off is a warning.

### Scripts and monitoring

| Option | For |
|---|---|
| `--json` | scripts and tools; the schema is stable (`nabd/1`, see [docs/output.md](docs/output.md)) |
| `--nagios` | Nagios, Icinga, NRPE |
| `--prometheus -o FILE` | node_exporter's textfile collector (written atomically) |
| `--md` | a ticket or a chat |
| `--only disk,certs`, `--skip cpu` | choose the checks |

Exit codes follow the Nagios plugin rule: `0` OK, `1` warning, `2` critical, `3` unknown. Ready-made systemd units and a Nagios example are in [contrib/](contrib/).

## Examples: what you will see

The outputs below are real nabd output from two test servers: a healthy one and one with five problems
(`cmd/nabd/examples_test.go` makes them: `NABD_EXAMPLES=DIR go test ./cmd/nabd -run TestReadmeExamples`).

### A healthy server: everything is OK

```console
$ sudo nabd
nabd 0.2.0 · web-prod-1 · Ubuntu 24.04.1 LTS · kernel 6.8.0-48-generic · up 41 days

 ✔ 13 checks OK  disk · memory · cpu · services · kernel · time · reboot · packages · network · ports · ssh · procs · accounts
 ○ skipped: certs  (nabd -v says why)

 healthy: no problems found · 1.0 s
$ echo $?
0
```

**This is good.** You see only `✔`, the last line says `healthy: no problems found`, and the exit code is `0`.

- `○ skipped` is **not** a problem: that check has nothing to look at here (on this server: no TLS certificates).
  `nabd -v` says why each check was skipped.
- `○ without root nabd could not read: …` means you ran it without `sudo`. Run `sudo nabd` to check everything.

### A server with problems

```console
$ sudo nabd
nabd 0.2.0 · web-prod-1 · Ubuntu 24.04.1 LTS · kernel 6.8.0-45-generic · up 41 days

 ✖ CRIT  disk      /var is 96% full (1.4 GB free of 40.0 GB)
                  why   10.7 GB in journal logs (/var/log/journal)
                  fix   journalctl --vacuum-size=500M
                        # for good: SystemMaxUse=500M in /etc/systemd/journald.conf, then restart systemd-journald
                        nabd why disk /var   # the biggest folders and files
 ✖ CRIT  ports     Redis listens on 0.0.0.0:6379: other machines can connect
                  why   Redis has no password by default; open Redis servers are attacked within
                        hours
                        process: redis-server (pid 1187, redis-server.service)
                        no active firewall was found
                  fix   # in redis.conf: `bind 127.0.0.1 -::1` and `protected-mode yes`, then restart redis
 ✖ CRIT  services  nginx.service failed 25 min ago
                  why   the program stopped with an error (exit code 1); its log lines say which
                        config test (nginx -t): nginx: [emerg] unknown directive "servr" in
                        /etc/nginx/sites-enabled/shop:14
                        file /etc/nginx/sites-enabled/shop changed 2 min before it failed (14:33)
                  fix   # the error is in /etc/nginx/sites-enabled/shop, line 14
                        nginx -t   # must say OK before you restart
                        systemctl restart nginx.service
                        journalctl -u nginx.service -b -e
                        nabd why service nginx
 ▲ WARN  certs     the certificate for shop.example.com expires in 12 days
                  why   file: /etc/letsencrypt/live/shop.example.com/fullchain.pem (used by nginx)
                        valid until 2026-11-13 13:00 UTC
                        certbot renews 30 days before the end, so the automatic renewal is failing
                  fix   certbot renew --dry-run   # shows why it fails
                        systemctl list-timers '*certbot*'   # is the renewal timer on?
 ▲ WARN  reboot    an update needs a reboot
                  why   updated: linux-image-6.8.0-48-generic
                  fix   reboot   # at a good time

 ✔ 9 checks OK  memory · cpu · kernel · time · packages · network · ssh · procs · accounts

 5 problems: 3 critical, 2 warnings · 1.0 s
 more: nabd why disk|slow|memory|service NAME|port N|dns|boot · nabd changes · nabd --json
$ echo $?
2
```

**This needs work.** Every problem has three parts:

- the title (what is wrong),
- `why` (the cause nabd found),
- `fix` (the commands to run; lines starting with `#` explain what to change).

Start with `✖ CRIT`, then do `▲ WARN`. After the fix, run `sudo nabd` again: when the problem is gone, it moves to
`✔ checks OK`.

### What the signs and exit codes mean

| Sign | Level | Meaning | What to do | Exit code |
|---|---|---|---|---|
| `✔` | OK | the check found nothing wrong | nothing | `0` |
| `○` | skipped | nothing to check here, or no permission | nothing; use `sudo` for a full check | `0` |
| `●` | INFO | worth knowing, not a problem | read it | `0` |
| `▲` | WARN | a problem that will grow, or a risk | fix it soon | `1` |
| `✖` | CRIT | broken now, or open to attack | fix it now | `2` |
| `?` | UNKN | a check could not finish (time limit or error) | run `nabd -v`; if it repeats, open an issue | `3` |

The exit code is the worst level found. With `--ascii` (or `TERM=dumb`) the signs are `+`, `-`, `i`, `!`, `x` and `?`.

### Only the problems: `nabd -q`

On a healthy server `-q` prints just the short summary:

```console
$ sudo nabd -q
nabd 0.2.0 · web-prod-1 · Ubuntu 24.04.1 LTS · kernel 6.8.0-48-generic · up 41 days

 ✔ 13 checks OK  disk · memory · cpu · services · kernel · time · reboot · packages · network · ports · ssh · procs · accounts

 healthy: no problems found · 1.0 s
```

On a server with problems it prints the problems without the notes.

### Ask why: `nabd why disk /var`

```console
$ sudo nabd why disk /var
nabd why disk /var · web-prod-1

 ✖ CRIT  /var is 96% full: 38.3 GB used, 1.4 GB free of 40.0 GB

   File system
     /var on /dev/vdb1 (ext4), inodes 4% used

   Biggest folders
     ▸  10.7 GB  67%  /var/log
         3.0 GB  19%  /var/lib
         2.3 GB  15%  /var/www
         ▸  10.7 GB 100%  /var/log/journal
                10.7 GB 100%  /var/log/journal/4f1c2e

   Biggest files
       9.6 GB  /var/log/journal/4f1c2e/system.journal
       3.0 GB  /var/lib/redis/dump.rdb
       2.3 GB  /var/www/shop/media/archive.tar
       1.2 GB  /var/log/journal/4f1c2e/system@0006.journal~

   What to do
     journalctl --vacuum-size=500M
     # for good: SystemMaxUse=500M in /etc/systemd/journald.conf, then restart systemd-journald
```

**Problem:** the first line is `✖ CRIT` or `▲ WARN`. The lines below show where the space went; `What to do`
frees it. **OK:** the first line starts with `✔` (the disk has enough free space).

### Ask why: `nabd why nginx`

```console
$ sudo nabd why nginx
nabd why service nginx · web-prod-1

 ✖ CRIT  nginx.service failed 25 min ago: the program stopped with an error (exit code 1); its log lines say which

   Status
     nginx.service — A high performance web server and a reverse proxy server
     state: failed
     at boot: enabled
     unit file: /usr/lib/systemd/system/nginx.service

   Why
     config test (nginx -t): nginx: [emerg] unknown directive "servr" in /etc/nginx/sites-enabled/shop:14
     file /etc/nginx/sites-enabled/shop changed 2 min before it failed (14:33)

   Config test
     nginx -t: FAILED
     nginx: [emerg] unknown directive "servr" in /etc/nginx/sites-enabled/shop:14
     nginx: configuration file /etc/nginx/nginx.conf test failed

   Last log lines
     nginx: [emerg] unknown directive "servr" in /etc/nginx/sites-enabled/shop:14

   What to do
     # the error is in /etc/nginx/sites-enabled/shop, line 14
     nginx -t   # must say OK before you restart
     systemctl restart nginx.service
     journalctl -u nginx.service -b -e
```

**Problem:** `state: failed` and the cause under `Why` (here a typo, `servr`, in line 14, made 2 minutes before
the crash). **OK:** the first line starts with `✔`: the service runs.

### Monitoring: `nabd --nagios`

One line for Nagios, Icinga or NRPE, plus one line per problem:

```console
$ sudo nabd --nagios        # healthy: exit 0
NABD OK - no problems | crit=0;;;0 warn=0;;;0 unknown=0;;;0 checks=14;;;0 time=1.002s;;;0

$ sudo nabd --nagios        # problems: exit 2
NABD CRITICAL - /var is 96% full (1.4 GB free of 40.0 GB); Redis listens on 0.0.0.0:6379: other machines can connect; nginx.service failed 25 min ago; +2 more | crit=3;;;0 warn=2;;;0 unknown=0;;;0 checks=14;;;0 time=1.002s;;;0
[CRIT] disk: /var is 96% full (1.4 GB free of 40.0 GB)
[CRIT] ports: Redis listens on 0.0.0.0:6379: other machines can connect
[CRIT] services: nginx.service failed 25 min ago
[WARN] certs: the certificate for shop.example.com expires in 12 days
[WARN] reboot: an update needs a reboot
```

### In a script

```sh
sudo nabd -q > /tmp/nabd.txt
case $? in
  0) echo "OK" ;;
  1) echo "warning: see /tmp/nabd.txt" ;;
  2) echo "CRITICAL: see /tmp/nabd.txt" ;;
  *) echo "nabd could not finish a check" ;;
esac
```

## What nabd checks

| Check | What it looks at |
|---|---|
| `disk` | Space and inodes on every local file system. For a full one it finds the cause: the journal, package caches, container images, crash dumps, big logs, or deleted files that a process still keeps open. |
| `memory` | Available memory (or the container limit), swap, memory pressure (PSI) and processes the kernel killed because memory ran out. |
| `cpu` | Load per CPU, CPU use, time spent waiting for the disk (iowait), CPU taken by the hypervisor (steal) and CPU pressure, with the busiest processes. |
| `services` | Failed systemd units with the reason in plain words (exit code, signal, timeout, OOM), the last log lines, the service's own config test, and the files or packages that changed just before it failed. Services that keep restarting. |
| `kernel` | Disk and file system errors, file systems that turned read-only, hardware (MCE/EDAC) errors and hung tasks in the kernel log of this boot. |
| `time` | Is the clock synchronised (systemd-timesyncd, chrony or ntpd)? A wrong clock breaks TLS, Kerberos, logs and cron. |
| `reboot` | A newer kernel or core library is installed but not running yet, or the running kernel was removed by an update. |
| `packages` | Interrupted dpkg runs, stale pacman locks, and how long ago updates were installed. |
| `network` | A default route, DNS servers, and a real DNS server behind a local address like 127.0.0.53. Sends no traffic. |
| `ports` | Databases, caches and admin APIs open to the network (Redis, MongoDB, Elasticsearch, Memcached, MySQL, PostgreSQL, the Docker API, telnet …), the process behind them and the firewall. |
| `ssh` | Empty passwords, root login with a password, and brute-force login attempts in the last hour. |
| `certs` | Certificates used by nginx, Apache, HAProxy, Postfix, Dovecot and Let's Encrypt: expired or expiring soon. Parsed by nabd itself, no openssl needed. |
| `procs` | Zombie processes and their parent, processes stuck in D state, processes close to their open-file limit, system-wide file and process limits. |
| `accounts` | Other accounts with UID 0 and accounts without a password. |

Every finding has a stable ID such as `disk.full` or `ports.exposed-6379`. The full list is in [docs/checks.md](docs/checks.md).

## Safe by design

- nabd never writes, deletes, restarts or installs anything. `nabd snapshot` writes only its own files (`/var/lib/nabd` as root, else `~/.local/state/nabd`); `-o FILE` writes only the file you name.
- It reads `/proc`, `/sys` and files in `/etc`, and runs only commands that read: `systemctl show`, `journalctl`, `timedatectl show`, `sshd -T`, and the config tests of your services (`nginx -t`, `apachectl -t`, `haproxy -c` …). Every command runs with `LC_ALL=C`, a time limit and a cap on its output.
- No telemetry. Nothing leaves the machine. Only `nabd why dns` sends DNS queries, and it says so.
- `--json` and `--md` output contain host details (hostname, users, ports). Read them before you share them.

## How it compares

nabd does not replace monitoring. It is the command you run when you log in to a server: the first minutes of an incident, a machine you take over, a daily health check.

| Tool | What it is for |
|---|---|
| Prometheus, Netdata, Zabbix | metrics over time, graphs and alerts; they need setup |
| Lynis | a deep security audit with hundreds of tests, for hardening |
| htop, glances | a live view of resources |
| **nabd** | one command, one answer: what is wrong now, why, how to fix it, and what changed |

They work well together: `nabd --prometheus` feeds node_exporter, and `nabd --nagios` runs under Icinga.

## For distributions

nabd is easy to package: one Go module with no dependencies, no cgo, and tests that need neither root nor network. Packaging for Debian, Fedora/EPEL, Arch and Alpine is in [packaging/](packaging/). See [PACKAGING.md](PACKAGING.md).

## Contributing

False alarms and missed problems are the most useful reports. Open an issue with the `nabd --json` output (remove what is private). Each check is a small Go function, tested against a fake machine; see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © 2026 Hosam Hani ([s0sta](https://s0sta.com))
