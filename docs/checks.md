# Checks and finding IDs

Every finding has an ID: `<check>.<name>`. IDs are stable: scripts, dashboards and alert rules can use them.
A new ID can come in any release; an ID is only removed or renamed in a major version.

Severities: **crit** (exit 2), **warn** (exit 1), **unknown** (exit 3), **info** (a note; does not change the exit code).

| ID | Severity | When |
|---|---|---|
| `disk.full` | warn ≥ 85 %, crit ≥ 95 % | a writable local file system is nearly full; the finding names the cause (journal, package cache, container images, crash dumps, big log files, deleted files still open) |
| `disk.inodes` | warn ≥ 85 %, crit ≥ 95 % | a file system has almost no free inodes (millions of small files) |
| `disk.unreadable` | unknown | a mount point does not answer (a hung network file system) |
| `memory.low` | warn < 10 % free, crit < 5 % | little memory is available (the container limit inside a container) |
| `memory.pressure` | warn | programs waited for memory ≥ 10 % of the last minute (PSI) |
| `memory.swap` | warn | swap is ≥ 80 % used |
| `memory.oom` | warn | the kernel killed processes because memory ran out (this boot) |
| `cpu.load` | warn ≥ 1.5 per CPU, crit ≥ 3 | the load average is high, with the busiest processes |
| `cpu.iowait` | warn | the CPUs wait for the disk ≥ 20 % of the time |
| `cpu.steal` | warn | the hypervisor takes ≥ 10 % of the CPU |
| `cpu.pressure` | warn | programs waited for CPU ≥ 40 % of the time (PSI) |
| `services.failed` | crit for an enabled long-running service or a mount, else warn | a systemd unit failed; the finding explains the exit code or signal, shows the config test result, the files and packages that changed before, and the last log lines |
| `services.restarts` | warn | a service restarted ≥ 5 times since boot |
| `kernel.fs-errors` | crit | the kernel reports file system errors |
| `kernel.io-errors` | crit | a disk reports read or write errors |
| `kernel.readonly` | crit | the kernel made a file system read-only after errors |
| `kernel.ro-mount` | crit | `/`, `/var`, `/home` … is mounted read-only |
| `kernel.hardware` | warn | machine check (MCE) or EDAC memory errors |
| `kernel.hung` | warn | tasks were blocked for more than 2 minutes |
| `kernel.segfaults` | info | programs crashed (segfault) in this boot |
| `time.unsynced` | warn | the clock is not synchronised, or no time service runs |
| `reboot.required` | warn | an update needs a reboot (`/run/reboot-required` or `needs-restarting -r`) |
| `reboot.kernel-gone` | warn | the modules of the running kernel were removed by an update (new hardware or modules will not load) |
| `reboot.new-kernel` | info | a newer kernel is installed than the one that runs |
| `packages.dpkg-interrupted` | crit | a dpkg run was interrupted; apt will not work until it is finished |
| `packages.pacman-lock` | warn | an old pacman lock blocks updates |
| `packages.old-updates` | warn | no package was updated for 90 days |
| `network.no-route` | warn | there is no default route |
| `network.no-resolv` | crit | `/etc/resolv.conf` is missing |
| `network.no-dns` | crit | no DNS server is set |
| `network.resolved-down` | crit | DNS goes to 127.0.0.53, but systemd-resolved does not run |
| `network.local-dns-down` | crit | DNS goes to a local address where no DNS server listens |
| `ports.exposed-<port>` | crit or warn (one level lower with an active firewall; the Docker API is always crit) | a database, cache or admin API listens on all addresses |
| `ssh.empty-passwords` | crit | `PermitEmptyPasswords yes` |
| `ssh.root-password` | warn | root can log in with a password |
| `ssh.bruteforce` | warn (info when password login is off) | ≥ 20 failed logins in the last hour |
| `certs.expiring` | crit when expired or < 7 days, warn < 21 days | a certificate used by a server is about to expire |
| `procs.zombies` | warn | zombie processes pile up under one parent |
| `procs.d-state` | warn | processes are stuck in uninterruptible sleep (D) |
| `procs.fd-limit` | warn ≥ 80 %, crit ≥ 95 % | a process is close to its open-file limit |
| `procs.file-max` | warn | the system is close to its open-file limit |
| `procs.pid-max` | crit | the system is close to its process limit |
| `accounts.uid0` | crit | an account other than root has UID 0 |
| `accounts.no-password` | crit | an account with a login shell has no password |
| `<check>.timeout` | unknown | a check did not finish in its time limit (`--timeout`) |
| `<check>.error` | unknown | a check failed: this is a bug in nabd, please report it |

## Snapshot differences

`nabd diff` sorts each difference into an area with a severity:

| Area | Severity |
|---|---|
| users | crit for a new UID 0 account, warn for a new account with a login shell, info otherwise |
| admin groups (sudo, wheel, admin, docker, adm, libvirt, lxd, root) | warn for a new member |
| SUID/SGID files | crit in `/tmp`, `/var/tmp`, `/dev/shm` or `/home`, warn elsewhere |
| open ports | warn for a new port on all addresses, info for a local one |
| firewall, SELinux | warn when it went off or to permissive |
| enabled services | warn for a new one |
| files | warn for `authorized_keys`, sudoers, cron tables, `/etc/passwd`, `/etc/shadow`, `/etc/ld.so.preload`, `sshd_config`; info otherwise |
| kernel, kernel settings, packages | info |
