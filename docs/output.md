# Output formats

## Exit codes

| Command | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| `nabd`, `nabd check` | healthy | a warning | a critical problem | unknown: a check could not finish, or a bad option |
| `nabd why …` | the answer is OK | warning | critical | unknown or bad option |
| `nabd changes` | nothing changed | changes found | — | bad option |
| `nabd diff` | no differences | differences | a critical difference | error |
| `nabd snapshot` | saved | — | — | error |

Notes (`info`) never change the exit code.

## JSON (`--json`)

The schema is `nabd/1`. Fields can be added in any release; a field is only removed or changes its meaning in
`nabd/2`. Severities are strings: `ok`, `info`, `warn`, `crit`, `unknown`.

```json
{
  "schema": "nabd/1",
  "version": "0.1.0",
  "generated_at": "2026-11-01T12:00:00Z",
  "host": {
    "hostname": "web-prod-1", "os": "Ubuntu 24.04.1 LTS", "os_id": "ubuntu", "os_like": ["debian"],
    "os_version": "24.04", "kernel": "6.8.0-45-generic", "arch": "amd64", "uptime_seconds": 3564000,
    "boot_time": "2026-09-21T06:00:00Z", "systemd": true, "root": true, "cpus": 4, "package_manager": "apt"
  },
  "status": "crit",
  "exit_code": 2,
  "summary": { "crit": 3, "warn": 2, "info": 0, "unknown": 0, "ok_checks": 9, "duration_ms": 1012 },
  "findings": [
    {
      "id": "disk.full",
      "check": "disk",
      "severity": "crit",
      "title": "/var is 96% full (1.4 GB free of 40.0 GB)",
      "why": ["10.7 GB in journal logs (/var/log/journal)"],
      "fix": ["journalctl --vacuum-size=500M", "# for good: SystemMaxUse=500M in /etc/systemd/journald.conf, then restart systemd-journald"],
      "data": { "mount": "/var", "percent": 96.4, "free_bytes": 1520435200, "size_bytes": 42949672960, "fstype": "ext4", "device": "/dev/vdb1" }
    }
  ],
  "checks": [
    { "name": "disk", "title": "Disk space", "status": "crit", "detail": "2 file systems, fullest /var 96%", "ms": 41 }
  ]
}
```

- `fix` lines that start with `#` are advice; the others are commands.
- `data` holds the numbers behind a finding; its keys depend on the finding.
- A check's `status` is `ok`, `info`, `warn`, `crit`, `unknown` or `skipped`; `limited` says what it could not read
  without root.

`nabd why --json`, `nabd changes --json` and `nabd diff --json` use the same schema with `why`, `changes` or
`differences` instead of `findings`.

## Nagios and Icinga (`--nagios`)

```
NABD CRITICAL - /var is 96% full (1.4 GB free of 40.0 GB); Redis listens on 0.0.0.0:6379: other machines can connect; nginx.service failed 25 min ago; +2 more | crit=3;;;0 warn=2;;;0 unknown=0;;;0 checks=14;;;0 time=1.012s;;;0
[CRIT] disk: /var is 96% full (1.4 GB free of 40.0 GB)
…
```

The first line is the status and the performance data; the next lines are the long output. With NRPE:

```
command[check_nabd]=/usr/bin/nabd --nagios --skip cpu
```

See [contrib/nagios/nabd.cfg](../contrib/nagios/nabd.cfg).

## Prometheus (`--prometheus`)

For the textfile collector of node_exporter. `-o` writes the file atomically, so node_exporter never reads half
a file:

```sh
nabd --prometheus -o /var/lib/prometheus/node-exporter/nabd.prom
```

```
nabd_status 2
nabd_findings{severity="crit"} 3
nabd_check_status{check="disk"} 2
nabd_finding{check="disk",id="disk.full",severity="crit",title="/var is 96% full (1.4 GB free of 40.0 GB)"} 1
nabd_last_run_timestamp_seconds 1793534400
nabd_run_duration_seconds 1.012
```

`nabd_check_status` is 0 OK, 1 warning, 2 critical, 3 unknown and -1 skipped. The systemd units in
[contrib/systemd](../contrib/systemd) run this every 5 minutes. An alert rule:

```yaml
- alert: NabdCritical
  expr: nabd_status == 2
  for: 10m
  annotations:
    summary: "{{ $labels.instance }}: nabd found a critical problem (run: sudo nabd)"
```

## Markdown (`--md`)

A table of the problems and one section per problem with its fix, ready to paste into a ticket or a chat.
