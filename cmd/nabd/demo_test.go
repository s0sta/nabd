package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/sys"
)

// demoMachine is a made-up web server with five real-world problems:
// a full /var (journal), a failed nginx (a typo in a site file), Redis open
// to the internet, a Let's Encrypt certificate that does not renew, and a
// kernel update that waits for a reboot.
func demoMachine(t *testing.T) *sys.Fake {
	t.Helper()
	f := sys.NewFake(t.TempDir())
	f.Host = "web-prod-1"
	now := f.Clock
	uptime := 41*24*time.Hour + 6*time.Hour
	boot := now.Add(-uptime)
	mono := func(at time.Time) string { return fmt.Sprint(at.Sub(boot).Microseconds()) }
	iso := func(at time.Time) string { return at.Format("2006-01-02T15:04:05-0700") }
	local := func(at time.Time) string { return at.In(time.Local).Format("2006-01-02 15:04:05") }

	f.File("/etc/os-release", "NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=debian\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04.1 LTS\"\n")
	f.File("/proc/sys/kernel/osrelease", "6.8.0-45-generic\n")
	f.File("/proc/uptime", fmt.Sprintf("%.2f 100.00\n", uptime.Seconds()))
	f.File("/proc/meminfo", "MemTotal:        8130000 kB\nMemFree:          900000 kB\nMemAvailable:    5210000 kB\nSwapTotal:       2097148 kB\nSwapFree:        2090000 kB\n")
	f.File("/proc/loadavg", "0.42 0.38 0.31 2/312 48211\n")
	f.File("/proc/stat", "cpu  4000 0 2000 900000 300 0 50 0 0 0\n")
	f.File("/proc/sys/fs/file-nr", "3200 0 9223372036854775807\n")
	f.File("/proc/sys/kernel/pid_max", "4194304\n")
	f.File("/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t100\t00000000\t0\t0\t0\n")
	f.File("/etc/resolv.conf", "nameserver 10.0.0.2\nsearch internal\n")
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\nredis:x:110:111::/var/lib/redis:/usr/sbin/nologin\ndeploy:x:1000:1000::/home/deploy:/bin/bash\n")
	f.File("/etc/shadow", "root:*:19800:0:99999:7:::\nwww-data:*:19800:0:99999:7:::\nredis:!:19800::::::\ndeploy:$y$j9T$x:19800:0:99999:7:::\n")
	f.Dir("/run/systemd/system")

	// disk: /var is nearly full, the journal is the cause
	f.File("/proc/self/mountinfo", "22 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw\n23 22 252:17 / /var rw,relatime - ext4 /dev/vdb1 rw\n")
	f.Fs["/"] = sys.Statfs{Size: 50 << 30, Free: 35 << 30, Avail: 32 << 30, Files: 3000000, FilesFree: 2800000}
	f.Fs["/var"] = sys.Statfs{Size: 40 << 30, Free: 1700 << 20, Avail: 1450 << 20, Files: 2600000, FilesFree: 2500000}
	sparse := func(p string, size int64) {
		f.File(p, "")
		if err := os.Truncate(filepath.Join(f.Root, p), size); err != nil {
			t.Fatal(err)
		}
	}
	sparse("/var/log/journal/4f1c2e/system.journal", 9800<<20)
	sparse("/var/log/journal/4f1c2e/system@0006.journal~", 1200<<20)
	sparse("/var/lib/redis/dump.rdb", 3100<<20)
	sparse("/var/www/shop/media/archive.tar", 2400<<20)

	// processes: nginx is gone, redis listens everywhere, sshd on 22
	proc := func(pid int, comm, unit string, ino int) {
		p := fmt.Sprintf("/proc/%d", pid)
		f.File(p+"/stat", fmt.Sprintf("%d (%s) S 1 %d %d 0 -1 0 0 0 0 0 900 300 0 0 20 0 4 0 1000 200000000 %d 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n", pid, comm, pid, pid, 30000))
		f.File(p+"/comm", comm+"\n")
		f.File(p+"/status", "Name:\t"+comm+"\nState:\tS (sleeping)\nUid:\t0\t0\t0\t0\n")
		f.File(p+"/cgroup", "0::/system.slice/"+unit+"\n")
		f.File(p+"/limits", "Limit                     Soft Limit           Hard Limit           Units\nMax open files            65536                65536                files\n")
		f.Symlink(fmt.Sprintf("socket:[%d]", ino), p+"/fd/6")
	}
	proc(1187, "redis-server", "redis-server.service", 31001)
	proc(902, "sshd", "ssh.service", 31002)
	head := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
	f.File("/proc/net/tcp", head+
		"   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   110        0 31001 1 0 100 0 0 10 0\n"+
		"   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 31002 1 0 100 0 0 10 0\n")
	f.Cmd("sshd -T", 0, "port 22\npermitrootlogin without-password\npasswordauthentication no\npermitemptypasswords no\nkbdinteractiveauthentication no\n")
	f.File("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin prohibit-password\nPasswordAuthentication no\n")
	f.Cmd("journalctl _COMM=sshd *", 0, "")

	// nginx failed 25 minutes ago, 2 minutes after someone edited a site
	failedAt := now.Add(-25 * time.Minute)
	f.File("/etc/nginx/nginx.conf", "events {}\nhttp { include /etc/nginx/sites-enabled/*; }\n")
	f.File("/etc/nginx/sites-enabled/shop", "server {\n  listen 443 ssl;\n  ssl_certificate /etc/letsencrypt/live/shop.example.com/fullchain.pem;\n}\n")
	f.Touch("/etc/nginx/nginx.conf", now.Add(-90*24*time.Hour))
	f.Touch("/etc/nginx/sites-enabled/shop", failedAt.Add(-2*time.Minute))
	f.Cmd("systemctl list-units --failed *", 0, "nginx.service loaded failed failed A high performance web server and a reverse proxy server\n")
	f.Cmd("systemctl list-units --type=service *", 0, "redis-server.service loaded active running Advanced key-value store\nssh.service loaded active running OpenBSD Secure Shell server\n")
	f.Cmd("systemctl show *", 0, strings.Join([]string{
		"Id=nginx.service", "Description=A high performance web server and a reverse proxy server", "LoadState=loaded",
		"ActiveState=failed", "SubState=failed", "Result=exit-code", "UnitFileState=enabled", "Type=forking",
		"ExecMainCode=1", "ExecMainStatus=1", "MainPID=0", "NRestarts=0", "FragmentPath=/usr/lib/systemd/system/nginx.service",
		"InactiveEnterTimestampMonotonic=" + mono(failedAt), "ExecMainExitTimestampMonotonic=" + mono(failedAt),
		"ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no }", ""}, "\n"))
	f.Cmds["nginx -t"] = sys.Result{Code: 1, Stderr: "nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/shop:14\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"}
	f.Cmd("journalctl -u nginx.service *", 0, "nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/shop:14\nnginx.service: Control process exited, code=exited, status=1/FAILURE\nFailed to start nginx.service - A high performance web server and a reverse proxy server.\n")

	// the kernel log is clean; time is in sync
	f.Cmd("journalctl -k *", 0, iso(boot.Add(time.Second))+" web-prod-1 kernel: Linux version 6.8.0-45-generic (buildd@lcy02-amd64-075)\n"+
		iso(boot.Add(2*time.Second))+" web-prod-1 kernel: EXT4-fs (vdb1): mounted filesystem with ordered data mode\n")
	f.Cmd("timedatectl show *", 0, "NTPSynchronized=yes\nNTP=yes\nTimezone=Etc/UTC\n")

	// packages: a kernel update 3 days ago waits for a reboot
	f.File("/var/log/dpkg.log", local(now.Add(-72*time.Hour))+" upgrade linux-image-generic:amd64 6.8.0-45.45 6.8.0-48.48\n"+
		local(now.Add(-72*time.Hour))+" install linux-image-6.8.0-48-generic:amd64 <none> 6.8.0-48.48\n")
	f.File("/run/reboot-required", "*** System restart required ***\n")
	f.File("/run/reboot-required.pkgs", "linux-image-6.8.0-48-generic\n")
	f.Dir("/lib/modules/6.8.0-45-generic")
	f.Dir("/lib/modules/6.8.0-48-generic")
	f.Programs["apt-get"] = true

	// the certificate: certbot should have renewed it 18 days ago
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "shop.example.com"}, DNSNames: []string{"shop.example.com"},
		NotBefore: now.Add(-78 * 24 * time.Hour), NotAfter: now.Add(12*24*time.Hour + time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	f.File("/etc/letsencrypt/live/shop.example.com/cert.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	f.File("/etc/letsencrypt/live/shop.example.com/fullchain.pem", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	return f
}

// TestDemo runs every check on the demo server, from the files to the screen.
// NABD_DEMO=out.ansi also saves the coloured output (for docs/demo.svg).
func TestDemo(t *testing.T) {
	t.Setenv("COLUMNS", "100")
	f := demoMachine(t)
	code, out, errOut := runWith(t, f, "--color", "always")
	if code != 2 {
		t.Errorf("the demo server has critical problems: exit %d, %s", code, errOut)
	}
	for _, want := range []string{
		"/var is 96% full", "journalctl --vacuum-size=500M",
		"nginx.service failed 25 min ago", `unknown directive "servr"`,
		"Redis listens on 0.0.0.0:6379", "shop.example.com", "certbot renew --dry-run",
		"an update needs a reboot",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in the demo output", want)
		}
	}
	if p := os.Getenv("NABD_DEMO"); p != "" {
		if err := os.WriteFile(p, []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + out)
	}
}

// TestDemoChanges is the "nabd changes" example of the README.
func TestDemoChanges(t *testing.T) {
	f := demoMachine(t)
	now := f.Clock
	day := func(d, h, m int) time.Time {
		x := now.AddDate(0, 0, -d)
		return time.Date(x.Year(), x.Month(), x.Day(), h, m, 0, 0, time.Local)
	}
	upd := day(1, 9, 12)
	f.File("/var/log/dpkg.log", upd.Format("2006-01-02 15:04:05")+" upgrade openssl:amd64 3.0.13-0ubuntu3.4 3.0.13-0ubuntu3.5\n"+
		upd.Format("2006-01-02 15:04:05")+" upgrade libssl3t64:amd64 3.0.13-0ubuntu3.4 3.0.13-0ubuntu3.5\n")
	for _, p := range []string{"/etc/ssl/openssl.cnf", "/etc/ld.so.conf.d/x86_64-linux-gnu.conf", "/etc/default/openssl"} {
		f.File(p, "x\n")
		f.Touch(p, upd.Add(20*time.Second))
	}
	f.File("/root/.ssh/authorized_keys", "ssh-ed25519 AAAA deploy@ci\n")
	f.Touch("/root/.ssh/authorized_keys", day(1, 23, 40))
	code, out, errOut := runWith(t, f, "changes", "--since", "2d", "--color", "never")
	if code != 1 {
		t.Fatalf("changes found: exit %d %s", code, errOut)
	}
	for _, want := range []string{"openssl upgraded", "SSH keys of root changed", "/etc/nginx/sites-enabled/shop", "nginx.service failed", "touches security"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if testing.Verbose() {
		t.Log("\n" + out)
	}
}
