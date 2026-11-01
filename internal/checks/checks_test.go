package checks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/sys"
)

// machine is a small healthy Debian server.
func machine(t *testing.T) *sys.Fake {
	t.Helper()
	f := sys.NewFake(t.TempDir())
	f.File("/etc/os-release", "NAME=\"Debian GNU/Linux\"\nID=debian\nVERSION_ID=\"12\"\nPRETTY_NAME=\"Debian GNU/Linux 12 (bookworm)\"\n")
	f.File("/proc/sys/kernel/osrelease", "6.1.0-28-amd64\n")
	f.File("/proc/uptime", "864000.00 1000.00\n")
	f.File("/proc/meminfo", "MemTotal:        8000000 kB\nMemFree:         3000000 kB\nMemAvailable:    6000000 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n")
	f.File("/proc/loadavg", "0.10 0.20 0.30 1/100 1234\n")
	f.File("/proc/stat", "cpu  100 0 100 10000 10 0 0 0 0 0\n")
	f.File("/proc/self/mountinfo", "22 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw,errors=remount-ro\n")
	f.Fs["/"] = sys.Statfs{Size: 100 << 30, Free: 60 << 30, Avail: 55 << 30, Files: 1000000, FilesFree: 900000}
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nalice:x:1000:1000::/home/alice:/bin/bash\n")
	f.File("/etc/shadow", "root:$y$j9T$abc:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::\nalice:$y$j9T$def:19000:0:99999:7:::\n")
	f.File("/etc/resolv.conf", "nameserver 192.0.2.53\n")
	f.File("/proc/net/route", "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\neth0\t00000000\t0100000A\t0003\t0\t0\t0\t00000000\t0\t0\t0\n")
	f.Dir("/proc/net")
	return f
}

func run(t *testing.T, f *sys.Fake, ch core.Check) (core.CheckResult, []core.Finding) {
	t.Helper()
	c := core.NewCtx(f)
	c.SampleTime = 0
	res, fs := core.Run(c, []core.Check{ch}, core.Options{Timeout: 10 * time.Second})
	if len(res) != 1 {
		t.Fatalf("want 1 result, got %d", len(res))
	}
	return res[0], fs
}

func find(fs []core.Finding, id string) *core.Finding {
	for i := range fs {
		if fs[i].ID == id {
			return &fs[i]
		}
	}
	return nil
}

func ids(fs []core.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"="+f.Severity.String())
	}
	return strings.Join(out, ", ")
}

func TestDiskHealthy(t *testing.T) {
	res, fs := run(t, machine(t), Disk)
	if res.Status != "ok" || len(fs) != 0 {
		t.Fatalf("want ok and no findings, got %s: %s", res.Status, ids(fs))
	}
}

func TestDiskFull(t *testing.T) {
	f := machine(t)
	f.Fs["/"] = sys.Statfs{Size: 100 << 30, Free: 2 << 30, Avail: 1 << 30, Files: 1000000, FilesFree: 900000}
	f.File("/var/log/app.log", "x")
	_, fs := run(t, f, Disk)
	full := find(fs, "disk.full")
	if full == nil || full.Severity != core.Crit {
		t.Fatalf("want a critical disk.full finding, got: %s", ids(fs))
	}
	if !strings.Contains(full.Title, "/ is 99% full") {
		t.Fatalf("title: %q", full.Title)
	}
	if len(full.Fix) == 0 {
		t.Fatal("a full disk needs a fix")
	}
}

func TestDiskInodes(t *testing.T) {
	f := machine(t)
	f.Fs["/"] = sys.Statfs{Size: 100 << 30, Free: 60 << 30, Avail: 55 << 30, Files: 1000000, FilesFree: 30000}
	_, fs := run(t, f, Disk)
	if len(fs) == 0 || fs[0].Severity != core.Crit {
		t.Fatalf("97%% inodes used must be critical, got: %s", ids(fs))
	}
}

func TestDiskReadOnlyIsNotFull(t *testing.T) {
	f := machine(t)
	f.File("/proc/self/mountinfo", "22 1 252:1 / / rw,relatime - ext4 /dev/vda1 rw\n30 22 252:3 / /mnt/rescue ro,relatime - ext4 /dev/vdc ro\n")
	f.Fs["/mnt/rescue"] = sys.Statfs{Size: 1 << 30, Free: 0, Avail: 0, Files: 1000, FilesFree: 0}
	res, fs := run(t, f, Disk)
	if len(fs) != 0 {
		t.Fatalf("a read-only file system cannot fill up, got: %s", ids(fs))
	}
	if !strings.Contains(res.Detail, "1 file system") {
		t.Fatalf("the read-only mount must not be counted: %q", res.Detail)
	}
}

func TestMemoryLow(t *testing.T) {
	f := machine(t)
	f.File("/proc/meminfo", "MemTotal:        8000000 kB\nMemFree:          100000 kB\nMemAvailable:     240000 kB\nSwapTotal:             0 kB\nSwapFree:              0 kB\n")
	_, fs := run(t, f, Memory)
	low := find(fs, "memory.low")
	if low == nil || low.Severity != core.Crit {
		t.Fatalf("3%% free must be critical, got: %s", ids(fs))
	}
}

// listener adds a process with a listening socket on 0.0.0.0:port.
func listener(f *sys.Fake, pid int, comm string, port int, inode int) {
	line := func(i int) string {
		return "   " + itoa(i) + ": 00000000:" + hex4(port) + " 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 " + itoa(inode) + " 1 0000000000000000 100 0 0 10 0\n"
	}
	f.File("/proc/net/tcp", "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"+line(0))
	p := "/proc/" + itoa(pid)
	f.File(p+"/stat", itoa(pid)+" ("+comm+") S 1 1 1 0 -1 0 0 0 0 0 10 10 0 0 20 0 1 0 100 1000 100 0 0 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	f.File(p+"/comm", comm+"\n")
	f.File(p+"/status", "Name:\t"+comm+"\nUid:\t999\t999\t999\t999\n")
	f.File(p+"/cgroup", "0::/system.slice/"+comm+".service\n")
	f.Symlink("socket:["+itoa(inode)+"]", p+"/fd/3")
}

func itoa(i int) string {
	return strings.TrimSpace(strings.Replace(time.Duration(i).String(), "ns", "", 1))
}

func hex4(n int) string {
	const digits = "0123456789ABCDEF"
	return string([]byte{digits[n>>12&15], digits[n>>8&15], digits[n>>4&15], digits[n&15]})
}

func TestPortsRedisOpen(t *testing.T) {
	f := machine(t)
	listener(f, 812, "redis-server", 6379, 41001)
	_, fs := run(t, f, Ports)
	x := find(fs, "ports.exposed-6379")
	if x == nil {
		t.Fatalf("an open Redis port must be found, got: %s", ids(fs))
	}
	if x.Severity != core.Crit {
		t.Fatalf("Redis open to the network without a firewall must be critical, got %s", x.Severity)
	}
	if !strings.Contains(strings.Join(x.Why, " "), "redis-server (pid 812, redis-server.service)") {
		t.Fatalf("the finding must name the process and unit: %v", x.Why)
	}
}

func TestPortsFirewallLowersSeverity(t *testing.T) {
	f := machine(t)
	listener(f, 812, "redis-server", 6379, 41001)
	f.File("/etc/ufw/ufw.conf", "# /etc/ufw/ufw.conf\nENABLED=yes\nLOGLEVEL=low\n")
	_, fs := run(t, f, Ports)
	x := find(fs, "ports.exposed-6379")
	if x == nil || x.Severity == core.Crit {
		t.Fatalf("with an active firewall the open port is a warning to check, got: %s", ids(fs))
	}
}

func TestPortsDockerAPIAlwaysCritical(t *testing.T) {
	f := machine(t)
	listener(f, 900, "dockerd", 2375, 41009)
	f.Cmd("nft list ruleset", 0, "table inet filter {\n\tchain input {\n\t\ttype filter hook input priority filter; policy drop;\n\t\tct state established,related accept\n\t}\n}\n")
	_, fs := run(t, f, Ports)
	x := find(fs, "ports.exposed-2375")
	if x == nil || x.Severity != core.Crit {
		t.Fatalf("the open Docker API is root for everybody: must be critical, got: %s", ids(fs))
	}
	if !strings.Contains(strings.Join(x.Why, " "), "nftables") {
		t.Fatalf("the nftables firewall must be found: %v", x.Why)
	}
}

func TestSSHEmptyPasswords(t *testing.T) {
	f := machine(t)
	f.Programs["sshd"] = true // sshd -T fails, so nabd reads the files
	f.File("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin no\n")
	f.File("/etc/ssh/sshd_config.d/50-bad.conf", "PermitEmptyPasswords yes\n")
	_, fs := run(t, f, SSH)
	x := find(fs, "ssh.empty-passwords")
	if x == nil || x.Severity != core.Crit {
		t.Fatalf("PermitEmptyPasswords yes (from an Include) must be critical, got: %s", ids(fs))
	}
}

func TestSSHFirstValueWins(t *testing.T) {
	f := machine(t)
	f.Programs["sshd"] = true
	// sshd uses the first value it reads: the drop-in "no" wins over the later "yes"
	f.File("/etc/ssh/sshd_config", "Include /etc/ssh/sshd_config.d/*.conf\nPermitRootLogin yes\nPasswordAuthentication yes\n")
	f.File("/etc/ssh/sshd_config.d/10-hardening.conf", "PermitRootLogin no\n")
	_, fs := run(t, f, SSH)
	for _, x := range fs {
		if strings.Contains(x.ID, "root") {
			t.Fatalf("root login is off by the first value, got: %s", ids(fs))
		}
	}
}

func TestAccountsSecondRoot(t *testing.T) {
	f := machine(t)
	f.File("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n")
	_, fs := run(t, f, Accounts)
	x := find(fs, "accounts.uid0")
	if x == nil || x.Severity != core.Crit || !strings.Contains(x.Title, `"toor"`) {
		t.Fatalf("a second UID 0 account must be critical, got: %s", ids(fs))
	}
}

func TestAccountsEmptyPassword(t *testing.T) {
	f := machine(t)
	f.File("/etc/shadow", "root:$y$j9T$abc:19000:0:99999:7:::\nalice::19000:0:99999:7:::\ndaemon::19000:0:99999:7:::\n")
	_, fs := run(t, f, Accounts)
	x := find(fs, "accounts.no-password")
	if x == nil || !strings.Contains(x.Title, `"alice"`) {
		t.Fatalf("alice can log in without a password, got: %s", ids(fs))
	}
	for _, y := range fs {
		if strings.Contains(y.Title, "daemon") {
			t.Fatal("daemon has no login shell: an empty password field is not a problem there")
		}
	}
}

func TestKernelFileSystemErrors(t *testing.T) {
	f := machine(t)
	f.Cmd("journalctl -k -b -o short-iso --no-pager -q", 0,
		"2026-11-01T11:00:00+0000 test-host kernel: Linux version 6.1.0-28-amd64\n"+
			"2026-11-01T11:58:00+0000 test-host kernel: EXT4-fs error (device vda1): ext4_lookup:1855: inode #1311: comm nginx: deleted inode referenced: 1312\n")
	_, fs := run(t, f, Kernel)
	if len(fs) == 0 || fs[0].Severity != core.Crit {
		t.Fatalf("file system errors in the kernel log must be critical, got: %s", ids(fs))
	}
}

func TestRebootRequired(t *testing.T) {
	f := machine(t)
	f.File("/run/reboot-required", "*** System restart required ***\n")
	f.File("/run/reboot-required.pkgs", "linux-image-6.1.0-29-amd64\n")
	_, fs := run(t, f, Reboot)
	x := find(fs, "reboot.required")
	if x == nil || x.Severity != core.Warn {
		t.Fatalf("want a reboot warning, got: %s", ids(fs))
	}
}

func cert(t *testing.T, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "shop.example.com"},
		DNSNames: []string{"shop.example.com"}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func TestCertExpiresSoon(t *testing.T) {
	f := machine(t)
	f.File("/etc/nginx/sites-enabled/shop", "server {\n  listen 443 ssl;\n  ssl_certificate /etc/ssl/shop/fullchain.pem;\n}\n")
	f.File("/etc/ssl/shop/fullchain.pem", cert(t, f.Clock.Add(3*24*time.Hour)))
	_, fs := run(t, f, Certs)
	if len(fs) != 1 || fs[0].Severity != core.Crit || !strings.Contains(fs[0].Title, "shop.example.com") {
		t.Fatalf("a certificate that ends in 3 days must be critical, got: %s", ids(fs))
	}
}

func TestCertFine(t *testing.T) {
	f := machine(t)
	f.Dir("/etc/letsencrypt/live/shop.example.com")
	f.File("/etc/letsencrypt/live/shop.example.com/cert.pem", cert(t, f.Clock.Add(60*24*time.Hour)))
	res, fs := run(t, f, Certs)
	if len(fs) != 0 || res.Status != "ok" || !strings.Contains(res.Detail, "60 days") {
		t.Fatalf("a certificate with 60 days left is fine, got %s %q: %s", res.Status, res.Detail, ids(fs))
	}
}

const showNginx = `Id=nginx.service
Description=A high performance web server
LoadState=loaded
ActiveState=failed
SubState=failed
Result=exit-code
UnitFileState=enabled
Type=forking
ExecMainCode=1
ExecMainStatus=1
MainPID=0
NRestarts=0
FragmentPath=/lib/systemd/system/nginx.service
InactiveEnterTimestampMonotonic=86000000000
ExecStart={ path=/usr/sbin/nginx ; argv[]=/usr/sbin/nginx -g daemon on; master_process on; ; ignore_errors=no }
`

func TestServiceFailed(t *testing.T) {
	f := machine(t)
	f.Dir("/run/systemd/system")
	f.Cmd("systemctl list-units --failed *", 0, "nginx.service loaded failed failed A high performance web server\n")
	f.Cmd("systemctl list-units --type=service *", 0, "")
	f.Cmd("systemctl show *", 0, showNginx)
	f.Cmd("nginx -t", 1, "")
	f.Cmds["nginx -t"] = sys.Result{Code: 1, Stderr: "nginx: [emerg] unknown directive \"servr\" in /etc/nginx/sites-enabled/shop:1\nnginx: configuration file /etc/nginx/nginx.conf test failed\n"}
	_, fs := run(t, f, Services)
	x := find(fs, "services.failed")
	if x == nil || x.Severity != core.Crit {
		t.Fatalf("an enabled service that failed must be critical, got: %s", ids(fs))
	}
	if !strings.Contains(strings.Join(x.Why, "\n"), "unknown directive") {
		t.Fatalf("the config test result must explain the failure: %v", x.Why)
	}
}

func TestOneBrokenCheckDoesNotStopTheOthers(t *testing.T) {
	f := machine(t)
	c := core.NewCtx(f)
	c.SampleTime = 0
	boom := core.Check{Name: "boom", Run: func(*core.Ctx, *core.Out) { panic("bad data") }}
	res, fs := core.Run(c, []core.Check{boom, Accounts}, core.Options{})
	if len(res) != 2 {
		t.Fatalf("want 2 results, got %d", len(res))
	}
	if find(fs, "boom.error") == nil || res[1].Status != "ok" {
		t.Fatalf("a panic becomes an unknown finding and the next check still runs: %s / %+v", ids(fs), res)
	}
}

func TestAllChecksRunOnAnEmptyMachine(t *testing.T) {
	// nothing is there: no check may panic or hang
	f := sys.NewFake(t.TempDir())
	c := core.NewCtx(f)
	c.SampleTime = 0
	res, fs := core.Run(c, All(), core.Options{Timeout: 10 * time.Second})
	if len(res) != len(All()) {
		t.Fatalf("want %d results, got %d", len(All()), len(res))
	}
	for _, x := range fs {
		if strings.HasSuffix(x.ID, ".error") || strings.HasSuffix(x.ID, ".timeout") {
			t.Errorf("%s: %s", x.ID, x.Title)
		}
	}
}

func TestNoCheckWritesOrRunsUnknownPrograms(t *testing.T) {
	f := machine(t)
	c := core.NewCtx(f)
	c.SampleTime = 0
	core.Run(c, All(), core.Options{Timeout: 10 * time.Second})
	allowed := []string{"systemctl", "journalctl", "dmesg", "timedatectl", "chronyc", "needs-restarting", "sshd", "ufw", "firewall-cmd",
		"nft", "iptables", "last", "nginx", "apachectl", "haproxy", "named-checkconf", "postfix", "doveconf", "php-fpm", "squid",
		"dnsmasq", "unbound-checkconf", "keepalived", "caddy", "varnishd", "rpm", "dpkg", "dpkg-query", "pacman", "apk", "zypper", "dnf", "yum"}
	ok := map[string]bool{}
	for _, a := range allowed {
		ok[a] = true
	}
	for _, call := range f.Calls() {
		name := strings.Fields(call)[0]
		if !ok[name] {
			t.Errorf("unexpected program: %s", call)
		}
		for _, bad := range []string{" restart", " stop", " start", " enable", " disable", " -w ", " --delete", " rm "} {
			if strings.Contains(" "+call+" ", bad) && !strings.HasPrefix(call, "systemctl show") && !strings.HasPrefix(call, "systemctl list") {
				t.Errorf("a check must only read, but ran: %s", call)
			}
		}
	}
}
