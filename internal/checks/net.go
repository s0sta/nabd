package checks

import (
	"fmt"
	"net"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Network checks the default route and the DNS setup (no traffic is sent).
var Network = core.Check{
	Name:  "network",
	Title: "Network and DNS setup",
	Help:  "A default route exists, DNS servers are set, and a local DNS address (127.0.0.53 or 127.0.0.1) really has a DNS server behind it. Sends no traffic.",
	Run:   runNetwork,
}

// Ports checks services that listen on all addresses but should not.
var Ports = core.Check{
	Name:  "ports",
	Title: "Open ports",
	Help:  "Databases, caches and admin APIs that listen on every address (Redis, MongoDB, Elasticsearch, Memcached, MySQL, PostgreSQL, the Docker API, telnet …), with the process behind them and whether a firewall is on.",
	Run:   runPorts,
}

// SSH checks the SSH server settings and login attacks.
var SSH = core.Check{
	Name:  "ssh",
	Title: "SSH server",
	Help:  "Empty passwords, root login with a password, and failed logins in the last hour (brute force).",
	Run:   runSSH,
}

func runNetwork(c *core.Ctx, o *core.Out) {
	sudo := c.Sudo()
	gw, dev := defaultRoute(c)
	if gw == "" && !hasDefault6(c) {
		o.Add(core.Finding{ID: "no-route", Severity: core.Warn, Title: "there is no default route",
			Why: []string{"this machine cannot reach other networks or the internet"},
			Fix: []string{"ip route   # look at the routes", "# set a gateway in your network config (nmcli, netplan or /etc/network)"}})
	} else if gw != "" {
		o.OK("default route via %s (%s)", gw, dev)
	}
	b, err := c.Sys.ReadFile("/etc/resolv.conf")
	if err != nil {
		o.Add(core.Finding{ID: "no-resolv", Severity: core.Crit, Title: "/etc/resolv.conf is missing",
			Why: []string{"no DNS: names like example.com cannot be found"},
			Fix: []string{"ls -l /etc/resolv.conf   # a broken link?"}})
		return
	}
	var servers []string
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "nameserver" {
			servers = append(servers, f[1])
		}
	}
	if len(servers) == 0 {
		o.Add(core.Finding{ID: "no-dns", Severity: core.Crit, Title: "no DNS server is set in /etc/resolv.conf",
			Why: []string{"names like example.com cannot be found"},
			Fix: []string{"# set DNS in your network config, for example: " + sudo + "nmcli con mod CONNECTION ipv4.dns 1.1.1.1"}})
		return
	}
	o.OK("DNS %s", strings.Join(servers, ", "))
	if c.Facts.Container != "" {
		return
	}
	for _, s := range servers {
		ip := net.ParseIP(s)
		if ip == nil || !ip.IsLoopback() {
			continue
		}
		if s == "127.0.0.53" {
			if !procRunning(c, "systemd-resolve") {
				o.Add(core.Finding{ID: "resolved-down", Severity: core.Crit,
					Title: "DNS points to systemd-resolved (127.0.0.53), but it is not running",
					Why:   []string{"no name can be found until it runs"},
					Fix:   []string{sudo + "systemctl enable --now systemd-resolved"}})
			}
			continue
		}
		if !listensUDP53(c, ip) {
			o.Add(core.Finding{ID: "local-dns-down", Severity: core.Crit,
				Title: "DNS points to " + s + ", but no DNS server listens there",
				Why:   []string{"a local DNS cache (dnsmasq, unbound, bind) is stopped, or /etc/resolv.conf is wrong"},
				Fix:   []string{"nabd why port 53", "nabd why dns"}})
		}
	}
}

func defaultRoute(c *core.Ctx) (gw, dev string) {
	b, err := c.Sys.ReadFile("/proc/net/route")
	if err != nil {
		return "", ""
	}
	for i, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if i == 0 || len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		if g, err := strconv.ParseUint(f[2], 16, 32); err == nil {
			ip := net.IPv4(byte(g), byte(g>>8), byte(g>>16), byte(g>>24))
			return ip.String(), f[0]
		}
	}
	return "", ""
}

func hasDefault6(c *core.Ctx) bool {
	b, err := c.Sys.ReadFile("/proc/net/ipv6_route")
	if err != nil {
		return false
	}
	for _, l := range linux.Lines(b) {
		f := strings.Fields(l)
		if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" && f[9] != "lo" {
			return true
		}
	}
	return false
}

func procRunning(c *core.Ctx, comm string) bool {
	for _, p := range c.Procs() {
		if p.Comm == comm {
			return true
		}
	}
	return false
}

func listensUDP53(c *core.Ctx, ip net.IP) bool {
	ls, _ := c.Listeners()
	for _, l := range ls {
		if l.Port == 53 && (l.IP.Equal(ip) || l.Wildcard()) {
			return true
		}
	}
	return false
}

type riskyPort struct {
	name    string
	sev     core.Severity // without a firewall
	why     string
	fix     string
	process []string
}

var riskyPorts = map[int]riskyPort{
	2375:  {"the Docker API (no TLS)", core.Crit, "anyone who reaches this port controls Docker, and so is root on this machine", "remove `-H tcp://0.0.0.0:2375` from the Docker service; use the local socket, or TLS on 2376", []string{"dockerd"}},
	6379:  {"Redis", core.Crit, "Redis has no password by default; open Redis servers are attacked within hours", "in redis.conf: `bind 127.0.0.1 -::1` and `protected-mode yes`, then restart redis", []string{"redis-server", "redis"}},
	11211: {"Memcached", core.Crit, "Memcached has no login; open servers are used for DDoS attacks", "listen on localhost only: `-l 127.0.0.1` in /etc/sysconfig/memcached or /etc/memcached.conf", []string{"memcached"}},
	27017: {"MongoDB", core.Crit, "MongoDB without auth on the network is a common data leak", "in /etc/mongod.conf: `net.bindIp: 127.0.0.1` and turn on authorization", []string{"mongod"}},
	9200:  {"Elasticsearch / OpenSearch", core.Crit, "the search API can read and delete all data if security is off", "in elasticsearch.yml / opensearch.yml: `network.host: 127.0.0.1`, or turn on security", []string{"java"}},
	5984:  {"CouchDB", core.Crit, "the database admin API is open to the network", "bind_address = 127.0.0.1 in local.ini", []string{"beam.smp"}},
	2379:  {"etcd", core.Crit, "etcd holds cluster secrets; without client TLS anyone can read them", "listen-client-urls only on localhost or with client certificates", []string{"etcd"}},
	23:    {"telnet", core.Crit, "telnet sends passwords in clear text", "turn it off and use SSH: " + "systemctl disable --now telnet.socket", []string{"telnetd", "in.telnetd", "systemd"}},
	3306:  {"MySQL / MariaDB", core.Warn, "the database can be reached from the network; only its passwords protect it", "bind-address = 127.0.0.1 in my.cnf (if only local apps use it)", []string{"mysqld", "mariadbd"}},
	5432:  {"PostgreSQL", core.Warn, "the database can be reached from the network; only pg_hba.conf and passwords protect it", "listen_addresses = 'localhost' in postgresql.conf (if only local apps use it)", []string{"postgres", "postmaster"}},
	8086:  {"InfluxDB", core.Warn, "the time-series database API is open to the network", "bind it to 127.0.0.1 or turn on auth", []string{"influxd"}},
	9042:  {"Cassandra", core.Warn, "the database is open to the network", "set rpc_address to a private address", []string{"java"}},
	5601:  {"Kibana", core.Warn, "the Kibana UI is open to the network", "server.host: \"127.0.0.1\" in kibana.yml", []string{"node"}},
	15672: {"RabbitMQ management", core.Warn, "the RabbitMQ admin UI is open to the network", "listen only on localhost, change the guest user", []string{"beam.smp"}},
	9090:  {"Prometheus", core.Warn, "Prometheus has no login by default and shows your whole setup", "--web.listen-address=127.0.0.1:9090 or put it behind a proxy with login", []string{"prometheus"}},
	873:   {"rsync daemon", core.Warn, "rsync modules can be readable without a password", "check /etc/rsyncd.conf (auth users, hosts allow)", []string{"rsync"}},
	2049:  {"NFS", core.Warn, "NFS shares are reachable from the network", "check /etc/exports: allow only your client addresses", []string{"rpc.nfsd"}},
	5900:  {"VNC", core.Warn, "VNC is often weakly protected", "use it through an SSH tunnel and listen on localhost", []string{"Xvnc", "x11vnc", "vncserver"}},
	21:    {"FTP", core.Warn, "plain FTP sends passwords in clear text", "use SFTP (part of SSH) instead", []string{"vsftpd", "proftpd", "pure-ftpd"}},
}

// Firewall is what nabd can tell about the firewall.
type Firewall struct {
	Name   string // firewalld, ufw, nftables, iptables, ""
	Active bool
}

// DetectFirewall finds an active firewall (best effort, no root needed for most).
func DetectFirewall(c *core.Ctx) Firewall {
	if procRunning(c, "firewalld") {
		return Firewall{"firewalld", true}
	}
	if b, err := c.Sys.ReadFile("/etc/ufw/ufw.conf"); err == nil && regexp.MustCompile(`(?m)^ENABLED=yes`).Match(b) {
		return Firewall{"ufw", true}
	}
	if c.Facts.Root {
		if r := c.Sys.Run(5*time.Second, "nft", "list", "ruleset"); r.OK() && strings.Count(r.Stdout, "\n") > 3 {
			if strings.Contains(r.Stdout, "drop") || strings.Contains(r.Stdout, "reject") {
				return Firewall{"nftables", true}
			}
		}
		if r := c.Sys.Run(5*time.Second, "iptables", "-S", "INPUT"); r.OK() &&
			(strings.Contains(r.Stdout, "-P INPUT DROP") || strings.Contains(r.Stdout, "-j DROP") || strings.Contains(r.Stdout, "-j REJECT")) {
			return Firewall{"iptables", true}
		}
	}
	return Firewall{}
}

// Exposed is true when other machines can connect to the socket.
func Exposed(l core.Listener) bool {
	if l.Loopback() {
		return false
	}
	return true
}

func runPorts(c *core.Ctx, o *core.Out) {
	ls, full := c.Listeners()
	if !full && !c.Facts.Root {
		o.Limit("processes behind other users' sockets")
	}
	fw := DetectFirewall(c)
	var open []string
	seen := map[string]bool{}
	for _, l := range ls {
		if !Exposed(l) || !strings.HasPrefix(l.Proto, "tcp") {
			continue
		}
		label := strconv.Itoa(l.Port)
		if l.Process != "" {
			label += " (" + l.Process + ")"
		}
		if !seen[label] {
			seen[label] = true
			open = append(open, label)
		}
		rp, risky := riskyPorts[l.Port]
		if !risky || seen["risk"+strconv.Itoa(l.Port)] {
			continue
		}
		seen["risk"+strconv.Itoa(l.Port)] = true
		sev := rp.sev
		f := core.Finding{ID: "exposed-" + strconv.Itoa(l.Port),
			Title: fmt.Sprintf("%s listens on %s: other machines can connect", rp.name, l.Addr()),
			Why:   []string{rp.why},
			Fix:   []string{"# " + rp.fix},
			Data:  map[string]interface{}{"port": l.Port, "address": l.Addr(), "pid": l.PID, "process": l.Process}}
		if l.PID > 0 {
			f.Why = append(f.Why, "process: "+c.Owner(l.PID))
		}
		if fw.Active {
			f.Why = append(f.Why, "a firewall ("+fw.Name+") is on: check that it blocks port "+strconv.Itoa(l.Port))
			if sev == core.Crit {
				sev = core.Warn
			} else {
				sev = core.Info
			}
		} else {
			f.Why = append(f.Why, "no active firewall was found")
			switch {
			case c.Sys.Has("ufw"):
				f.Fix = append(f.Fix, c.Sudo()+"ufw deny "+strconv.Itoa(l.Port)+"/tcp")
			case c.Sys.Has("firewall-cmd"):
				f.Fix = append(f.Fix, c.Sudo()+"systemctl enable --now firewalld   # the default zone blocks this port")
			}
		}
		if l.Port == 2375 {
			sev = core.Crit
		}
		f.Severity = sev
		o.Add(f)
	}
	if len(open) == 0 {
		o.OK("no TCP port is open to the network")
		return
	}
	sort.Strings(open)
	if len(open) > 8 {
		open = append(open[:8], fmt.Sprintf("+%d more", len(open)-8))
	}
	fwText := "no firewall found"
	if fw.Active {
		fwText = "firewall: " + fw.Name
	}
	o.OK("open to the network: %s; %s", strings.Join(open, ", "), fwText)
}

// ---------------------------------------------------------------- SSH

// SSHDConfig reads the effective SSH server settings: `sshd -T` as root,
// else the config files (first value wins, Match blocks are skipped).
func SSHDConfig(c *core.Ctx) (map[string]string, string) {
	if c.Facts.Root {
		if r := c.Sys.Run(5*time.Second, "sshd", "-T"); r.OK() {
			m := map[string]string{}
			for _, l := range strings.Split(r.Stdout, "\n") {
				if f := strings.Fields(l); len(f) >= 2 {
					if _, ok := m[f[0]]; !ok {
						m[f[0]] = strings.ToLower(f[1])
					}
				}
			}
			return m, "sshd -T"
		}
	}
	m := map[string]string{}
	readSSHD(c, "/etc/ssh/sshd_config", m, 0)
	return m, "/etc/ssh/sshd_config"
}

func readSSHD(c *core.Ctx, file string, m map[string]string, depth int) {
	if depth > 5 {
		return
	}
	b, err := c.Sys.ReadFile(file)
	if err != nil {
		return
	}
	for _, l := range linux.Lines(b) {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(strings.Replace(l, "=", " ", 1))
		if len(f) < 2 {
			continue
		}
		key := strings.ToLower(f[0])
		if key == "match" {
			return // the rest is conditional
		}
		if key == "include" {
			for _, pat := range f[1:] {
				if !strings.HasPrefix(pat, "/") {
					pat = "/etc/ssh/" + pat
				}
				dir := path.Dir(pat)
				ents, _ := c.Sys.ReadDir(dir)
				var names []string
				for _, e := range ents {
					if ok, _ := filepath.Match(path.Base(pat), e.Name()); ok {
						names = append(names, dir+"/"+e.Name())
					}
				}
				sort.Strings(names)
				for _, n := range names {
					readSSHD(c, n, m, depth+1)
				}
			}
			continue
		}
		if _, ok := m[key]; !ok {
			m[key] = strings.ToLower(f[1])
		}
	}
}

var (
	sshFailRe = regexp.MustCompile(`Failed password for|Invalid user|authentication failure;|Connection closed by authenticating user|maximum authentication attempts exceeded|Failed publickey for`)
	sshIPRe   = regexp.MustCompile(`from (\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,39}) port`)
)

// SSHFailures counts failed SSH logins in the last hour and the top addresses.
func SSHFailures(c *core.Ctx) (count int, top []string, ok bool) {
	var lines []string
	r := c.Sys.Run(8*time.Second, "journalctl", "_COMM=sshd", "--since", "-1h", "-o", "cat", "--no-pager", "-q")
	if r.OK() && strings.TrimSpace(r.Stdout) != "" {
		lines = strings.Split(r.Stdout, "\n")
		ok = true
	} else {
		cut := c.Sys.Now().Add(-time.Hour)
		for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
			b, err := c.Sys.ReadFile(p)
			if err != nil {
				continue
			}
			ok = true
			if len(b) > 16<<20 {
				b = b[len(b)-16<<20:]
			}
			for _, l := range linux.Lines(b) {
				if t, good := lineTime(c, l); good && t.After(cut) {
					lines = append(lines, l)
				}
			}
		}
		if !ok && r.OK() {
			ok = true // journal readable, simply no lines
		}
	}
	byIP := map[string]int{}
	for _, l := range lines {
		if !sshFailRe.MatchString(l) {
			continue
		}
		count++
		if m := sshIPRe.FindStringSubmatch(l); m != nil {
			byIP[m[1]]++
		}
	}
	ips := make([]string, 0, len(byIP))
	for ip := range byIP {
		ips = append(ips, ip)
	}
	sort.Slice(ips, func(i, j int) bool { return byIP[ips[i]] > byIP[ips[j]] })
	for i, ip := range ips {
		if i == 3 {
			break
		}
		top = append(top, fmt.Sprintf("%s (%d)", ip, byIP[ip]))
	}
	return count, top, ok
}

var sysTimeRe = regexp.MustCompile(`^([A-Z][a-z]{2}\s+\d{1,2} \d\d:\d\d:\d\d) `)

func lineTime(c *core.Ctx, l string) (time.Time, bool) {
	if m := sysTimeRe.FindStringSubmatch(l); m != nil {
		t, err := time.ParseInLocation("2006 Jan _2 15:04:05", strconv.Itoa(c.Sys.Now().Year())+" "+m[1], time.Local)
		if err != nil {
			return time.Time{}, false
		}
		if t.After(c.Sys.Now().Add(24 * time.Hour)) {
			t = t.AddDate(-1, 0, 0)
		}
		return t, true
	}
	if ts, _, ok := strings.Cut(l, " "); ok {
		return core.ParseISO(ts)
	}
	return time.Time{}, false
}

func runSSH(c *core.Ctx, o *core.Out) {
	listening := false
	ls, _ := c.Listeners()
	for _, l := range ls {
		if l.Port == 22 || l.Process == "sshd" {
			listening = true
		}
	}
	if !c.Sys.Has("sshd") && !listening {
		o.Skip("no SSH server on this machine")
		return
	}
	cfg, src := SSHDConfig(c)
	get := func(k, def string) string {
		if v, ok := cfg[k]; ok {
			return v
		}
		return def
	}
	if src != "sshd -T" {
		o.Limit("SSH settings from sshd -T (read from the files instead)")
	}
	root := get("permitrootlogin", "prohibit-password")
	pass := get("passwordauthentication", "yes")
	sudo := c.Sudo()
	if get("permitemptypasswords", "no") == "yes" {
		o.Add(core.Finding{ID: "empty-passwords", Severity: core.Crit,
			Title: "SSH allows accounts with an empty password to log in",
			Fix:   []string{"# set PermitEmptyPasswords no in /etc/ssh/sshd_config", sudo + "sshd -t && " + sudo + "systemctl reload sshd"}})
	}
	if root == "yes" && pass == "yes" {
		o.Add(core.Finding{ID: "root-password", Severity: core.Warn,
			Title: "root can log in over SSH with a password",
			Why:   []string{"attackers try root passwords all day; one weak password gives them the whole machine"},
			Fix: []string{"# in /etc/ssh/sshd_config: PermitRootLogin prohibit-password  (keys only)",
				sudo + "sshd -t && " + sudo + "systemctl reload sshd"},
			Note: "check that you can log in with a key or another user first"})
	}
	n, top, ok := SSHFailures(c)
	if !ok {
		o.Limit("SSH login log")
	}
	if n >= 20 {
		f := core.Finding{ID: "bruteforce", Severity: core.Warn,
			Title: fmt.Sprintf("%d failed SSH logins in the last hour", n),
			Data:  map[string]interface{}{"failed_logins_1h": n}}
		if len(top) > 0 {
			f.Why = []string{"most from: " + strings.Join(top, ", ")}
		}
		if pass == "no" {
			f.Severity = core.Info
			f.Why = append(f.Why, "password login is off, so these tries cannot work; this is internet noise")
		} else {
			f.Why = append(f.Why, "password login is on: a weak password can be guessed")
			f.Fix = []string{"# use keys and set PasswordAuthentication no in /etc/ssh/sshd_config",
				"# and/or install fail2ban to block addresses that keep trying"}
		}
		o.Add(f)
	}
	o.OK("PermitRootLogin %s, PasswordAuthentication %s, %d failed logins in the last hour", root, pass, n)
}
