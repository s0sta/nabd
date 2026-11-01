package checks

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/s0sta/nabd/internal/core"
	"github.com/s0sta/nabd/internal/linux"
)

// Certs checks TLS certificates that web and mail servers use.
var Certs = core.Check{
	Name:  "certs",
	Title: "TLS certificates",
	Help:  "Certificates used by nginx, Apache, HAProxy, Postfix, Dovecot and Let's Encrypt: expired or expiring soon. Read from the server configs, parsed by nabd itself (no openssl needed).",
	Run:   runCerts,
}

// Procs checks zombies, stuck processes and open-file limits.
var Procs = core.Check{
	Name:  "procs",
	Title: "Processes",
	Help:  "Zombie processes (and the parent that leaves them), processes stuck in D state, processes close to their open-file limit, and the system-wide file and process limits.",
	Run:   runProcs,
}

// Accounts checks user accounts for dangerous settings.
var Accounts = core.Check{
	Name:  "accounts",
	Title: "User accounts",
	Help:  "Other accounts with UID 0 (full root rights) and accounts without a password.",
	Run:   runAccounts,
}

var certCfg = []struct {
	glob []string
	re   *regexp.Regexp
}{
	{[]string{"/etc/nginx"}, regexp.MustCompile(`(?m)^\s*ssl_certificate\s+([^;\s]+)\s*;`)},
	{[]string{"/etc/httpd", "/etc/apache2"}, regexp.MustCompile(`(?mi)^\s*SSLCertificateFile\s+"?([^"\s]+)`)},
	{[]string{"/etc/haproxy"}, regexp.MustCompile(`\bcrt\s+(\S+)`)},
	{[]string{"/etc/postfix"}, regexp.MustCompile(`(?m)^\s*smtpd_tls_cert_file\s*=\s*(\S+)`)},
	{[]string{"/etc/dovecot"}, regexp.MustCompile(`(?m)^\s*ssl_cert\s*=\s*<\s*(\S+)`)},
}

// CertFile is a certificate in use.
type CertFile struct {
	Path     string    `json:"path"`
	Subject  string    `json:"subject"`
	Names    []string  `json:"names,omitempty"`
	NotAfter time.Time `json:"not_after"`
	UsedBy   string    `json:"used_by"`
}

// FindCerts collects certificates from server configs and Let's Encrypt.
func FindCerts(c *core.Ctx) (certs []CertFile, unreadable []string) {
	paths := map[string]string{}
	add := func(p, by string) {
		if strings.Contains(p, "$") || p == "" {
			return
		}
		if _, ok := paths[p]; !ok {
			paths[p] = by
		}
	}
	for _, cc := range certCfg {
		for _, dir := range cc.glob {
			_ = c.Sys.Walk(dir, func(p string, e os.DirEntry, err error) error {
				if err != nil || e.IsDir() {
					return nil
				}
				if info, err := e.Info(); err != nil || info.Size() > 2<<20 {
					return nil
				}
				b, err := c.Sys.ReadFile(p)
				if err != nil {
					return nil
				}
				for _, m := range cc.re.FindAllSubmatch(b, -1) {
					add(strings.Trim(string(m[1]), `"'`), path.Base(dir))
				}
				return nil
			})
		}
	}
	if ents, err := c.Sys.ReadDir("/etc/letsencrypt/live"); err == nil {
		for _, e := range ents {
			if e.IsDir() {
				add("/etc/letsencrypt/live/"+e.Name()+"/cert.pem", "letsencrypt")
			}
		}
	} else if os.IsPermission(err) {
		unreadable = append(unreadable, "/etc/letsencrypt/live")
	}
	keys := make([]string, 0, len(paths))
	for p := range paths {
		keys = append(keys, p)
	}
	sort.Strings(keys)
	seen := map[string]int{} // certificate -> index in certs
	for _, p := range keys {
		files := []string{p}
		if st, err := c.Sys.Stat(p); err == nil && st.IsDir() { // haproxy crt <dir>
			files = nil
			ents, _ := c.Sys.ReadDir(p)
			for _, e := range ents {
				if !e.IsDir() {
					files = append(files, strings.TrimSuffix(p, "/")+"/"+e.Name())
				}
			}
		}
		for _, f := range files {
			b, err := c.Sys.ReadFile(f)
			if err != nil {
				if os.IsPermission(err) {
					unreadable = append(unreadable, f)
				}
				continue
			}
			cert := firstCert(b)
			if cert == nil {
				continue
			}
			key := cert.SerialNumber.String() + cert.Issuer.String()
			if i, ok := seen[key]; ok {
				// the same certificate again: a web or mail server is the better "used by"
				if certs[i].UsedBy == "letsencrypt" && paths[p] != "letsencrypt" {
					certs[i].UsedBy, certs[i].Path = paths[p], f
				}
				continue
			}
			seen[key] = len(certs)
			cf := CertFile{Path: f, Subject: cert.Subject.CommonName, Names: cert.DNSNames, NotAfter: cert.NotAfter, UsedBy: paths[p]}
			if cf.Subject == "" && len(cert.DNSNames) > 0 {
				cf.Subject = cert.DNSNames[0]
			}
			certs = append(certs, cf)
		}
	}
	sort.Slice(certs, func(i, j int) bool { return certs[i].NotAfter.Before(certs[j].NotAfter) })
	return certs, unreadable
}

func firstCert(b []byte) *x509.Certificate {
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return nil
		}
		if blk.Type == "CERTIFICATE" {
			if c, err := x509.ParseCertificate(blk.Bytes); err == nil {
				return c
			}
		}
	}
}

func runCerts(c *core.Ctx, o *core.Out) {
	certs, unreadable := FindCerts(c)
	if len(unreadable) > 0 {
		o.Limit("certificate files readable only by root")
	}
	if len(certs) == 0 {
		o.Skip("no certificates found in nginx, Apache, HAProxy, Postfix, Dovecot or Let's Encrypt")
		return
	}
	now := c.Sys.Now()
	for _, ce := range certs {
		left := ce.NotAfter.Sub(now)
		days := int(left.Hours() / 24)
		var sev core.Severity
		var title string
		switch {
		case left <= 0:
			sev, title = core.Crit, fmt.Sprintf("the certificate for %s expired %s", ce.Subject, core.Ago(now, ce.NotAfter))
		case left < 7*24*time.Hour:
			sev, title = core.Crit, fmt.Sprintf("the certificate for %s expires in %s", ce.Subject, core.Duration(left))
		case left < 21*24*time.Hour:
			sev, title = core.Warn, fmt.Sprintf("the certificate for %s expires in %d days", ce.Subject, days)
		default:
			continue
		}
		f := core.Finding{ID: "expiring", Severity: sev, Title: title,
			Why:  []string{"file: " + ce.Path + " (used by " + ce.UsedBy + ")", "valid until " + ce.NotAfter.UTC().Format("2006-01-02 15:04 UTC")},
			Data: map[string]interface{}{"path": ce.Path, "subject": ce.Subject, "not_after": ce.NotAfter, "days_left": days}}
		if strings.HasPrefix(ce.Path, "/etc/letsencrypt/") {
			f.Why = append(f.Why, "certbot renews 30 days before the end, so the automatic renewal is failing")
			f.Fix = []string{c.Sudo() + "certbot renew --dry-run   # shows why it fails",
				"systemctl list-timers '*certbot*'   # is the renewal timer on?"}
		} else {
			f.Fix = []string{"# renew it with your certificate provider and replace " + ce.Path + ", then reload " + ce.UsedBy}
		}
		o.Add(f)
	}
	if len(certs) == 1 {
		o.OK("1 certificate, it ends in %d days", int(certs[0].NotAfter.Sub(now).Hours()/24))
	} else {
		o.OK("%d certificates, the next one ends in %d days", len(certs), int(certs[0].NotAfter.Sub(now).Hours()/24))
	}
}

func runProcs(c *core.Ctx, o *core.Out) {
	procs := c.Procs()
	zombies := map[int][]int{}
	nz := 0
	for _, p := range procs {
		if p.State == 'Z' {
			zombies[p.PPID] = append(zombies[p.PPID], p.PID)
			nz++
		}
	}
	if nz >= 5 {
		parents := make([]int, 0, len(zombies))
		for pp := range zombies {
			parents = append(parents, pp)
		}
		sort.Slice(parents, func(i, j int) bool { return len(zombies[parents[i]]) > len(zombies[parents[j]]) })
		f := core.Finding{ID: "zombies", Severity: core.Warn,
			Title: fmt.Sprintf("%d zombie processes", nz),
			Why:   []string{"a zombie is a finished process whose parent did not collect it; they use a process number each"}}
		for i, pp := range parents {
			if i == 2 {
				break
			}
			f.Why = append(f.Why, fmt.Sprintf("%s left %d", c.Owner(pp), len(zombies[pp])))
			if unit, _ := c.UnitOf(pp); unit != "" {
				f.Fix = append(f.Fix, c.Sudo()+"systemctl restart "+unit+"   # restarting the parent clears them")
			} else {
				f.Fix = append(f.Fix, "# restart "+c.ProcName(pp)+" (pid "+strconv.Itoa(pp)+"); restarting the parent clears them")
			}
		}
		o.Add(f)
	}
	s := c.Sample()
	if len(s.DState) >= 5 {
		f := core.Finding{ID: "d-state", Severity: core.Warn,
			Title: fmt.Sprintf("%d processes are stuck waiting for I/O (D state)", len(s.DState)),
			Fix:   []string{"nabd why slow"}}
		waits := map[string]int{}
		for _, pid := range s.DState {
			if b, err := c.Sys.ReadFile("/proc/" + strconv.Itoa(pid) + "/wchan"); err == nil {
				waits[strings.TrimSpace(string(b))]++
			}
		}
		var wl []string
		nfs := false
		for w, n := range waits {
			wl = append(wl, fmt.Sprintf("%s ×%d", w, n))
			if strings.Contains(w, "nfs") || strings.Contains(w, "rpc") {
				nfs = true
			}
		}
		sort.Strings(wl)
		if len(wl) > 0 {
			f.Why = append(f.Why, "waiting in: "+strings.Join(wl, ", "))
		}
		if nfs {
			f.Why = append(f.Why, "they wait for NFS: the NFS server or the network to it may be down")
		}
		o.Add(f)
	}
	// open files per process
	type near struct {
		pid       int
		used, max uint64
	}
	var nears []near
	denied := false
	for _, p := range procs {
		dir := "/proc/" + strconv.Itoa(p.PID)
		ents, err := c.Sys.ReadDir(dir + "/fd")
		if err != nil {
			if os.IsPermission(err) {
				denied = true
			}
			continue
		}
		if len(ents) < 800 {
			continue
		}
		lb, err := c.Sys.ReadFile(dir + "/limits")
		if err != nil {
			continue
		}
		max := linux.MaxOpenFiles(lb)
		if max > 0 && float64(len(ents)) >= 0.8*float64(max) {
			nears = append(nears, near{p.PID, uint64(len(ents)), max})
		}
	}
	if denied {
		o.Limit("open files of other users' processes")
	}
	for _, n := range nears {
		sev := core.Warn
		if float64(n.used) >= 0.95*float64(n.max) {
			sev = core.Crit
		}
		f := core.Finding{ID: "fd-limit", Severity: sev,
			Title: fmt.Sprintf("%s uses %d of its %d open files", c.Owner(n.pid), n.used, n.max),
			Why:   []string{"at the limit it gets \"Too many open files\" and new connections fail"}}
		if unit, _ := c.UnitOf(n.pid); unit != "" {
			f.Fix = []string{c.Sudo() + "systemctl edit " + unit + "   # add: [Service] LimitNOFILE=65536", c.Sudo() + "systemctl restart " + unit}
		}
		f.Fix = append(f.Fix, "ls -l /proc/"+strconv.Itoa(n.pid)+"/fd | awk '{print $NF}' | sort | uniq -c | sort -n | tail   # a leak?")
		o.Add(f)
	}
	// system-wide limits
	if b, err := c.Sys.ReadFile("/proc/sys/fs/file-nr"); err == nil {
		if f := strings.Fields(string(b)); len(f) == 3 {
			used, _ := strconv.ParseFloat(f[0], 64)
			max, _ := strconv.ParseFloat(f[2], 64)
			if max > 0 && used/max >= 0.8 {
				o.Add(core.Finding{ID: "file-max", Severity: core.Warn,
					Title: fmt.Sprintf("the system uses %.0f%% of all open files (%s of %s)", 100*used/max, f[0], f[2]),
					Fix:   []string{c.Sudo() + "sysctl -w fs.file-max=" + strconv.Itoa(int(max*2))}})
			}
		}
	}
	if b, err := c.Sys.ReadFile("/proc/sys/kernel/pid_max"); err == nil {
		max, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		threads := 0
		for _, p := range procs {
			threads += p.Threads
		}
		if max > 0 && float64(threads)/float64(max) >= 0.8 {
			o.Add(core.Finding{ID: "pid-max", Severity: core.Crit,
				Title: fmt.Sprintf("%d of %d process ids are used", threads, max),
				Why:   []string{"when they run out, nothing new can start (not even a shell)"},
				Fix:   []string{"nabd why slow   # which program makes so many threads"}})
		}
	}
	o.OK("%d processes, %d zombies", len(procs), nz)
}

func runAccounts(c *core.Ctx, o *core.Out) {
	b, err := c.Sys.ReadFile("/etc/passwd")
	if err != nil {
		o.Skip("no /etc/passwd")
		return
	}
	shells := map[string]bool{}
	users := 0
	for _, l := range linux.Lines(b) {
		f := strings.Split(l, ":")
		if len(f) < 7 || strings.HasPrefix(l, "#") {
			continue
		}
		users++
		if f[2] == "0" && f[0] != "root" {
			o.Add(core.Finding{ID: "uid0", Severity: core.Crit,
				Title: fmt.Sprintf("the account %q has UID 0: it is a second root", f[0]),
				Why:   []string{"attackers often add such an account as a back door; admins rarely need one"},
				Fix:   []string{"# if you did not make it: " + c.Sudo() + "userdel " + f[0] + "   (check its files and logins first)"}})
		}
		sh := f[6]
		if !strings.HasSuffix(sh, "nologin") && !strings.HasSuffix(sh, "false") && sh != "" && sh != "/bin/sync" {
			shells[f[0]] = true
		}
	}
	sb, err := c.Sys.ReadFile("/etc/shadow")
	if err != nil {
		if os.IsPermission(err) {
			o.Limit("passwords in /etc/shadow")
		}
	} else {
		for _, l := range linux.Lines(sb) {
			f := strings.Split(l, ":")
			if len(f) < 2 {
				continue
			}
			if f[1] == "" && shells[f[0]] {
				o.Add(core.Finding{ID: "no-password", Severity: core.Crit,
					Title: fmt.Sprintf("the account %q has no password", f[0]),
					Why:   []string{"anyone can log in as this user where password login is allowed (console, su, sometimes SSH)"},
					Fix:   []string{c.Sudo() + "passwd " + f[0] + "   # or lock it: " + c.Sudo() + "passwd -l " + f[0]}})
			}
		}
	}
	o.OK("%s, %d can log in", core.Plural(users, "account", "accounts"), len(shells))
}
