// Package linux parses the text files of /proc and /etc. Every parser is a
// plain function on bytes, so it is easy to test with real samples.
package linux

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

// Meminfo parses /proc/meminfo into bytes.
func Meminfo(b []byte) map[string]uint64 {
	m := map[string]uint64{}
	for _, line := range lines(b) {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseUint(f[0], 10, 64)
		if err != nil {
			continue
		}
		if len(f) > 1 && f[1] == "kB" {
			n *= 1024
		}
		m[strings.TrimSpace(k)] = n
	}
	return m
}

// Pressure parses /proc/pressure/{cpu,memory,io}: "some"/"full" -> "avg10"... -> value.
func Pressure(b []byte) map[string]map[string]float64 {
	out := map[string]map[string]float64{}
	for _, line := range lines(b) {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		vals := map[string]float64{}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				continue
			}
			if x, err := strconv.ParseFloat(v, 64); err == nil {
				vals[k] = x
			}
		}
		out[f[0]] = vals
	}
	return out
}

// Loadavg parses /proc/loadavg.
func Loadavg(b []byte) (l1, l5, l15 float64, err error) {
	f := strings.Fields(string(b))
	if len(f) < 3 {
		return 0, 0, 0, errors.New("bad loadavg")
	}
	if l1, err = strconv.ParseFloat(f[0], 64); err != nil {
		return
	}
	if l5, err = strconv.ParseFloat(f[1], 64); err != nil {
		return
	}
	l15, err = strconv.ParseFloat(f[2], 64)
	return
}

// CPUTimes is the "cpu" line of /proc/stat, in clock ticks.
type CPUTimes struct {
	User, Nice, System, Idle, Iowait, IRQ, SoftIRQ, Steal uint64
}

// Total is all ticks.
func (c CPUTimes) Total() uint64 {
	return c.User + c.Nice + c.System + c.Idle + c.Iowait + c.IRQ + c.SoftIRQ + c.Steal
}

// ProcStatCPU parses the first line of /proc/stat.
func ProcStatCPU(b []byte) (CPUTimes, error) {
	for _, line := range lines(b) {
		f := strings.Fields(line)
		if len(f) < 5 || f[0] != "cpu" {
			continue
		}
		v := make([]uint64, 8)
		for i := 0; i < 8 && i+1 < len(f); i++ {
			v[i], _ = strconv.ParseUint(f[i+1], 10, 64)
		}
		return CPUTimes{v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]}, nil
	}
	return CPUTimes{}, errors.New("no cpu line in /proc/stat")
}

// Mount is one line of /proc/self/mountinfo.
type Mount struct {
	Dev       string // major:minor
	Root      string
	Point     string
	Options   string
	FSType    string
	Source    string
	SuperOpts string
}

// ReadOnly is true when the mount or the file system is read-only.
func (m Mount) ReadOnly() bool {
	for _, o := range strings.Split(m.Options, ",") {
		if o == "ro" {
			return true
		}
	}
	return false
}

// Mountinfo parses /proc/self/mountinfo.
func Mountinfo(b []byte) []Mount {
	var out []Mount
	for _, line := range lines(b) {
		f := strings.Fields(line)
		sep := -1
		for i, x := range f {
			if x == "-" {
				sep = i
				break
			}
		}
		if sep < 6 || len(f) < sep+3 {
			continue
		}
		out = append(out, Mount{
			Dev: f[2], Root: unescape(f[3]), Point: unescape(f[4]), Options: f[5],
			FSType: f[sep+1], Source: unescape(f[sep+2]), SuperOpts: strings.Join(f[sep+3:], " "),
		})
	}
	return out
}

// Mounts parses /proc/mounts (fallback when mountinfo is missing).
func Mounts(b []byte) []Mount {
	var out []Mount
	for _, line := range lines(b) {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		out = append(out, Mount{Source: unescape(f[0]), Point: unescape(f[1]), FSType: f[2], Options: f[3], Dev: unescape(f[0])})
	}
	return out
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// Socket is one line of /proc/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto string // tcp, tcp6, udp, udp6
	IP    net.IP
	Port  int
	State string // hex state, 0A = LISTEN for TCP
	UID   int
	Inode uint64
}

// Listening is a TCP socket in LISTEN state or an unconnected UDP socket.
func (s Socket) Listening() bool {
	if strings.HasPrefix(s.Proto, "tcp") {
		return s.State == "0A"
	}
	return s.State == "07"
}

// Wildcard is true when the socket listens on all addresses.
func (s Socket) Wildcard() bool { return s.IP.IsUnspecified() }

// Loopback is true when only this machine can connect.
func (s Socket) Loopback() bool { return s.IP.IsLoopback() }

// Addr is "ip:port" in normal notation.
func (s Socket) Addr() string {
	if s.IP.To4() == nil && !s.IP.IsUnspecified() {
		return "[" + s.IP.String() + "]:" + strconv.Itoa(s.Port)
	}
	ip := s.IP.String()
	if s.IP.IsUnspecified() {
		if strings.HasSuffix(s.Proto, "6") {
			ip = "[::]"
		} else {
			ip = "0.0.0.0"
		}
	}
	return ip + ":" + strconv.Itoa(s.Port)
}

// NetSockets parses a /proc/net/tcp-like file.
func NetSockets(proto string, b []byte) []Socket {
	var out []Socket
	for i, line := range lines(b) {
		if i == 0 {
			continue // header
		}
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		ip, port, err := hexAddr(f[1])
		if err != nil {
			continue
		}
		uid, _ := strconv.Atoi(f[7])
		inode, _ := strconv.ParseUint(f[9], 10, 64)
		out = append(out, Socket{Proto: proto, IP: ip, Port: port, State: f[3], UID: uid, Inode: inode})
	}
	return out
}

func hexAddr(s string) (net.IP, int, error) {
	host, port, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, errors.New("bad address")
	}
	p, err := strconv.ParseUint(port, 16, 16)
	if err != nil {
		return nil, 0, err
	}
	b, err := hex.DecodeString(host)
	if err != nil {
		return nil, 0, err
	}
	switch len(b) {
	case 4:
		return net.IP{b[3], b[2], b[1], b[0]}, int(p), nil
	case 16:
		ip := make(net.IP, 16)
		for w := 0; w < 4; w++ {
			for j := 0; j < 4; j++ {
				ip[w*4+j] = b[w*4+3-j]
			}
		}
		return ip, int(p), nil
	}
	return nil, 0, errors.New("bad address length")
}

// OSRelease parses /etc/os-release.
func OSRelease(b []byte) map[string]string {
	m := map[string]string{}
	for _, line := range lines(b) {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' || v[0] == '\'') && v[len(v)-1] == v[0] {
			v = v[1 : len(v)-1]
		}
		m[k] = v
	}
	return m
}

// ProcStat is the useful part of /proc/<pid>/stat.
type ProcStat struct {
	PID, PPID int
	Comm      string
	State     byte
	UTime     uint64 // clock ticks
	STime     uint64
	Threads   int
	StartTime uint64 // ticks after boot
	RSSPages  int64
}

// ParseProcStat parses /proc/<pid>/stat. The name can hold spaces and ")".
func ParseProcStat(b []byte) (ProcStat, error) {
	s := string(b)
	open := strings.IndexByte(s, '(')
	end := strings.LastIndexByte(s, ')')
	if open < 0 || end < open || end+2 > len(s) {
		return ProcStat{}, errors.New("bad stat")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(s[:open]))
	if err != nil {
		return ProcStat{}, err
	}
	rest := strings.Fields(s[end+2:])
	if len(rest) < 22 {
		return ProcStat{}, errors.New("short stat")
	}
	p := ProcStat{PID: pid, Comm: s[open+1 : end], State: rest[0][0]}
	p.PPID, _ = strconv.Atoi(rest[1])
	p.UTime, _ = strconv.ParseUint(rest[11], 10, 64)
	p.STime, _ = strconv.ParseUint(rest[12], 10, 64)
	p.Threads, _ = strconv.Atoi(rest[17])
	p.StartTime, _ = strconv.ParseUint(rest[19], 10, 64)
	p.RSSPages, _ = strconv.ParseInt(rest[21], 10, 64)
	return p, nil
}

// Status parses /proc/<pid>/status into key -> value.
func Status(b []byte) map[string]string {
	m := map[string]string{}
	for _, line := range lines(b) {
		k, v, ok := strings.Cut(line, ":")
		if ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// CgroupUnit finds the systemd unit or container of a process from /proc/<pid>/cgroup.
// It returns ("nginx.service", "") or ("", "docker 3f2a1b0c9d8e").
func CgroupUnit(b []byte) (unit, container string) {
	for _, line := range lines(b) {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		path := parts[2]
		for _, el := range strings.Split(path, "/") {
			switch {
			case strings.HasPrefix(el, "docker-") && strings.HasSuffix(el, ".scope"):
				container = "docker " + short(strings.TrimSuffix(strings.TrimPrefix(el, "docker-"), ".scope"))
			case strings.HasPrefix(el, "libpod-") && strings.HasSuffix(el, ".scope"):
				container = "podman " + short(strings.TrimSuffix(strings.TrimPrefix(el, "libpod-"), ".scope"))
			case strings.HasSuffix(el, ".service") && !strings.HasPrefix(el, "user@"):
				unit = el
			}
		}
		if i := strings.Index(path, "/docker/"); i >= 0 && container == "" {
			container = "docker " + short(strings.SplitN(path[i+8:], "/", 2)[0])
		}
	}
	if container != "" {
		unit = ""
	}
	return unit, container
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// Limits reads the soft "Max open files" value of /proc/<pid>/limits (0 = unlimited/unknown).
func MaxOpenFiles(b []byte) uint64 {
	for _, line := range lines(b) {
		if strings.HasPrefix(line, "Max open files") {
			f := strings.Fields(strings.TrimPrefix(line, "Max open files"))
			if len(f) > 0 {
				n, _ := strconv.ParseUint(f[0], 10, 64)
				return n
			}
		}
	}
	return 0
}

// KV parses "Key=Value" lines (systemctl show, timedatectl show).
func KV(s string) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok && k != "" {
			m[k] = strings.TrimRight(v, "\r")
		}
	}
	return m
}

// KVBlocks parses several "systemctl show" blocks separated by blank lines.
func KVBlocks(s string) []map[string]string {
	var out []map[string]string
	for _, block := range strings.Split(strings.ReplaceAll(s, "\r", ""), "\n\n") {
		if strings.TrimSpace(block) == "" {
			continue
		}
		out = append(out, KV(block))
	}
	return out
}

func lines(b []byte) []string {
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	return out
}

// Lines splits text into lines (exported helper).
func Lines(b []byte) []string { return lines(b) }
