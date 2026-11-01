package linux

import (
	"testing"
)

func TestMeminfo(t *testing.T) {
	m := Meminfo([]byte("MemTotal:        8000000 kB\nMemAvailable:    2000000 kB\nHugePages_Total:       0\n"))
	if m["MemTotal"] != 8000000*1024 || m["MemAvailable"] != 2000000*1024 {
		t.Fatalf("kB must become bytes: %v", m)
	}
	if v, ok := m["HugePages_Total"]; !ok || v != 0 {
		t.Fatalf("a value without unit is kept as is: %v", m)
	}
}

func TestPressure(t *testing.T) {
	p := Pressure([]byte("some avg10=12.50 avg60=3.00 avg300=1.00 total=100\nfull avg10=4.25 avg60=1.00 avg300=0.50 total=50\n"))
	if p["some"]["avg10"] != 12.5 || p["full"]["avg10"] != 4.25 || p["full"]["total"] != 50 {
		t.Fatalf("pressure: %v", p)
	}
}

func TestLoadavg(t *testing.T) {
	l1, l5, l15, err := Loadavg([]byte("1.50 0.75 0.25 2/345 6789\n"))
	if err != nil || l1 != 1.5 || l5 != 0.75 || l15 != 0.25 {
		t.Fatalf("loadavg: %v %v %v %v", l1, l5, l15, err)
	}
	if _, _, _, err := Loadavg([]byte("")); err == nil {
		t.Fatal("an empty file must be an error")
	}
}

func TestMountinfo(t *testing.T) {
	b := []byte(`22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,errors=remount-ro
40 22 252:2 / /mnt/my\040disk ro,nosuid shared:2 - xfs /dev/vdb rw
41 22 0:45 / /run/user/0 rw,nosuid,nodev - tmpfs tmpfs rw,size=1g
`)
	ms := Mountinfo(b)
	if len(ms) != 3 {
		t.Fatalf("want 3 mounts, got %d", len(ms))
	}
	if ms[0].Point != "/" || ms[0].FSType != "ext4" || ms[0].Source != "/dev/vda1" || ms[0].Dev != "252:1" {
		t.Fatalf("first mount: %+v", ms[0])
	}
	if ms[1].Point != "/mnt/my disk" {
		t.Fatalf(`\040 must become a space: %q`, ms[1].Point)
	}
	if !ms[1].ReadOnly() || ms[0].ReadOnly() {
		t.Fatal("read-only flags are wrong")
	}
}

func TestNetSockets(t *testing.T) {
	tcp := []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:18EB 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 41001 1 0000000000000000 100 0 0 10 0
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 41002 1 0000000000000000 100 0 0 10 0
   2: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000     0        0 41003 1 0000000000000000 100 0 0 10 0
`)
	ss := NetSockets("tcp", tcp)
	if len(ss) != 3 {
		t.Fatalf("want 3 sockets, got %d", len(ss))
	}
	redis := ss[0]
	if redis.Port != 6379 || !redis.Wildcard() || !redis.Listening() || redis.UID != 999 || redis.Inode != 41001 {
		t.Fatalf("redis socket: %+v", redis)
	}
	if redis.Addr() != "0.0.0.0:6379" {
		t.Fatalf("addr: %s", redis.Addr())
	}
	if !ss[1].Loopback() || ss[1].Addr() != "127.0.0.1:3306" {
		t.Fatalf("mysql socket: %+v %s", ss[1], ss[1].Addr())
	}
	if ss[2].Listening() {
		t.Fatal("an established connection is not listening")
	}
	tcp6 := []byte(`  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42001 1 0000000000000000 100 0 0 10 0
   1: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 42002 1 0000000000000000 100 0 0 10 0
`)
	s6 := NetSockets("tcp6", tcp6)
	if len(s6) != 2 || s6[0].Addr() != "[::]:22" || !s6[0].Wildcard() {
		t.Fatalf("tcp6 wildcard: %+v", s6)
	}
	if !s6[1].Loopback() || s6[1].Addr() != "[::1]:8080" {
		t.Fatalf("tcp6 loopback: %+v %s", s6[1], s6[1].Addr())
	}
}

func TestParseProcStat(t *testing.T) {
	// a name with a space and a ")" inside, like "(sd-pam)" or a renamed process
	b := []byte("4242 (my (odd) app) S 1 4242 4242 0 -1 4194560 100 0 0 0 250 50 0 0 20 0 3 0 12345 10000000 512 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0\n")
	p, err := ParseProcStat(b)
	if err != nil {
		t.Fatal(err)
	}
	if p.PID != 4242 || p.Comm != "my (odd) app" || p.State != 'S' || p.PPID != 1 {
		t.Fatalf("stat: %+v", p)
	}
	if p.UTime != 250 || p.STime != 50 || p.Threads != 3 || p.StartTime != 12345 || p.RSSPages != 512 {
		t.Fatalf("stat numbers: %+v", p)
	}
	if _, err := ParseProcStat([]byte("garbage")); err == nil {
		t.Fatal("garbage must be an error")
	}
}

func TestOSRelease(t *testing.T) {
	m := OSRelease([]byte("NAME=\"Rocky Linux\"\nID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"\n# comment\nPRETTY_NAME='Rocky Linux 9.4 (Blue Onyx)'\n"))
	if m["ID"] != "rocky" || m["ID_LIKE"] != "rhel centos fedora" || m["PRETTY_NAME"] != "Rocky Linux 9.4 (Blue Onyx)" {
		t.Fatalf("os-release: %v", m)
	}
}

func TestCgroupUnit(t *testing.T) {
	cases := []struct {
		in, unit, container string
	}{
		{"0::/system.slice/nginx.service\n", "nginx.service", ""},
		{"0::/user.slice/user-1000.slice/user@1000.service/app.slice/foo.service\n", "foo.service", ""},
		{"0::/system.slice/docker-3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a.scope\n", "", "docker 3f2a1b0c9d8e"},
		{"12:pids:/docker/abcdef0123456789abcdef\n", "", "docker abcdef012345"},
		{"0::/machine.slice/libpod-0123456789abcdef.scope/container\n", "", "podman 0123456789ab"},
		{"0::/init.scope\n", "", ""},
	}
	for _, c := range cases {
		u, ct := CgroupUnit([]byte(c.in))
		if u != c.unit || ct != c.container {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.in, u, ct, c.unit, c.container)
		}
	}
}

func TestKVBlocks(t *testing.T) {
	bs := KVBlocks("Id=a.service\nActiveState=failed\n\nId=b.service\nActiveState=active\n")
	if len(bs) != 2 || bs[0]["Id"] != "a.service" || bs[1]["ActiveState"] != "active" {
		t.Fatalf("blocks: %v", bs)
	}
}
