# Packaging nabd

Thank you for packaging nabd. It was made to be easy for distributions.

## Facts for packagers

| | |
|---|---|
| Language | Go ≥ 1.19, standard library only: **no dependencies, nothing to vendor** |
| cgo | not needed (`CGO_ENABLED=0` gives a static binary; a PIE build with cgo works too) |
| Version | `-ldflags "-X main.version=$VERSION"`; without it the version in `cmd/nabd/main.go` is used |
| Tests | `go test ./...`, about 2 seconds, no root, no network, only temporary folders |
| Reproducible | build with `-trimpath`; nabd embeds no dates or paths |
| Runtime deps | none; nabd uses `systemctl`, `journalctl`, `sshd`, … when they exist |
| Platforms | Linux only; builds for amd64, arm64, armv7, 386, ppc64le, s390x, riscv64, mips64le and loong64 |
| License | MIT (SPDX: `MIT`) |

```sh
CGO_ENABLED=0 go build -trimpath -ldflags "-X main.version=0.1.0" -o nabd ./cmd/nabd
go test ./...
make install PREFIX=/usr DESTDIR="$pkgdir"   # binary, man page, completions
make install-systemd PREFIX=/usr DESTDIR="$pkgdir"   # optional units
```

## Files

| File | Install to |
|---|---|
| `nabd` | `/usr/bin/nabd` |
| `docs/nabd.1` | `/usr/share/man/man1/nabd.1` |
| `completions/nabd.bash` | `/usr/share/bash-completion/completions/nabd` |
| `completions/_nabd` | zsh: `/usr/share/zsh/site-functions/_nabd` (Debian: `/usr/share/zsh/vendor-completions/_nabd`) |
| `completions/nabd.fish` | `/usr/share/fish/vendor_completions.d/nabd.fish` |
| `contrib/systemd/*` | `/usr/lib/systemd/system/` — please ship them **disabled**; the admin turns them on |
| `contrib/nagios/nabd.cfg` | an example for the docs |

Snapshots go to `/var/lib/nabd/snapshots` (mode 0700). The units use `StateDirectory=nabd`, so the folder is made
when needed.

## Ready-made packaging

| Folder | For | Notes |
|---|---|---|
| [packaging/debian](packaging/debian) | Debian, Ubuntu | dh-golang; copy it to `debian/` in the source tree. A Debian maintainer will put their own name in `Maintainer`. |
| [packaging/rpm](packaging/rpm) | Fedora, EPEL, Copr | follows the Fedora Go packaging guidelines (`%gometa`, `%gobuild`, `%gocheck`) |
| [packaging/arch](packaging/arch) | Arch Linux (AUR) | run `updpkgsums` after a release |
| [packaging/alpine](packaging/alpine) | Alpine (aports) | run `abuild checksum` after a release |
| [.goreleaser.yaml](.goreleaser.yaml) | GitHub releases | .deb, .rpm, .apk and Arch packages and static tarballs for 7 architectures |

## The road into distributions

No one can force a distribution to take a package. Distributions take software that is useful, well made and
used by people, and a volunteer must agree to maintain it. This is the plan:

1. **GitHub releases** with packages for every big distribution (done with each release).
2. **AUR**: `nabd` (from source) and `nabd-bin`. Anyone can publish there.
3. **Fedora Copr**: a public repository built from `packaging/rpm/nabd.spec`, so `dnf copr enable s0sta/nabd` works on
   Fedora, RHEL, Rocky and Alma.
4. **Fedora and EPEL**: a package review request in Red Hat Bugzilla; a sponsor reviews the spec. After that, nabd
   can be built for EPEL 9 and 10.
5. **Debian**: an ITP (Intent To Package) bug, the package on mentors.debian.net, and a Debian Developer who sponsors
   the upload. Once nabd is in Debian, Ubuntu takes it automatically in its next release.
6. **Alpine**: a merge request to `aports` (first in `testing`).
7. **openSUSE** (Open Build Service), **nixpkgs**, **Gentoo GURU**: pull requests.

Every step goes faster when there are real users. If nabd helps you, a star, a blog post or a package in your
favourite distribution helps the most.
