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
| [packaging/rpm](packaging/rpm) | Fedora, EPEL, Copr | follows the Fedora Go packaging guidelines (`%gometa`, `%gobuild`, `%gocheck`); [.copr/Makefile](.copr/Makefile) makes the source RPM for Copr |
| [packaging/aur](packaging/aur) | Arch Linux (AUR): `nabd` (from source) and `nabd-bin` (release binary) | with `.SRCINFO`; the `aur` workflow publishes both after every release |
| [packaging/alpine](packaging/alpine) | Alpine (aports) | run `abuild checksum` for a new version |
| [.goreleaser.yaml](.goreleaser.yaml) | GitHub releases | .deb, .rpm, .apk and Arch packages and static tarballs for 15 builds (every Linux CPU Go supports) |

Every change in `packaging/` is tested by the [packaging workflow](.github/workflows/packaging.yml): it builds each
package in its own distribution the way the distribution does (dpkg-buildpackage + lintian on Debian 12, Debian
testing and Ubuntu 24.04; the Copr source RPM + rpmbuild + rpmlint on Fedora, Fedora rawhide and Rocky 9 with
EPEL; makepkg + namcap on Arch; abuild on Alpine), installs it and runs nabd.

## Publishing to the AUR

1. Make an account on <https://aur.archlinux.org/register> and add the public part of an SSH key to it
   (`ssh-keygen -t ed25519 -f aur_nabd -N ""` makes `aur_nabd` and `aur_nabd.pub`).
2. In the GitHub repository: Settings → Secrets and variables → Actions → New repository secret:
   name `AUR_SSH_PRIVATE_KEY`, value: the content of `aur_nabd` (the private part).
3. Actions → **aur** → Run workflow. After that it runs by itself after every release.

## Publishing to Fedora Copr

1. Log in on <https://copr.fedorainfracloud.org> with a Fedora account.
2. New project `nabd`; chroots: the Fedora releases, `fedora-rawhide`, `epel-9`, `epel-10`.
3. Packages → New package → SCM: clone URL `https://github.com/s0sta/nabd`, spec file
   `packaging/rpm/nabd.spec`, build SRPM with **make srpm**. Build.
4. Users then install with `sudo dnf copr enable s0sta/nabd && sudo dnf install nabd`.

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
