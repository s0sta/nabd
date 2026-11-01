# nabd — build, test and install
#
#   make                 build ./nabd (static, no cgo)
#   make test            go vet + tests
#   sudo make install    binary, man page, completions
#   sudo make install-systemd   the snapshot and Prometheus units (not enabled)
#
# Packagers: PREFIX, DESTDIR, VERSION, GOFLAGS and LDFLAGS can be set.

PREFIX         ?= /usr/local
BINDIR         ?= $(PREFIX)/bin
DATADIR        ?= $(PREFIX)/share
MANDIR         ?= $(DATADIR)/man
SYSTEMDUNITDIR ?= $(PREFIX)/lib/systemd/system
BASHCOMPDIR    ?= $(DATADIR)/bash-completion/completions
ZSHCOMPDIR     ?= $(DATADIR)/zsh/site-functions
FISHCOMPDIR    ?= $(DATADIR)/fish/vendor_completions.d

GO      ?= go
VERSION ?= $(shell git describe --tags --dirty 2>/dev/null | sed 's/^v//')
GOFLAGS ?= -trimpath
LDFLAGS ?= -s -w
LDFLAGS += $(if $(VERSION),-X main.version=$(VERSION))

SOURCES := $(shell find cmd internal -name '*.go' -not -name '*_test.go') go.mod

.PHONY: all test check install install-systemd uninstall demo clean

all: nabd

nabd: $(SOURCES)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $@ ./cmd/nabd

test:
	$(GO) vet ./...
	$(GO) test ./...

check: test
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }

install: nabd
	install -Dm 755 nabd $(DESTDIR)$(BINDIR)/nabd
	install -Dm 644 docs/nabd.1 $(DESTDIR)$(MANDIR)/man1/nabd.1
	install -Dm 644 completions/nabd.bash $(DESTDIR)$(BASHCOMPDIR)/nabd
	install -Dm 644 completions/_nabd $(DESTDIR)$(ZSHCOMPDIR)/_nabd
	install -Dm 644 completions/nabd.fish $(DESTDIR)$(FISHCOMPDIR)/nabd.fish

# The units call /usr/bin/nabd: with PREFIX=/usr/local, fix the path after install.
install-systemd:
	install -Dm 644 contrib/systemd/nabd-snapshot.service $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-snapshot.service
	install -Dm 644 contrib/systemd/nabd-snapshot.timer $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-snapshot.timer
	install -Dm 644 contrib/systemd/nabd-prometheus.service $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-prometheus.service
	install -Dm 644 contrib/systemd/nabd-prometheus.timer $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-prometheus.timer
	sed -i 's|/usr/bin/nabd|$(BINDIR)/nabd|' $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-snapshot.service $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-prometheus.service

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/nabd $(DESTDIR)$(MANDIR)/man1/nabd.1 $(DESTDIR)$(BASHCOMPDIR)/nabd \
		$(DESTDIR)$(ZSHCOMPDIR)/_nabd $(DESTDIR)$(FISHCOMPDIR)/nabd.fish \
		$(DESTDIR)$(SYSTEMDUNITDIR)/nabd-snapshot.service $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-snapshot.timer \
		$(DESTDIR)$(SYSTEMDUNITDIR)/nabd-prometheus.service $(DESTDIR)$(SYSTEMDUNITDIR)/nabd-prometheus.timer

# docs/demo.svg: the README picture, made from the demo server of the tests
demo:
	NABD_DEMO=$(CURDIR)/demo.ansi $(GO) test ./cmd/nabd -run '^TestDemo$$' -count=1
	python3 scripts/ansi2svg.py demo.ansi docs/demo.svg nabd
	rm -f demo.ansi

clean:
	rm -f nabd demo.ansi
	rm -rf dist
