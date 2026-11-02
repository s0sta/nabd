# Fedora Copr, build method "make_srpm": Copr runs `make -f .copr/Makefile srpm outdir=DIR`.
# It downloads the release source named in the spec and makes the source RPM.
SPEC   := packaging/rpm/nabd.spec
outdir ?= $(CURDIR)/out

srpm:
	dnf -y install rpm-build rpmdevtools go-rpm-macros
	mkdir -p $(outdir)
	spectool -g -C $(outdir) $(SPEC)
	rpmbuild -bs --define "_sourcedir $(outdir)" --define "_srcrpmdir $(outdir)" $(SPEC)
