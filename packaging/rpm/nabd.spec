# Fedora / EPEL / Copr spec for nabd. It follows the Fedora Go packaging guidelines.
%bcond_without check

%global goipath github.com/s0sta/nabd
Version:        0.1.0

%gometa -f

%global common_description %{expand:
nabd checks a Linux machine in about a second: disk space and inodes, memory,
CPU, failed services, kernel log errors, time sync, pending reboots, package
state, network and DNS, open ports, SSH settings, TLS certificates, processes
and accounts. For each problem it explains the cause in plain words and prints
the command that fixes it. nabd only reads: it never changes the system.}

%global golicenses      LICENSE
%global godocs          README.md CHANGELOG.md docs/checks.md docs/output.md

%{!?bash_completions_dir: %global bash_completions_dir %{_datadir}/bash-completion/completions}
%{!?zsh_completions_dir:  %global zsh_completions_dir  %{_datadir}/zsh/site-functions}
%{!?fish_completions_dir: %global fish_completions_dir %{_datadir}/fish/vendor_completions.d}

Name:           nabd
Release:        1%{?dist}
Summary:        Doctor for Linux servers: finds problems and gives the fix

License:        MIT
URL:            %{gourl}
Source:         %{gosource}

BuildRequires:  systemd-rpm-macros

%description %{common_description}

%prep
%goprep

%generate_buildrequires
%go_generate_buildrequires

%build
export LDFLAGS="-X main.version=%{version}"
%gobuild -o %{gobuilddir}/bin/nabd %{goipath}/cmd/nabd

%install
install -m 0755 -vd                     %{buildroot}%{_bindir}
install -m 0755 -vp %{gobuilddir}/bin/* %{buildroot}%{_bindir}/
install -Dpm 0644 docs/nabd.1                           %{buildroot}%{_mandir}/man1/nabd.1
install -Dpm 0644 completions/nabd.bash                 %{buildroot}%{bash_completions_dir}/nabd
install -Dpm 0644 completions/_nabd                     %{buildroot}%{zsh_completions_dir}/_nabd
install -Dpm 0644 completions/nabd.fish                 %{buildroot}%{fish_completions_dir}/nabd.fish
install -Dpm 0644 contrib/systemd/nabd-snapshot.service %{buildroot}%{_unitdir}/nabd-snapshot.service
install -Dpm 0644 contrib/systemd/nabd-snapshot.timer   %{buildroot}%{_unitdir}/nabd-snapshot.timer
install -Dpm 0644 contrib/systemd/nabd-prometheus.service %{buildroot}%{_unitdir}/nabd-prometheus.service
install -Dpm 0644 contrib/systemd/nabd-prometheus.timer   %{buildroot}%{_unitdir}/nabd-prometheus.timer
install -dm 0700 %{buildroot}%{_sharedstatedir}/nabd

%if %{with check}
%check
%gocheck
%endif

%post
%systemd_post nabd-snapshot.timer nabd-prometheus.timer

%preun
%systemd_preun nabd-snapshot.timer nabd-prometheus.timer

%postun
%systemd_postun nabd-snapshot.timer nabd-prometheus.timer

%files
%license LICENSE
%doc README.md CHANGELOG.md docs/checks.md docs/output.md contrib/nagios/nabd.cfg
%{_bindir}/nabd
%{_mandir}/man1/nabd.1*
%{bash_completions_dir}/nabd
%{zsh_completions_dir}/_nabd
%{fish_completions_dir}/nabd.fish
%{_unitdir}/nabd-snapshot.service
%{_unitdir}/nabd-snapshot.timer
%{_unitdir}/nabd-prometheus.service
%{_unitdir}/nabd-prometheus.timer
%dir %attr(0700,root,root) %{_sharedstatedir}/nabd

%changelog
* Mon Nov 02 2026 Hosam Hani <76218642+s0sta@users.noreply.github.com> - 0.1.0-1
- Initial package
