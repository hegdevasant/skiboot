Name:		opal-prd
Epoch:		3
Version:	ess.v4.1
Release:	1%{?dist}
Summary:	OPAL Processor Recovery Diagnostics Daemon

Group:		System Environment/Daemons
License:	ASL 2.0
URL:		http://github.com/open-power/skiboot
# Presently opal-prd is supported on ppc64le architecture only.
ExclusiveArch:	ppc64le

BuildRequires:	systemd
BuildRequires:	gcc
BuildRequires:	openssl-devel

Requires(post):	systemd
Requires(post):	systemd-udev
Requires(preun): systemd
Requires(postun): systemd

Source0: https://github.com/open-power/%{project}/archive/v%{version}/%{version}.tar.gz

%description
This package provides a daemon to load and run the OpenPower firmware's
Processor Recovery Diagnostics binary. This is responsible for run time
maintenance of OpenPower Systems hardware.


%package -n	opal-utils
Summary:	OPAL firmware utilities
Group:		Applications/System

%description -n opal-utils
This package contains utility programs.

The 'gard' utility, can read, parse and clear hardware gard partitions
on OpenPower platforms. The 'getscom' and 'putscom' utilities provide
an interface to query or modify the registers of the different chipsets
of an OpenPower system. 'pflash' is a tool to access the flash modules
on such systems and update the OpenPower firmware.

%package -n	opal-firmware
Summary:	OPAL firmware
BuildArch:	noarch

%description -n	opal-firmware
OPAL firmware, aka skiboot, loads the bootloader and provides runtime
services to the OS (Linux) on IBM Power and OpenPower systems.

%prep
%setup -q -n skiboot-%{version}

%build
OPAL_PRD_VERSION=%{version} make V=1 CC="gcc" CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags}" ASFLAGS="-m64 -Wa,--generate-missing-build-notes=yes" -C external/opal-prd
GARD_VERSION=%{version} make V=1 CC="gcc" CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags}" -C external/gard
PFLASH_VERSION=%{version} make V=1 CC="gcc" CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags}" -C external/pflash
XSCOM_VERSION=%{version} make V=1 CC="gcc" CFLAGS="%{build_cflags}" LDFLAGS="%{build_ldflags}" -C external/xscom-utils

SKIBOOT_VERSION=%{version} make V=1 CROSS=

%install
make -C external/opal-prd install DESTDIR=%{buildroot} prefix=/usr
make -C external/gard install DESTDIR=%{buildroot} prefix=/usr
make -C external/pflash install DESTDIR=%{buildroot} prefix=/usr
make -C external/xscom-utils install DESTDIR=%{buildroot} prefix=/usr

mkdir -p %{buildroot}%{_unitdir}
install -m 644 -p external/opal-prd/opal-prd.service %{buildroot}%{_unitdir}/opal-prd.service

mkdir -p %{buildroot}%{_datadir}/qemu
install -m 644 -p skiboot.lid %{buildroot}%{_datadir}/qemu/skiboot.lid
install -m 644 -p skiboot.lid.xz %{buildroot}%{_datadir}/qemu/skiboot.lid.xz

# log opal-prd messages to /var/log/opal-prd.log
mkdir -p %{buildroot}%{_sysconfdir}/{rsyslog.d,logrotate.d}
install -m 644 external/opal-prd/opal-prd-rsyslog %{buildroot}/%{_sysconfdir}/rsyslog.d/opal-prd.conf
install -m 644 external/opal-prd/opal-prd-logrotate %{buildroot}/%{_sysconfdir}/logrotate.d/opal-prd

# Auto-load kernel module after boot/reboot
mkdir -p %{buildroot}/%{_prefix}/lib/modules-load.d
echo 'opal-prd' > %{buildroot}/%{_prefix}/lib/modules-load.d/%{name}.conf

%post
%systemd_post opal-prd.service

%preun
%systemd_preun opal-prd.service

%postun
%systemd_postun_with_restart opal-prd.service

%files
%doc README.md
%license LICENCE
%config(noreplace) %{_sysconfdir}/logrotate.d/opal-prd
%config(noreplace) %{_sysconfdir}/rsyslog.d/opal-prd.conf
%config(noreplace) %{_prefix}/lib/modules-load.d/%{name}.conf
%{_sbindir}/opal-prd
%{_unitdir}/opal-prd.service
%{_mandir}/man8/*

%files -n opal-utils
%doc README.md
%license LICENCE
%{_sbindir}/opal-gard
%{_sbindir}/getscom
%{_sbindir}/putscom
%{_sbindir}/pflash
%{_sbindir}/getsram
%{_mandir}/man1/*

%files -n opal-firmware
%doc README.md
%license LICENCE
%{_datadir}/qemu/


%changelog
* Thu Mar 11 2021 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - ess.v4.1
- Create conf file to load opal-prd module at boot
- Load opal-prd service after systemd-modules-load service
- Fix `opal-prd` crash due to buffer overflow

* Fri Jan 08 2021 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - ess.v4
- opal-prd: Have a worker process handle page offlining
- Update to ess.v4 version

* Mon May 04 2020 Oliver O'Halloran <oohall@gmail.com> - 3000.0
- Specfile changes for the NVDIMM aware opal-prd.

* Thu Mar 01 2018 Murilo Opsfelder Araujo <muriloo@linux.vnet.ibm.com> - 5.10-1
- Update to v5.10 release

* Tue Feb 09 2016 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - 5.1.13
- Update to latest upstream release

* Mon Nov 23 2015 Vasant Hegde <hegdevasant@linux.vnet.ibm.com> - 5.1.12
- initial upstream spec file
