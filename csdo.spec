%{!?_version: %define _version 0}
%{!?_release: %define _release 0}
%{!?_reversion: %define _reversion "000000"}

Name:           csdo
Version:        %{_version}
Release:        %{_release}.%{_reversion}%{?dist}
License:        GPLv2 and GPLv2+ and LGPLv2+
Group:          iodepth
Summary:        An command performer
Source:	csdo-%{version}.tar.gz

# Patch0: 0001-foo.patch

%if 0%{?rhel}
ExclusiveArch: i686 x86_64 s390x ppc64le aarch64
%endif

%description
csdo is a command performer client.
csdod is a command performer server.

%prep
%setup -c -q -n csdo-%{version}

# %patch0 -p1 -b .0001-foo.patch

%build
CFLAGS=$RPM_OPT_FLAGS make all

%install
install -Dm 0644 csdod.service %{buildroot}%{_unitdir}/csdod.service
# install -Dm 0644 xxx.conf %{buildroot}/etc/xxx.conf
install -Dm 0644 csdo %{buildroot}/usr/bin/csdo
install -Dm 0644 csdod %{buildroot}/usr/sbin/csdod

%post
%systemd_post csdod.service

%preun
%systemd_preun csdod.service

%postun
%systemd_postun_with_restart csdod.service
# $1为0是卸载，1为更新
if [ "$1" = "0" ] ; then
rm -f /usr/bin/csdo
rm -f /usr/sbin/csdod
fi

%files
%defattr(0755,root,root,-)
/usr/bin/csdo
%attr(4750, root, wheel) /usr/sbin/csdod
%{_unitdir}/csdod.service

%changelog
