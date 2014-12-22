%if 0%{?fedora} > 16 || 0%{?rhel} > 6
%global security_parent_dir /%{_libdir}
%else
%global security_parent_dir /%{_lib}
%endif

Name:		pam_yubico
Version:	2.17
Release:	1%{?dist}
Summary:	Yubico Pluggable Authentication Module (PAM)

Group:		System Environment/Base
License:	BSD
URL:		https://developers.yubico.com/yubico-pam/
Source0:	https://github.com/Yubico/yubico-pam/archive/%{version}.tar.gz
Packager:       Ulrich Habel <rhaen@pkgbox.de>

BuildRequires:	pam-devel, ykclient-devel, libyubikey-devel, ykpers-devel, openldap-devel
BuildRequires:  asciidoc, autoconf, automake, libtool

%description
The Yubico PAM module provides an easy way to integrate the Yubikey into
your existing user authentication infrastructure. PAM is used by
GNU/Linux, Solaris and Mac OS X for user authentication, and by other
specialized applications such as NCSA MyProxy.

%prep
%setup -q -n yubico-pam-%{version}

%build
libtoolize --force
aclocal
autoreconf --install
%configure --with-pam-dir=%{security_parent_dir}/security
make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%files
%doc AUTHORS README COPYING doc/*
%{_bindir}/*
%{_mandir}/man1/*
%{_mandir}/man8/*
%{security_parent_dir}/security/pam_yubico.so
%{security_parent_dir}/security/pam_yubico.la

%changelog
* Mon Dec 22 2014 Ulrich Habel <rhaen@pkgbox.de>
- Initial package

