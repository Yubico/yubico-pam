# Written by Simon Josefsson <simon@yubico.com>.
# Copyright (c) 2006-2014 Yubico AB
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#
#     * Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_yubico.la

pam_yubico_la_SOURCES = pam_yubico.c util.h util.c drop_privs.h drop_privs.c
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_yubico_la_LIBADD = @LTLIBYKCLIENT@ @LIBLDAP@ @YKPERS_LIBS@ @LTLIBYUBIKEY@ -lpam
pam_yubico_la_LDFLAGS = -module -avoid-version
pam_yubico_la_CPPFLAGS = @YKPERS_CFLAGS@

DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

# The command line tools.

if YKPERS
bin_PROGRAMS = ykpamcfg
endif

ykpamcfg_SOURCES = ykpamcfg.c util.c
ykpamcfg_LDADD = @LTLIBYKCLIENT@ @YKPERS_LIBS@ @LTLIBYUBIKEY@
ykpamcfg_CPPFLAGS = @YKPERS_CFLAGS@

if YKPERS
dist_man1_MANS = ykpamcfg.1
endif

dist_man8_MANS = pam_yubico.8
DISTCLEANFILES = $(dist_man1_MANS) $(dist_man8_MANS)

# Self tests.

AM_LDFLAGS = -no-install
LDADD = ./pam_yubico.la

check_PROGRAMS = test
TESTS = $(check_PROGRAMS)

MANSOURCES = pam_yubico.8.txt ykpamcfg.1.txt
EXTRA_DIST = doc/LocalAuthenticationUsingChallengeResponse.txt doc/MacOSXChallengeResponse.txt doc/TwoFactorPAMConfiguration.txt doc/UbuntuFreeRadiusYubiKey.txt doc/YubiKeyAndFreeRADIUSviaPAM.txt doc/YubiKeyAndFreeRADIUSwithsinglefactorauthenticationviaPAM.txt doc/YubiKeyAndOpenVPNviaPAM.txt doc/YubikeyAndRadiusViaPAM.txt doc/Yubikey-and-SELinux-on-Fedora-18-and-up.txt doc/YubikeyAndSSHViaPAM.txt
EXTRA_DIST += $(MANSOURCES)

SUFFIXES = .1.txt .1 .8.txt .8
.1.txt.1:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<

.8.txt.8:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<

# Release

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

check-doc-dist:
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `cd $(srcdir) && ls doc/*.txt | xargs echo`," < $(srcdir)/Makefile.am > check-doc-dist.tmp
	diff -ur $(srcdir)/Makefile.am check-doc-dist.tmp || \
		(rm -f check-doc-dist.tmp; echo 'error: please update $(srcdir)/Makefile.am to include all docs'; exit 1)
	rm -f check-doc-dist.tmp

PROJECT = yubico-pam

release:
	@if test -z "$(KEYID)"; then \
		echo "Try this instead:"; \
		echo "  make release KEYID=[PGPKEYID]"; \
		echo "For example:"; \
		echo "  make release KEYID=2117364A"; \
		exit 1; \
	fi
	@head -3 $(srcdir)/NEWS | grep -q "Version $(VERSION) .released `date -I`" || \
		(echo 'error: Update date/version in $(srcdir)/NEWS.'; exit 1)
	@if test ! -d "$(YUBICO_GITHUB_REPO)"; then \
		echo "yubico.github.com repo not found!"; \
		echo "Make sure that YUBICO_GITHUB_REPO is set"; \
		exit 1; \
		fi
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) $(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_GITHUB_REPO)/save-mans $(PROJECT) $(MANSOURCES)
	$(YUBICO_GITHUB_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
