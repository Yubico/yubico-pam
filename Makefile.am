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

SUBDIRS = . tests

ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = $(WARN_CFLAGS)
AM_CPPFLAGS = @YKPERS_CFLAGS@

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_yubico.la

pam_yubico_la_SOURCES = drop_privs.h drop_privs.c
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_yubico_la_LIBADD = @LTLIBYUBIKEY@ @LTLIBYKCLIENT@ @LIBLDAP@ @LIBPAM@
pam_yubico_la_LIBADD += libpam_util.la libpam_real.la
pam_yubico_la_LDFLAGS = -module -avoid-version

noinst_LTLIBRARIES = libpam_util.la libpam_real.la
libpam_util_la_SOURCES = util.c util.h
libpam_util_la_LIBADD = @LTLIBYUBIKEY@ @YKPERS_LIBS@

libpam_real_la_SOURCES = pam_yubico.c

DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

# The command line tools.

if YKPERS
bin_PROGRAMS = ykpamcfg
endif

ykpamcfg_SOURCES = ykpamcfg.c
ykpamcfg_LDADD = libpam_util.la

if YKPERS
dist_man1_MANS = ykpamcfg.1
endif

dist_man8_MANS = pam_yubico.8
DISTCLEANFILES = $(dist_man1_MANS) $(dist_man8_MANS)

MANSOURCES = pam_yubico.8.txt ykpamcfg.1.txt
EXTRA_DIST = doc/Authentication_Using_Challenge-Response.adoc doc/MacOS_X_Challenge-Response.adoc doc/Two_Factor_PAM_Configuration.adoc doc/Ubuntu_FreeRadius_YubiKey.adoc doc/YubiKey_and_FreeRADIUS_1FA_via_PAM.adoc doc/YubiKey_and_FreeRADIUS_via_PAM.adoc doc/YubiKey_and_OpenVPN_via_PAM.adoc doc/Yubikey_and_Radius_via_PAM.adoc doc/Yubikey_and_SELinux_on_Fedora_18_and_up.adoc doc/Yubikey_and_SSH_via_PAM.adoc
EXTRA_DIST += $(MANSOURCES)
EXTRA_DIST += tests/aux/ykval.pl tests/aux/ldap.pl tests/aux/authfile

SUFFIXES = .1.txt .1 .8.txt .8
.1.txt.1:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<

.8.txt.8:
	$(A2X) --format=manpage -a revdate="Version $(VERSION)" $<


if ENABLE_COV
AM_CFLAGS += --coverage
AM_LDFLAGS = --coverage

cov-reset:
	rm -fr coverage
	find . -name "*.gcda" -exec rm {} \;
	lcov --directory . --zerocounters

cov-report:
	mkdir -p coverage
	lcov --compat-libtool --directory . --capture --output-file coverage/app.info
	lcov --extract coverage/app.info '*.c' --output-file coverage/app2.info
	genhtml -o coverage/ coverage/app2.info

cov:
	make cov-report

clean-local:
	make cov-reset

check:
	make cov
endif

if ENABLE_CPPCHECK
cppcheck:
	$(CPPCHECK) -q -v -f --enable=all .
endif

# Release

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

check-doc-dist:
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `cd $(srcdir) && ls doc/*.adoc | xargs echo`," < $(srcdir)/Makefile.am > check-doc-dist.tmp
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
	@if test ! -d "$(YUBICO_WWW_REPO)"; then \
		echo "WWW repo not found!"; \
		echo "Make sure that YUBICO_WWW_REPO is set"; \
		exit 1; \
		fi
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID) -m $(VERSION) $(VERSION)
	cd $(srcdir) && git push --tags
	$(YUBICO_WWW_REPO)/save-mans $(PROJECT) $(MANSOURCES)
	$(YUBICO_WWW_REPO)/publish $(PROJECT) $(VERSION) $(PACKAGE)-$(VERSION).tar.gz*
