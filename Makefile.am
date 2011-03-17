# Written by Simon Josefsson <simon@yubico.com>.
# Copyright (c) 2006, 2007, 2008, 2009, 2010 Yubico AB
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

libdir = $(PAMDIR)

lib_LTLIBRARIES = pam_yubico.la

pam_yubico_la_SOURCES = pam_yubico.c util.c
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_yubico_la_LIBADD = @LTLIBYKCLIENT@ @LIBLDAP@ @YKPERS_LIBS@
pam_yubico_la_LDFLAGS = -module -avoid-version
pam_yubico_la_CPPFLAGS = @YKPERS_CFLAGS@

DEFS = -DDEBUG_PAM -DPAM_DEBUG @DEFS@

# The command line tools.

bin_PROGRAMS = ykpamcfg

ykpamcfg_SOURCES = ykpamcfg.c util.c
ykpamcfg_LDADD = @LTLIBYKCLIENT@ @YKPERS_LIBS@
ykpamcfg_CPPFLAGS = @YKPERS_CFLAGS@

dist_man1_MANS = ykpamcfg.1


# Self tests.

AM_LDFLAGS = -no-install
LDADD = ./pam_yubico.la -lpam

check_PROGRAMS = test
TESTS = $(check_PROGRAMS)

# Dist docs from wiki.
EXTRA_DIST = doc/ReadMe.asciidoc doc/TwoFactorPAMConfiguration.asciidoc doc/UbuntuFreeRadiusYubiKey.asciidoc doc/YubiKeyAndFreeRADIUSviaPAM.asciidoc doc/YubiKeyAndFreeRADIUSwithsinglefactorauthenticationviaPAM.asciidoc doc/YubiKeyAndOpenVPNviaPAM.asciidoc doc/YubikeyAndRadiusViaPAM.asciidoc doc/YubikeyAndSSHViaPAM.asciidoc

# Release

ChangeLog:
	cd $(srcdir) && git2cl > ChangeLog

check-doc-dist:
	cd $(srcdir) && git submodule update
	cd $(srcdir)/doc && git pull
	perl -pe "s,^EXTRA_DIST = .*,EXTRA_DIST = `cd $(srcdir) && ls doc/*.asciidoc | grep -v Todo.ascii | xargs echo`," \
		< $(srcdir)/Makefile.am > check-doc-dist.tmp
	diff -ur $(srcdir)/Makefile.am check-doc-dist.tmp || \
		(rm -f check-doc-dist.tmp; echo 'error: please update $(srcdir)/Makefile.am to include all docs'; exit 1)
	rm -f check-doc-dist.tmp
	diff -ur $(srcdir)/README $(srcdir)/doc/ReadMe.asciidoc || \
		(echo 'error: README and doc/ReadMe.asciidoc does not match!'; exit 1)

PROJECT = yubico-pam
GOOGLEACCOUNT ?= $(PACKAGE_BUGREPORT)
KEYID ?= B9156397

release:
	rm -f ChangeLog
	make check-doc-dist ChangeLog distcheck
	gpg --detach-sign --default-key $(KEYID) $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	cd $(srcdir) && git push
	cd $(srcdir) && git tag -u $(KEYID)! -m $(VERSION) v$(VERSION)
	cd $(srcdir) && git push --tags
	mkdir -p ../releases/$(PACKAGE)/ && \
		cp -v $(PACKAGE)-$(VERSION).tar.gz* ../releases/$(PACKAGE)/
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u $(GOOGLEACCOUNT) $(PACKAGE)-$(VERSION).tar.gz.sig
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u $(GOOGLEACCOUNT) $(PACKAGE)-$(VERSION).tar.gz 
