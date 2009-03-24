# Written by Simon Josefsson <simon@yubico.com>.
# Copyright (c) 2006, 2007, 2008, 2009 Yubico AB
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

pam_yubico_la_SOURCES = pam_yubico.c
# XXX add -Wl,-x too?  PAM documentation suggests it.
pam_yubico_la_LIBADD = @LTLIBYUBIKEY_CLIENT@ @LIBLDAP@
pam_yubico_la_LDFLAGS = -module -avoid-version

DEFS = -DDEBUG_PAM @DEFS@

# Self tests.

AM_LDFLAGS = -no-install
LDADD = ./pam_yubico.la -lpam

check_PROGRAMS = test
TESTS = $(check_PROGRAMS)

# Release

ChangeLog:
	svn2cl

PROJECT=yubico-pam

release:
	rm -f ChangeLog
	make ChangeLog distcheck
	gpg -b $(PACKAGE)-$(VERSION).tar.gz
	gpg --verify $(PACKAGE)-$(VERSION).tar.gz.sig
	svn copy https://$(PROJECT).googlecode.com/svn/trunk/ \
	 https://$(PROJECT).googlecode.com/svn/tags/$(PACKAGE)-$(VERSION) \
	 -m "Tagging the $(VERSION) release of the $(PACKAGE) project."
	googlecode_upload.py -s "$(PACKAGE) $(VERSION)" \
	 -p $(PROJECT) -u simon75j $(PACKAGE)-$(VERSION).tar.gz 
	googlecode_upload.py -s "OpenPGP signature for $(PACKAGE) $(VERSION)." \
	 -p $(PROJECT) -u simon75j $(PACKAGE)-$(VERSION).tar.gz.sig
