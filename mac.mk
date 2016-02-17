# Copyright (c) 2016 Yubico AB
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

YKPERS_VERSION=1.17.3
YKCLIENT_VERSION=2.15
CFLAGS="-mmacosx-version-min=10.6 -arch i386 -arch x86_64"
CHECK=check
ROOT_DIR="com.yubico.pam_yubico"
LICENSE_DIR="$(ROOT_DIR)/share/pam_yubico/licenses"
INSTALLER_IDENTITY:="Developer ID Installer"
ifeq ($(SIGN), sign)
SIGNING=--sign $(INSTALLER_IDENTITY) --timestamp
endif

all: usage doit

.PHONY: usage
usage:
	@if test -z "$(VERSION)"; then \
		echo "Must supply VERSION"; \
		exit 1; \
	fi

doit:
	DIR=`mktemp -d $(PWD)/pkg.XXXXXX` && \
	cd $$DIR && \
	cp ../ykpers-$(YKPERS_VERSION)-mac.zip . || \
		curl -L -O "https://developers.yubico.com/yubikey-personalization/Releases/ykpers-$(YKPERS_VERSION)-mac.zip" && \
	mkdir -p $(LICENSE_DIR) && \
	mkdir lib && cd lib && \
	unzip ../ykpers-$(YKPERS_VERSION)-mac.zip && \
	rm -rf lib/*.la && \
	cd .. && \
	cp ../ykclient-$(YKCLIENT_VERSION).tar.gz || \
		curl -L -O "https://developers.yubico.com/yubico-c-client/Releases/ykclient-$(YKCLIENT_VERSION).tar.gz" && \
	tar xfz ykclient-$(YKCLIENT_VERSION).tar.gz && \
	cd ykclient-$(YKCLIENT_VERSION) && \
	CFLAGS=$(CFLAGS) PKG_CONFIG_PATH=$$DIR/lib/lib/pkgconfig ./configure --prefix=$$DIR/lib/ && \
	make $(CHECK) install && \
	cp COPYING $$DIR/$(LICENSE_DIR)/yubico-c-client.txt && \
	cd .. && \
	mkdir -p $$DIR/$(ROOT_DIR)/lib && \
	LIBS="libjson-c.2.dylib libykclient.3.dylib libykpers-1.1.dylib libyubikey.0.dylib" && \
	for lib in $$LIBS; do \
		install_name_tool -id @loader_path/../$$lib $$DIR/lib/lib/$$lib && \
		install_name_tool -change @executable_path/../lib/libyubikey.0.dylib @loader_path/libyubikey.0.dylib $$DIR/lib/lib/$$lib && \
		install_name_tool -change @executable_path/../lib/libjson-c.2.dylib @loader_path/libjson-c.2.dylib $$DIR/lib/lib/$$lib && \
		cp $$DIR/lib/lib/$$lib $$DIR/$(ROOT_DIR)/lib/ ; \
	done && \
	cp ../pam_yubico-$(VERSION).tar.gz . || \
		curl -L -O "https://developers.yubico.com/yubico-pam/Releases/pam_yubico-$(VERSION).tar.gz" && \
	tar xfz pam_yubico-$(VERSION).tar.gz && \
	cd pam_yubico-$(VERSION)/ && \
	YKPERS_CFLAGS=-I$$DIR/lib/include/ykpers-1 YKPERS_LIBS="-L$$DIR/lib/lib/ -lykpers-1" CFLAGS=$(CFLAGS) PKG_CONFIG_PATH=$$DIR/lib/lib/pkgconfig ./configure --prefix=$$DIR/$(ROOT_DIR)/ --with-libyubikey-prefix=$$DIR/lib/ --with-libykclient-prefix=$$DIR/lib/ && \
	make install && \
	install_name_tool -change @executable_path/../lib/libyubikey.0.dylib @loader_path/../libyubikey.0.dylib $$DIR/$(ROOT_DIR)/lib/security/pam_yubico.so && \
	install_name_tool -change @executable_path/../lib/libykpers-1.1.dylib @loader_path/../libykpers-1.1.dylib $$DIR/$(ROOT_DIR)/lib/security/pam_yubico.so && \
	cp COPYING $$DIR/$(LICENSE_DIR)/yubico-pam.txt && \
	cd ../.. && \
	rm $$DIR/$(ROOT_DIR)/lib/security/*.la && \
	cp $$DIR/lib/licenses/* $$DIR/$(LICENSE_DIR) && \
	productbuild --root $$DIR/$(ROOT_DIR)/ /usr/local/ --version $(VERSION) pam_yubico-$(VERSION).pkg $(SIGNING) && \
	rm -rf $$DIR
