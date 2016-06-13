#!/bin/sh

set -x

autoreconf -i

if [ "x$TRAVIS_OS_NAME" != "xosx" ]; then
    sudo add-apt-repository -y ppa:yubico/stable
    sudo apt-get update -qq || true
    sudo apt-get install -qq -y --no-install-recommends libykclient-dev libpam0g-dev libyubikey-dev asciidoc docbook-xsl xsltproc libxml2-utils $EXTRA
else
    brew update
    brew install pkg-config
    brew install libtool
    brew install asciidoc
    brew install libyubikey
    brew install ykclient
    brew install ykpers
    cpanp install Net::LDAP::Server
fi

set -e

./configure $CONFIGURE_ARGS $COVERAGE
make check
if [ "x$COVERAGE" != "x" ]; then
    gem install coveralls-lcov
    coveralls-lcov coverage/app2.info
fi
