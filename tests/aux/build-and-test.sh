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
    brew install docbook-xsl
    brew install libyubikey
    brew install ykclient
    brew install ykpers
    brew install mysql-connector-c #Mysql
    cpanp install Net::LDAP::Server

    # this is required so asciidoc can find the xml catalog
    export XML_CATALOG_FILES=/usr/local/etc/xml/catalog
fi

set -e

if [ ! -z $MYSQL_PORT ]; then
    CFLAGS="-DTEST_MYSQL_PORT='\"${MYSQL_PORT}\"'" ./configure $CONFIGURE_ARGS $COVERAGE
else
    ./configure $CONFIGURE_ARGS $COVERAGE
fi

make check check-doc-dist
if [ "x$COVERAGE" != "x" ]; then
    gem install coveralls-lcov
    coveralls-lcov coverage/app2.info
fi
