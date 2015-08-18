#!/bin/sh

set -e
set -x

autoreconf -i

./configure $CONFIGURE_ARGS $COVERAGE
make check
if [ "x$COVERAGE" != "x" ]; then
    gem install coveralls-lcov
    coveralls-lcov coverage/app2.info
fi
