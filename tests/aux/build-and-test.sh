#!/bin/sh

set -e
set -x

autoreconf -i

./configure $CONFIGURE_ARGS $COVERAGE
make check
if [ "x$COVERAGE" != "x" ]; then
    gem install coveralls-lcov
    set +x
    coveralls-lcov --repo-token $COVERALLS_TOKEN coverage/app2.info
fi
