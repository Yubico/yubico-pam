#!/bin/sh

set -e

autoreconf -i

./configure $COVERAGE
make check
if [ "x$COVERAGE" != "x" ]; then
    gem install coveralls-lcov
    coveralls-lcov --repo-token $COVERALLS_TOKEN coverage/app2.info
fi
