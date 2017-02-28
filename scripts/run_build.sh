#!/usr/bin/env bash
#
# This script is used to run the build on travis-ci
#

set -e

echo "Creating build dir.."
mkdir -p build && cd build

set -x

echo "Building.."

function run_tests {
	echo "Running tests for OS: $TRAVIS_OS_NAME, with CXX: $CXX, CC: $CC, FLAGS: $FLAGS";
	make distclean || true; # Cleanup if file exist, but ignore error if dir is clean
	cmake .. ${FLAGS} -DTESTS=1 && make;
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Debug && make;
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make;
	## Compile without -Werror due to compile warnings in test library
	make distclean && cmake .. -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make;
	make test;
	./test;
}

export FLAGS=-DCMAKE_CXX_FLAGS=-Werror

run_tests

export FLAGS="-DCMAKE_CXX_FLAGS=-Werror -DWITH_DASH=1"

run_tests
