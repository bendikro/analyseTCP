#!/usr/bin/env bash
#
# This script is used to run the build on travis-ci
#

set -e

echo "Creating build dir.."
mkdir -p build && cd build

set -x

echo "Building.."

echo "Building CXX: $CXX"
echo "Building CC: $CC"

#-DCMAKE_CXX_COMPILER

function run_tests {
	cmake .. ${FLAGS} -DTESTS=1  && make;
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Debug && make;
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make;
	# Compile without -Werror due to compile warnings in test library
	make distclean && cmake .. -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make;
	make test;
	./test;
}

export FLAGS=-DCMAKE_CXX_FLAGS=-Werror

run_tests

#export CXX=clang++
#export CC=clang
#run_tests
#export FLAGS="-DCMAKE_CXX_FLAGS=-Werror -DWITH_DASH=1"

#run_tests
