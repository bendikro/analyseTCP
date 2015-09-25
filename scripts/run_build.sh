#!/usr/bin/env bash
set -e

echo "Creating build dir.."
mkdir -p build && cd build

set -x

echo "Building.."

cmake ..

function run_tests {
	make distclean && cmake .. ${FLAGS} -DTESTS=1  && make
	make test
	./test
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Debug && make
	make test
	./test
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make
	make test
	./test
	make distclean && cmake .. ${FLAGS} -DTESTS=1 -DCMAKE_BUILD_TYPE=Release && make
	make test
	./test
}

export FLAGS=-DCMAKE_CXX_FLAGS=-Werror

run_tests

export CXX=clang++
export CC=clang

run_tests

export FLAGS="-DCMAKE_CXX_FLAGS=-Werror -DWITH_DASH=1"

run_tests
