#!/usr/bin/env bash
set -e

echo "Creating build dir.."
mkdir -p build && cd build

set -x

echo "Building.."

cmake ..

function run_tests {
	make distclean && cmake .. ${FLAGS}  && make
	make distclean && cmake .. ${FLAGS} -DCMAKE_BUILD_TYPE=Debug && make
	make distclean && cmake .. ${FLAGS} -DCMAKE_BUILD_TYPE=Release && make
}

export FLAGS=-DCMAKE_CXX_FLAGS=-Werror

run_tests

export CXX=clang++
export CC=clang

run_tests

export FLAGS="-DCMAKE_CXX_FLAGS=-Werror -DWITH_DASH=1"

run_tests
