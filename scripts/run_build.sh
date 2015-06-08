#!/usr/bin/env bash
set -e
echo "Creating build dir.."
mkdir build && cd build

set -x

echo "Building.."

cmake ..

make distclean && cmake .. -DCMAKE_CXX_FLAGS="-Werror" && make
make distclean && cmake .. -DCMAKE_BUILD_TYPE=Debug  -DCMAKE_CXX_FLAGS="-Werror" && make
make distclean && cmake .. -DCMAKE_BUILD_TYPE=Release  -DCMAKE_CXX_FLAGS="-Werror" && make

export CXX=clang++

make distclean && cmake .. -DCMAKE_CXX_FLAGS="-Werror" && make
make distclean && cmake .. -DCMAKE_BUILD_TYPE=Debug  -DCMAKE_CXX_FLAGS="-Werror" && make
make distclean && cmake .. -DCMAKE_BUILD_TYPE=Release  -DCMAKE_CXX_FLAGS="-Werror" && make
