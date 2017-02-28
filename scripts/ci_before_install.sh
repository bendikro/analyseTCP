#!/usr/bin/env bash
#
# This script is used to run the build on travis-ci
#

set -x

echo "TRAVIS_OS_NAME: $TRAVIS_OS_NAME"

echo "CXX: $CXX"
echo "CC: $CC"

if [[ "$TRAVIS_OS_NAME" == "linux" ]]; then
	#add-apt-repository -y ppa:ubuntu-toolchain-r/test;
	#apt-get update -qq;
	#apt-get install -qq libpcap-dev g++-4.8;
	#update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-4.8 90;
	echo "LINUX  build!";
elif [[ "$TRAVIS_OS_NAME" == "osx" ]]; then
	echo "OSX  build!";
fi
