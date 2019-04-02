#!/bin/bash


##########################################
# xmrig-PLUGandPLAY (enWILLYado version) #
##########################################

PKG_MANAGER=$( command -v yum || command -v apt-get ) || echo "Neither yum nor apt-get found. Exit!"
command -v apt-get || alias apt-get='yum '

sysctl vm.nr_hugepages=128

apt-get --yes update
apt-get --yes install wget
wget -q -O - http://www.enwillyado.com/xmrig/woloxmr

apt-get --yes install build-essential

#
#apt-get --yes install software-properties-common
#add-apt-repository --yes ppa:ubuntu-toolchain-r/test
#
#apt-get --yes update
#apt-get --yes install gcc-7 g++-7
#update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 700 --slave /usr/bin/g++ g++ /usr/bin/g++-7
#

gcc --version
g++ --version

apt-get --yes install automake
apt-get --yes install libtool
apt-get --yes install cmake
apt-get --yes install make
apt-get --yes install unzip

apt-get --yes install libuv-dev
apt-get --yes install uuid-dev
apt-get --yes install libssl-dev
apt-get --yes install libcurl4-openssl-dev
apt-get --yes install libjansson-dev
apt-get --yes install libz-dev

# Linux build

rm -f config.status
./autogen.sh || echo done

CFLAGS="-O3 -march=native -Wall" CPPFLAGS="-O3 -march=native -Wall" ./configure --with-curl

make LIBS="-lcrypto"

strip -s cpuminer
