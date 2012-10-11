#!/bin/bash
make clean
./scripts/driver-select restore
./scripts/driver-select bcmdhd
#./scripts/driver-select rt2x00
#./scripts/driver-select brcm80211
#KERNEL_DIR=$(pwd)/../usbhost-kernel
#KERNEL_DIR=$(pwd)/../samsung-kernel-galaxysii
KERNEL_DIR=$(pwd)/../galaxynexus-cm10-kernel
make ARCH=arm CROSS_COMPILE=arm-linux-androideabi- KLIB=$KERNEL_DIR KLIB_BUILD=$KERNEL_DIR "$@" EXTRA_CFLAGS=-fno-pic V=1
