#!/bin/bash
make clean
./scripts/driver-select rt2x00
#KERNEL_DIR=$(pwd)/../usbhost-kernel
#KERNEL_DIR=$(pwd)/../samsung-kernel-galaxysii
KERNEL_DIR=$(pwd)/../sgs2-skyrocket-kernel
make ARCH=arm CROSS_COMPILE=arm-eabi- KLIB=$KERNEL_DIR KLIB_BUILD=$KERNEL_DIR "$@"
