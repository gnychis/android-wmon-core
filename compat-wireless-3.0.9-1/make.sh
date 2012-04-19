#!/bin/bash
make clean
./scripts/driver-select ath9k
KERNEL_DIR=$(pwd)/../usbhost-kernel
make ARCH=arm CROSS_COMPILE=arm-eabi- KLIB=$KERNEL_DIR KLIB_BUILD=$KERNEL_DIR "$@"
