#!/bin/bash
cp jni/libpcap/scanner_good.c jni/libpcap/scanner.c
cp jni/libpcap/grammar_good.c jni/libpcap/grammar.c
../android-ndk-r8b-linux/ndk-build
cp libs/armeabi/*.so ../android-ndk-r8b-linux/platforms/android-14/arch-arm/usr/lib/
