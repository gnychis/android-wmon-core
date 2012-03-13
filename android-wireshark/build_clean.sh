#!/bin/bash

# Setup the environment
export CROSS_COMPILE=
export ARCH=
export CC=$(pwd)/agcc

find . -name Makefile -exec rm -f {} \;
find . -name .deps -exec rm -fr {} \;
find . -name .libs -exec rm -fr {} \;
./autogen.sh

# Configure wireshark
CONFIG_OPTIONS="-host=arm-eabi --disable-wireshark --with-pcap=yes --disable-glibtest --disable-warnings-as-errors --with-libsmi=no --with-gnutls=no"
./configure $CONFIG_OPTIONS
make clean
./configure $CONFIG_OPTIONS
find . -name Makefile -exec sed -i 's/-pthread//g' {} \;
find . -name Makefile -exec sed -i 's/-lrt/-lgcc -lpcap/g' {} \;
find . -name Makefile -exec sed -i 's/-g -O2/-g/g' {} \;
cd tools/lemon/
gcc -D_U_=""   -o lemon lemon.c
cd ../../
make
NDK="/home/gnychis/Documents/android/android-ndk-r6b-linux/platforms/android-9/arch-arm"
ALIB="$NDK/usr/lib"
PLATFORM="/home/gnychis/Documents/android/os"
TOOLCHAIN="$PLATFORM/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3"
arm-eabi-gcc -shared  -Wl,-soname,libtshark.so -o libtshark.so -I/home/gnychis/Documents/android/os/system/core/include -I/home/gnychis/Documents/android/os/hardware/libhardware/include -I/home/gnychis/Documents/android/os/hardware/ril/include -I/home/gnychis/Documents/android/android-ndk-r6b/platforms/android-9/arch-arm/usr/include -I/home/gnychis/Documents/android/os/dalvik/libnativehelper/include -I/home/gnychis/Documents/android/os/frameworks/base/include -I/home/gnychis/Documents/android/os/external/skia/include -I/home/gnychis/Documents/android/os/out/target/product/generic/obj/include -I/home/gnychis/Documents/android/os/bionic/libc/arch-arm/include -I/home/gnychis/Documents/android/os/bionic/libc/include -I/home/gnychis/Documents/android/os/bionic/libstdc++/include -I/home/gnychis/Documents/android/os/bionic/libc/kernel/common -I/home/gnychis/Documents/android/os/bionic/libc/kernel/arch-arm -I/home/gnychis/Documents/android/os/bionic/libm/include -I/home/gnychis/Documents/android/os/bionic/libm/include/arch/arm -I/home/gnychis/Documents/android/os/bionic/libthread_db/include -I/home/gnychis/Documents/android/os/bionic/libm/arm -I/home/gnychis/Documents/android/os/bionic/libm -I/home/gnychis/Documents/android/os/out/target/product/generic/obj/SHARED_LIBRARIES/libm_intermediates -DG_DISABLE_ASSERT -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ -DANDROID -DSK_RELEASE -DNDEBUG -UDEBUG -march=armv5te -mtune=xscale -msoft-float -mthumb-interwork -fpic -fno-exceptions -ffunction-sections -funwind-tables -fstack-protector -fmessage-length=0 -Wall -Wno-unused -Wno-multichar -Wstrict-aliasing=2 -O2 -finline-functions -finline-limit=300 -fno-inline-functions-called-once -fgcse-after-reload -frerun-cse-after-loop -frename-registers -fomit-frame-pointer -fstrict-aliasing -funswitch-loops -Bdynamic -Wl,-T,$PLATFORM/build/core/armelf.x -Wl,-dynamic-linker,/system/bin/linker -Wl,--gc-sections -Wl,-z,nocopyreloc -Wl,--no-undefined -Wl,-rpath-link=/home/gnychis/Documents/android/android-ndk-r6b/platforms/android-9/arch-arm/usr/lib -L/home/gnychis/Documents/android/android-ndk-r6b/platforms/android-9/arch-arm/usr/lib -nostdlib $TOOLCHAIN/lib32/libiberty.a $TOOLCHAIN/lib/gcc/arm-eabi/4.4.3/libgcc.a -lc -lm -DPYTHON_DIR= "-D_U_=__attribute__((unused))" -g -I/usr/local/include -I/usr/include/glib-2.0 -I/usr/lib/glib-2.0/include -I/usr/local/include capture-pcap-util-unix.o capture-pcap-util.o cfile.o clopts_common.o disabled_protos.o packet-range.o print.o ps.o sync_pipe_write.o timestats.o util.o tap-megaco-common.o tap-rtp-common.o version_info.o capture_errs.o capture_ifinfo.o capture_ui_utils.o tap-afpstat.o tap-ansi_astat.o tap-bootpstat.o tap-camelcounter.o tap-camelsrt.o tap-comparestat.o tap-dcerpcstat.o tap-diameter-avp.o tap-funnel.o tap-gsm_astat.o tap-h225counter.o tap-h225rassrt.o tap-hosts.o tap-httpstat.o tap-icmpstat.o tap-icmpv6stat.o tap-iostat.o tap-iousers.o tap-mgcpstat.o tap-megacostat.o tap-protocolinfo.o tap-protohierstat.o tap-radiusstat.o tap-rpcstat.o tap-rpcprogs.o tap-rtp.o tap-scsistat.o tap-sctpchunkstat.o tap-sipstat.o tap-smbsids.o tap-smbstat.o tap-stats_tree.o tap-sv.o tap-wspstat.o capture_opts.o capture_sync.o tempfile.o tshark-tap-register.o tshark_lib.o .libs/libtsharkS.o -L/usr/local/lib plugins/asn1/.libs/libasn1.a plugins/docsis/.libs/libdocsis.a plugins/ethercat/.libs/libethercat.a plugins/giop/.libs/libcosnaming.a plugins/giop/.libs/libcoseventcomm.a plugins/gryphon/.libs/libgryphon.a plugins/interlink/.libs/libinterlink.a plugins/irda/.libs/libirda.a plugins/m2m/.libs/libm2m.a plugins/mate/.libs/libmate.a plugins/opcua/.libs/libopcua.a plugins/profinet/.libs/libprofinet.a plugins/sercosiii/.libs/libsercosiii.a plugins/stats_tree/.libs/libstats_tree.a plugins/unistim/.libs/libunistim.a plugins/wimax/.libs/libwimax.a wiretap/.libs/libwiretap.a epan/.libs/libwireshark.a wiretap/.libs/libwiretap.a wsutil/.libs/libwsutil.a wsutil/.libs/libwsutil.a -lgmodule-2.0 -lgcc -lglib-2.0 -lm -lpcap -lnl -lz -lstdc++ -ldl -lgcrypt -lgpg-error
