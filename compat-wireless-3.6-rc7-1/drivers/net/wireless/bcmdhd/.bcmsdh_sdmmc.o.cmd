cmd_/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o := arm-linux-androideabi-gcc -Wp,-MD,/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/.bcmsdh_sdmmc.o.d -I/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/ -include /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.h -DCOMPAT_BASE="\"compat-v3.6-rc7-1\"" -DCOMPAT_BASE_TREE="\"linux-stable.git\"" -DCOMPAT_BASE_TREE_VERSION="\"v3.6-rc7\"" -DCOMPAT_PROJECT="\"Compat-wireless\"" -DCOMPAT_VERSION="\"compat-wireless-v3.6-rc7-1\"" -I/home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include -Iarch/arm/include/generated -Iinclude  -include include/generated/autoconf.h -D__KERNEL__ -mlittle-endian -Iarch/arm/mach-omap2/include -Iarch/arm/plat-omap/include -Wall -Wundef -Wstrict-prototypes -Wno-trigraphs -fno-strict-aliasing -fno-common -Werror-implicit-function-declaration -Wno-format-security -fno-delete-null-pointer-checks -O2 -marm -fno-dwarf2-cfi-asm -fno-omit-frame-pointer -mapcs -mno-sched-prolog -mabi=aapcs-linux -mno-thumb-interwork -D__LINUX_ARM_ARCH__=7 -march=armv7-a -msoft-float -Uarm -Wframe-larger-than=1024 -fno-stack-protector -Wno-unused-but-set-variable -fno-omit-frame-pointer -fno-optimize-sibling-calls -g -Wdeclaration-after-statement -Wno-pointer-sign -fno-strict-overflow -fconserve-stack -DCC_HAVE_ASM_GOTO -Wall -Wstrict-prototypes -Dlinux -DBCMDRIVER -DBCMDONGLEHOST -DUNRELEASEDCHIP -DBCMDMA32 -DWLBTAMP -DBCMFILEIMAGE -DDHDTHREAD -DDHD_GPL -DDHD_SCHED -DDHD_DEBUG -DSDTEST -DBDC -DTOE -DDHD_BCMEVENTS -DSHOW_EVENTS -DDONGLEOVERLAYS -DBCMDBG -DCUSTOMER_HW2 -DCUSTOM_OOB_GPIO_NUM=2 -DOOB_INTR_ONLY -DHW_OOB -DMMC_SDIO_ABORT -DBCMSDIO -DBCMLXSDMMC -DBCMPLATFORM_BUS -DWLP2P -DNEW_COMPAT_WIRELESS -DWIFI_ACT_FRAME -DARP_OFFLOAD_SUPPORT -DKEEP_ALIVE -DCSCAN -DGET_CUSTOM_MAC_ENABLE -DPKT_FILTER_SUPPORT -DEMBEDDED_PLATFORM -DENABLE_INSMOD_NO_FW_LOAD -DPNO_SUPPORT -DSET_RANDOM_MAC_SOFTAP -DWL_CFG80211_STA_EVENT -Idrivers/net/wireless/bcmdhd -Idrivers/net/wireless/bcmdhd/include -I/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd -I/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/include -DSOFTAP -DWL_WIRELESS_EXT -DWL_CFG80211 -DCUSTOM_ROAM_TRIGGER_SETTING=-65 -DCUSTOM_ROAM_DELTA_SETTING=15 -fno-pic  -DMODULE  -D"KBUILD_STR(s)=\#s" -D"KBUILD_BASENAME=KBUILD_STR(bcmsdh_sdmmc)"  -D"KBUILD_MODNAME=KBUILD_STR(bcmdhd)" -c -o /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.c

source_/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o := /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.c

deps_/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o := \
    $(wildcard include/config/pm/sleep.h) \
    $(wildcard include/config/mmc/msm7x00a.h) \
    $(wildcard include/config/dhd/use/static/buf.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.h \
  include/linux/version.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat_autoconf.h \
    $(wildcard include/config/compat/kernel/3/1.h) \
    $(wildcard include/config/compat/kernel/3/2.h) \
    $(wildcard include/config/compat/kernel/3/3.h) \
    $(wildcard include/config/compat/kernel/3/4.h) \
    $(wildcard include/config/compat/kernel/3/5.h) \
    $(wildcard include/config/compat/kernel/3/6.h) \
    $(wildcard include/config/compat/kernel/3/7.h) \
    $(wildcard include/config/compat/net/sch/codel.h) \
    $(wildcard include/config/compat/net/sch/fq/codel.h) \
    $(wildcard include/config/compat/kernel/2/6/24.h) \
    $(wildcard include/config/compat/kernel/2/6/27.h) \
    $(wildcard include/config/fw/loader.h) \
    $(wildcard include/config/compat/firmware/class.h) \
    $(wildcard include/config/compat/rhel/6/1.h) \
    $(wildcard include/config/compat/kernel/2/6/33.h) \
    $(wildcard include/config/compat/kernel/2/6/36.h) \
    $(wildcard include/config/compat/bt/sock/create/needs/kern.h) \
    $(wildcard include/config/compat/rhel/6/0.h) \
    $(wildcard include/config/compat/firmware/data/rw/needs/filp.h) \
    $(wildcard include/config/mac80211.h) \
    $(wildcard include/config/compat/mac80211/driver/api/tracer.h) \
    $(wildcard include/config/mac80211/rc/default.h) \
    $(wildcard include/config/mac80211/rc/default/minstrel.h) \
    $(wildcard include/config/compat/mac80211/rc/default.h) \
    $(wildcard include/config/mac80211/rc/pid.h) \
    $(wildcard include/config/mac80211/rc/minstrel.h) \
    $(wildcard include/config/mac80211/rc/minstrel/ht.h) \
    $(wildcard include/config/leds/triggers.h) \
    $(wildcard include/config/mac80211/leds.h) \
    $(wildcard include/config/mac80211/mesh.h) \
    $(wildcard include/config/cfg80211.h) \
    $(wildcard include/config/cfg80211/default/ps.h) \
    $(wildcard include/config/lib80211.h) \
    $(wildcard include/config/lib80211/crypt/wep.h) \
    $(wildcard include/config/lib80211/crypt/ccmp.h) \
    $(wildcard include/config/lib80211/crypt/tkip.h) \
    $(wildcard include/config/bt.h) \
    $(wildcard include/config/bt/rfcomm.h) \
    $(wildcard include/config/compat/bt/rfcomm/tty.h) \
    $(wildcard include/config/bt/bnep.h) \
    $(wildcard include/config/bt/bnep/mc/filter.h) \
    $(wildcard include/config/bt/bnep/proto/filter.h) \
    $(wildcard include/config/isdn/capi.h) \
    $(wildcard include/config/bt/cmtp.h) \
    $(wildcard include/config/compat/bt/hidp.h) \
    $(wildcard include/config/compat/kernel/2/6/28.h) \
    $(wildcard include/config/bt/hciuart.h) \
    $(wildcard include/config/bt/hciuart/h4.h) \
    $(wildcard include/config/bt/hciuart/bcsp.h) \
    $(wildcard include/config/bt/hciuart/ath3k.h) \
    $(wildcard include/config/bt/hciuart/ll.h) \
    $(wildcard include/config/bt/hcivhci.h) \
    $(wildcard include/config/bt/mrvl.h) \
    $(wildcard include/config/pcmcia.h) \
    $(wildcard include/config/bt/hcidtl1.h) \
    $(wildcard include/config/bt/hcibt3c.h) \
    $(wildcard include/config/bt/hcibluecard.h) \
    $(wildcard include/config/bt/hcibtuart.h) \
    $(wildcard include/config/wireless/ext.h) \
    $(wildcard include/config/cfg80211/wext.h) \
    $(wildcard include/config/staging.h) \
    $(wildcard include/config/compat/staging.h) \
    $(wildcard include/config/mac80211/hwsim.h) \
    $(wildcard include/config/ath5k.h) \
    $(wildcard include/config/ath9k.h) \
    $(wildcard include/config/ath9k/hw.h) \
    $(wildcard include/config/ath9k/common.h) \
    $(wildcard include/config/compat/ath9k/rate/control.h) \
    $(wildcard include/config/ath9k/btcoex/support.h) \
    $(wildcard include/config/wil6210.h) \
    $(wildcard include/config/compat/kernel/2/6/30.h) \
    $(wildcard include/config/ath6kl.h) \
    $(wildcard include/config/pci.h) \
    $(wildcard include/config/ath5k/pci.h) \
    $(wildcard include/config/ath9k/pci.h) \
    $(wildcard include/config/iwlwifi.h) \
    $(wildcard include/config/iwldvm.h) \
    $(wildcard include/config/iwlwifi/p2p.h) \
    $(wildcard include/config/iwlegacy.h) \
    $(wildcard include/config/compat/iwl4965.h) \
    $(wildcard include/config/iwl3945.h) \
    $(wildcard include/config/b43.h) \
    $(wildcard include/config/b43/hwrng.h) \
    $(wildcard include/config/b43/pci/autoselect.h) \
    $(wildcard include/config/b43/pcmcia.h) \
    $(wildcard include/config/b43/leds.h) \
    $(wildcard include/config/b43/phy/lp.h) \
    $(wildcard include/config/b43/phy/n.h) \
    $(wildcard include/config/b43/phy/ht.h) \
    $(wildcard include/config/b43legacy.h) \
    $(wildcard include/config/b43legacy/hwrng.h) \
    $(wildcard include/config/b43legacy/pci/autoselect.h) \
    $(wildcard include/config/b43legacy/leds.h) \
    $(wildcard include/config/b43legacy/dma.h) \
    $(wildcard include/config/b43legacy/pio.h) \
    $(wildcard include/config/libipw.h) \
    $(wildcard include/config/ipw2100.h) \
    $(wildcard include/config/ipw2100/monitor.h) \
    $(wildcard include/config/ipw2200.h) \
    $(wildcard include/config/ipw2200/monitor.h) \
    $(wildcard include/config/ipw2200/radiotap.h) \
    $(wildcard include/config/ipw2200/promiscuous.h) \
    $(wildcard include/config/ipw2200/qos.h) \
    $(wildcard include/config/ssb.h) \
    $(wildcard include/config/ssb/sprom.h) \
    $(wildcard include/config/ssb/blockio.h) \
    $(wildcard include/config/ssb/pcihost.h) \
    $(wildcard include/config/ssb/b43/pci/bridge.h) \
    $(wildcard include/config/ssb/pcmciahost.h) \
    $(wildcard include/config/ssb/driver/pcicore.h) \
    $(wildcard include/config/b43/ssb.h) \
    $(wildcard include/config/bcma.h) \
    $(wildcard include/config/bcma/blockio.h) \
    $(wildcard include/config/bcma/host/pci.h) \
    $(wildcard include/config/b43/bcma.h) \
    $(wildcard include/config/b43/bcma/extra.h) \
    $(wildcard include/config/p54/pci.h) \
    $(wildcard include/config/b44.h) \
    $(wildcard include/config/b44/pci.h) \
    $(wildcard include/config/rtl8180.h) \
    $(wildcard include/config/adm8211.h) \
    $(wildcard include/config/rt2x00/lib/pci.h) \
    $(wildcard include/config/rt2400pci.h) \
    $(wildcard include/config/rt2500pci.h) \
    $(wildcard include/config/crc/ccitt.h) \
    $(wildcard include/config/rt2800pci.h) \
    $(wildcard include/config/rt2800pci/rt33xx.h) \
    $(wildcard include/config/rt2800pci/rt35xx.h) \
    $(wildcard include/config/rt2800pci/rt53xx.h) \
    $(wildcard include/config/crc/itu/t.h) \
    $(wildcard include/config/rt61pci.h) \
    $(wildcard include/config/mwl8k.h) \
    $(wildcard include/config/atl1.h) \
    $(wildcard include/config/atl2.h) \
    $(wildcard include/config/atl1e.h) \
    $(wildcard include/config/atl1c.h) \
    $(wildcard include/config/alx.h) \
    $(wildcard include/config/hermes.h) \
    $(wildcard include/config/hermes/cache/fw/on/init.h) \
    $(wildcard include/config/ppc/pmac.h) \
    $(wildcard include/config/apple/airport.h) \
    $(wildcard include/config/plx/hermes.h) \
    $(wildcard include/config/tmd/hermes.h) \
    $(wildcard include/config/nortel/hermes.h) \
    $(wildcard include/config/pci/hermes.h) \
    $(wildcard include/config/pcmcia/hermes.h) \
    $(wildcard include/config/pcmcia/spectrum.h) \
    $(wildcard include/config/rtl8192ce.h) \
    $(wildcard include/config/rtl8192se.h) \
    $(wildcard include/config/rtl8192de.h) \
    $(wildcard include/config/brcmsmac.h) \
    $(wildcard include/config/mwifiex/pcie.h) \
    $(wildcard include/config/libertas.h) \
    $(wildcard include/config/libertas/cs.h) \
    $(wildcard include/config/eeprom/93cx6.h) \
    $(wildcard include/config/usb.h) \
    $(wildcard include/config/compat/zd1211rw.h) \
    $(wildcard include/config/compat/kernel/2/6/29.h) \
    $(wildcard include/config/usb/compat/usbnet.h) \
    $(wildcard include/config/usb/net/compat/rndis/host.h) \
    $(wildcard include/config/usb/net/compat/rndis/wlan.h) \
    $(wildcard include/config/usb/net/compat/cdcether.h) \
    $(wildcard include/config/usb/net/cdcether.h) \
    $(wildcard include/config/usb/net/cdcether/module.h) \
    $(wildcard include/config/p54/usb.h) \
    $(wildcard include/config/rtl8187.h) \
    $(wildcard include/config/rtl8187/leds.h) \
    $(wildcard include/config/at76c50x/usb.h) \
    $(wildcard include/config/carl9170.h) \
    $(wildcard include/config/carl9170/leds.h) \
    $(wildcard include/config/carl9170/wpc.h) \
    $(wildcard include/config/compat/usb/urb/thread/fix.h) \
    $(wildcard include/config/ath9k/htc.h) \
    $(wildcard include/config/ath6kl/usb.h) \
    $(wildcard include/config/brcmfmac/usb.h) \
    $(wildcard include/config/rt2500usb.h) \
    $(wildcard include/config/rt2800usb.h) \
    $(wildcard include/config/rt2800usb/rt33xx.h) \
    $(wildcard include/config/rt2800usb/rt35xx.h) \
    $(wildcard include/config/rt2800usb/rt53xx.h) \
    $(wildcard include/config/rt2800usb/unknown.h) \
    $(wildcard include/config/rt2x00/lib/usb.h) \
    $(wildcard include/config/rt73usb.h) \
    $(wildcard include/config/libertas/thinfirm/usb.h) \
    $(wildcard include/config/libertas/usb.h) \
    $(wildcard include/config/orinoco/usb.h) \
    $(wildcard include/config/bt/hcibtusb.h) \
    $(wildcard include/config/bt/hcibcm203x.h) \
    $(wildcard include/config/bt/hcibpa10x.h) \
    $(wildcard include/config/bt/hcibfusb.h) \
    $(wildcard include/config/bt/ath3k.h) \
    $(wildcard include/config/rtl8192cu.h) \
    $(wildcard include/config/spi/master.h) \
    $(wildcard include/config/crc7.h) \
    $(wildcard include/config/compat/wl1251/spi.h) \
    $(wildcard include/config/compat/kernel/2/6/37.h) \
    $(wildcard include/config/wlcore/spi.h) \
    $(wildcard include/config/p54/spi.h) \
    $(wildcard include/config/libertas/spi.h) \
    $(wildcard include/config/compat/kernel/2/6/25.h) \
    $(wildcard include/config/mmc.h) \
    $(wildcard include/config/ssb/sdiohost.h) \
    $(wildcard include/config/b43/sdio.h) \
    $(wildcard include/config/wl12xx/platform/data.h) \
    $(wildcard include/config/compat/wl1251/sdio.h) \
    $(wildcard include/config/wlcore/sdio.h) \
    $(wildcard include/config/mwifiex/sdio.h) \
    $(wildcard include/config/compat/libertas/sdio.h) \
    $(wildcard include/config/compat/kernel/2/6/32.h) \
    $(wildcard include/config/iwm.h) \
    $(wildcard include/config/bt/hcibtsdio.h) \
    $(wildcard include/config/bt/mrvl/sdio.h) \
    $(wildcard include/config/ath6kl/sdio.h) \
    $(wildcard include/config/brcmfmac/sdio.h) \
    $(wildcard include/config/rtlwifi.h) \
    $(wildcard include/config/rtl8192c/common.h) \
    $(wildcard include/config/bcmdhd.h) \
    $(wildcard include/config/rt2x00.h) \
    $(wildcard include/config/rt2x00/lib.h) \
    $(wildcard include/config/rt2800/lib.h) \
    $(wildcard include/config/rt2x00/lib/firmware.h) \
    $(wildcard include/config/rt2x00/lib/crypto.h) \
    $(wildcard include/config/rt2x00/lib/leds.h) \
    $(wildcard include/config/leds/class.h) \
    $(wildcard include/config/p54/common.h) \
    $(wildcard include/config/p54/leds.h) \
    $(wildcard include/config/ath/common.h) \
    $(wildcard include/config/brcmutil.h) \
    $(wildcard include/config/brcmfmac.h) \
    $(wildcard include/config/wl/ti.h) \
    $(wildcard include/config/wlcore.h) \
    $(wildcard include/config/wl1251.h) \
    $(wildcard include/config/wl12xx.h) \
    $(wildcard include/config/wl18xx.h) \
    $(wildcard include/config/mwifiex.h) \
    $(wildcard include/config/cordic.h) \
    $(wildcard include/config/compat/cordic.h) \
    $(wildcard include/config/crc8.h) \
    $(wildcard include/config/compat/crc8.h) \
    $(wildcard include/config/libertas/thinfirm.h) \
    $(wildcard include/config/libertas/mesh.h) \
    $(wildcard include/config/rfkill/backport.h) \
    $(wildcard include/config/rfkill/backport/leds.h) \
    $(wildcard include/config/rfkill/backport/input.h) \
    $(wildcard include/config/compat/kernel/2/6/31.h) \
    $(wildcard include/config/net/sched.h) \
    $(wildcard include/config/netdevices/multiqueue.h) \
    $(wildcard include/config/mac80211/qos.h) \
  include/linux/init.h \
    $(wildcard include/config/modules.h) \
    $(wildcard include/config/hotplug.h) \
  include/linux/compiler.h \
    $(wildcard include/config/sparse/rcu/pointer.h) \
    $(wildcard include/config/trace/branch/profiling.h) \
    $(wildcard include/config/profile/all/branches.h) \
    $(wildcard include/config/enable/must/check.h) \
    $(wildcard include/config/enable/warn/deprecated.h) \
  include/linux/compiler-gcc.h \
    $(wildcard include/config/arch/supports/optimized/inlining.h) \
    $(wildcard include/config/optimize/inlining.h) \
  include/linux/compiler-gcc4.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.22.h \
    $(wildcard include/config/ax25.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.23.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.24.h \
    $(wildcard include/config/net.h) \
    $(wildcard include/config/debug/sg.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.25.h \
    $(wildcard include/config/x86.h) \
    $(wildcard include/config/x86/64.h) \
    $(wildcard include/config/64bit.h) \
    $(wildcard include/config/x86/pae.h) \
    $(wildcard include/config/phys/64bit.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.26.h \
    $(wildcard include/config/net/ns.h) \
    $(wildcard include/config/alpha.h) \
    $(wildcard include/config/arm.h) \
    $(wildcard include/config/avr32.h) \
    $(wildcard include/config/blackfin.h) \
    $(wildcard include/config/cris.h) \
    $(wildcard include/config/frv.h) \
    $(wildcard include/config/h8300.h) \
    $(wildcard include/config/ia64.h) \
    $(wildcard include/config/m32r.h) \
    $(wildcard include/config/m68k.h) \
    $(wildcard include/config/coldfire.h) \
    $(wildcard include/config/mips.h) \
    $(wildcard include/config/mn10300.h) \
    $(wildcard include/config/parisc.h) \
    $(wildcard include/config/ppc.h) \
    $(wildcard include/config/s390.h) \
    $(wildcard include/config/superh.h) \
    $(wildcard include/config/sparc.h) \
    $(wildcard include/config/uml.h) \
    $(wildcard include/config/v850.h) \
    $(wildcard include/config/xtensa.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.27.h \
    $(wildcard include/config/compat.h) \
    $(wildcard include/config/debug/fs.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.28.h \
    $(wildcard include/config/phys/addr/t/64bit.h) \
    $(wildcard include/config/ppc64.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.29.h \
    $(wildcard include/config/ppc32.h) \
    $(wildcard include/config/net/poll/controller.h) \
    $(wildcard include/config/fcoe.h) \
  include/linux/netdevice.h \
    $(wildcard include/config/dcb.h) \
    $(wildcard include/config/wlan.h) \
    $(wildcard include/config/tr.h) \
    $(wildcard include/config/net/ipip.h) \
    $(wildcard include/config/net/ipgre.h) \
    $(wildcard include/config/ipv6/sit.h) \
    $(wildcard include/config/ipv6/tunnel.h) \
    $(wildcard include/config/netpoll.h) \
    $(wildcard include/config/smp.h) \
    $(wildcard include/config/rps.h) \
    $(wildcard include/config/xps.h) \
    $(wildcard include/config/numa.h) \
    $(wildcard include/config/rfs/accel.h) \
    $(wildcard include/config/vlan/8021q.h) \
    $(wildcard include/config/net/dsa.h) \
    $(wildcard include/config/net/dsa/tag/dsa.h) \
    $(wildcard include/config/net/dsa/tag/trailer.h) \
    $(wildcard include/config/netpoll/trap.h) \
    $(wildcard include/config/bug.h) \
    $(wildcard include/config/proc/fs.h) \
    $(wildcard include/config/dynamic/debug.h) \
  include/linux/if.h \
  include/linux/types.h \
    $(wildcard include/config/uid16.h) \
    $(wildcard include/config/lbdaf.h) \
    $(wildcard include/config/arch/dma/addr/t/64bit.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/types.h \
  include/asm-generic/int-ll64.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/bitsperlong.h \
  include/asm-generic/bitsperlong.h \
  include/linux/posix_types.h \
  include/linux/stddef.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/posix_types.h \
  include/linux/socket.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/socket.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/sockios.h \
  include/linux/sockios.h \
  include/linux/uio.h \
  include/linux/hdlc/ioctl.h \
  include/linux/if_ether.h \
  include/linux/skbuff.h \
    $(wildcard include/config/nf/conntrack.h) \
    $(wildcard include/config/bridge/netfilter.h) \
    $(wildcard include/config/nf/defrag/ipv4.h) \
    $(wildcard include/config/nf/defrag/ipv6.h) \
    $(wildcard include/config/xfrm.h) \
    $(wildcard include/config/net/cls/act.h) \
    $(wildcard include/config/ipv6/ndisc/nodetype.h) \
    $(wildcard include/config/net/dma.h) \
    $(wildcard include/config/network/secmark.h) \
    $(wildcard include/config/network/phy/timestamping.h) \
  include/linux/kernel.h \
    $(wildcard include/config/preempt/voluntary.h) \
    $(wildcard include/config/debug/spinlock/sleep.h) \
    $(wildcard include/config/prove/locking.h) \
    $(wildcard include/config/ring/buffer.h) \
    $(wildcard include/config/tracing.h) \
    $(wildcard include/config/compaction.h) \
    $(wildcard include/config/ftrace/mcount/record.h) \
  /home/owner/android-wmon/core/os/prebuilts/gcc/linux-x86/arm/arm-linux-androideabi-4.6/bin/../lib/gcc/arm-linux-androideabi/4.6.x-google/include/stdarg.h \
  include/linux/linkage.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/linkage.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/bitops.h \
    $(wildcard include/config/generic/find/first/bit.h) \
    $(wildcard include/config/generic/find/last/bit.h) \
    $(wildcard include/config/generic/find/next/bit.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/bitops.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/system.h \
    $(wildcard include/config/function/graph/tracer.h) \
    $(wildcard include/config/cpu/32v6k.h) \
    $(wildcard include/config/cpu/xsc3.h) \
    $(wildcard include/config/cpu/fa526.h) \
    $(wildcard include/config/arch/has/barriers.h) \
    $(wildcard include/config/arm/dma/mem/bufferable.h) \
    $(wildcard include/config/cpu/sa1100.h) \
    $(wildcard include/config/cpu/sa110.h) \
    $(wildcard include/config/cpu/v6.h) \
  include/linux/irqflags.h \
    $(wildcard include/config/trace/irqflags.h) \
    $(wildcard include/config/irqsoff/tracer.h) \
    $(wildcard include/config/preempt/tracer.h) \
    $(wildcard include/config/trace/irqflags/support.h) \
  include/linux/typecheck.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/irqflags.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/ptrace.h \
    $(wildcard include/config/cpu/endian/be8.h) \
    $(wildcard include/config/arm/thumb.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/hwcap.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/outercache.h \
    $(wildcard include/config/outer/cache/sync.h) \
    $(wildcard include/config/outer/cache.h) \
  arch/arm/mach-omap2/include/mach/barriers.h \
    $(wildcard include/config/arch/omap4.h) \
  include/asm-generic/cmpxchg-local.h \
  include/asm-generic/bitops/non-atomic.h \
  include/asm-generic/bitops/fls64.h \
  include/asm-generic/bitops/sched.h \
  include/asm-generic/bitops/hweight.h \
  include/asm-generic/bitops/arch_hweight.h \
  include/asm-generic/bitops/const_hweight.h \
  include/asm-generic/bitops/lock.h \
  include/asm-generic/bitops/le.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/byteorder.h \
  include/linux/byteorder/little_endian.h \
  include/linux/swab.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/swab.h \
  include/linux/byteorder/generic.h \
  include/linux/log2.h \
    $(wildcard include/config/arch/has/ilog2/u32.h) \
    $(wildcard include/config/arch/has/ilog2/u64.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/printk.h \
  include/linux/printk.h \
    $(wildcard include/config/printk.h) \
  include/linux/dynamic_debug.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/bug.h \
    $(wildcard include/config/debug/bugverbose.h) \
  include/asm-generic/bug.h \
    $(wildcard include/config/generic/bug.h) \
    $(wildcard include/config/generic/bug/relative/pointers.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/div64.h \
  include/linux/kmemcheck.h \
    $(wildcard include/config/kmemcheck.h) \
  include/linux/mm_types.h \
    $(wildcard include/config/split/ptlock/cpus.h) \
    $(wildcard include/config/want/page/debug/flags.h) \
    $(wildcard include/config/mmu.h) \
    $(wildcard include/config/aio.h) \
    $(wildcard include/config/mm/owner.h) \
    $(wildcard include/config/mmu/notifier.h) \
    $(wildcard include/config/transparent/hugepage.h) \
    $(wildcard include/config/cpumask/offstack.h) \
  include/linux/auxvec.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/auxvec.h \
  include/linux/threads.h \
    $(wildcard include/config/nr/cpus.h) \
    $(wildcard include/config/base/small.h) \
  include/linux/list.h \
    $(wildcard include/config/debug/list.h) \
  include/linux/poison.h \
    $(wildcard include/config/illegal/pointer/value.h) \
  include/linux/const.h \
  include/linux/spinlock.h \
    $(wildcard include/config/debug/spinlock.h) \
    $(wildcard include/config/generic/lockbreak.h) \
    $(wildcard include/config/preempt.h) \
    $(wildcard include/config/debug/lock/alloc.h) \
  include/linux/preempt.h \
    $(wildcard include/config/debug/preempt.h) \
    $(wildcard include/config/preempt/notifiers.h) \
  include/linux/thread_info.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/thread_info.h \
    $(wildcard include/config/arm/thumbee.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/fpstate.h \
    $(wildcard include/config/vfpv3.h) \
    $(wildcard include/config/iwmmxt.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/domain.h \
    $(wildcard include/config/io/36.h) \
    $(wildcard include/config/cpu/use/domains.h) \
  include/linux/stringify.h \
  include/linux/bottom_half.h \
  include/linux/spinlock_types.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/spinlock_types.h \
  include/linux/lockdep.h \
    $(wildcard include/config/lockdep.h) \
    $(wildcard include/config/lock/stat.h) \
    $(wildcard include/config/prove/rcu.h) \
  include/linux/rwlock_types.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/spinlock.h \
    $(wildcard include/config/thumb2/kernel.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/processor.h \
    $(wildcard include/config/have/hw/breakpoint.h) \
    $(wildcard include/config/arm/errata/754327.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/hw_breakpoint.h \
  include/linux/rwlock.h \
  include/linux/spinlock_api_smp.h \
    $(wildcard include/config/inline/spin/lock.h) \
    $(wildcard include/config/inline/spin/lock/bh.h) \
    $(wildcard include/config/inline/spin/lock/irq.h) \
    $(wildcard include/config/inline/spin/lock/irqsave.h) \
    $(wildcard include/config/inline/spin/trylock.h) \
    $(wildcard include/config/inline/spin/trylock/bh.h) \
    $(wildcard include/config/inline/spin/unlock.h) \
    $(wildcard include/config/inline/spin/unlock/bh.h) \
    $(wildcard include/config/inline/spin/unlock/irq.h) \
    $(wildcard include/config/inline/spin/unlock/irqrestore.h) \
  include/linux/rwlock_api_smp.h \
    $(wildcard include/config/inline/read/lock.h) \
    $(wildcard include/config/inline/write/lock.h) \
    $(wildcard include/config/inline/read/lock/bh.h) \
    $(wildcard include/config/inline/write/lock/bh.h) \
    $(wildcard include/config/inline/read/lock/irq.h) \
    $(wildcard include/config/inline/write/lock/irq.h) \
    $(wildcard include/config/inline/read/lock/irqsave.h) \
    $(wildcard include/config/inline/write/lock/irqsave.h) \
    $(wildcard include/config/inline/read/trylock.h) \
    $(wildcard include/config/inline/write/trylock.h) \
    $(wildcard include/config/inline/read/unlock.h) \
    $(wildcard include/config/inline/write/unlock.h) \
    $(wildcard include/config/inline/read/unlock/bh.h) \
    $(wildcard include/config/inline/write/unlock/bh.h) \
    $(wildcard include/config/inline/read/unlock/irq.h) \
    $(wildcard include/config/inline/write/unlock/irq.h) \
    $(wildcard include/config/inline/read/unlock/irqrestore.h) \
    $(wildcard include/config/inline/write/unlock/irqrestore.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/atomic.h \
    $(wildcard include/config/generic/atomic64.h) \
  include/asm-generic/atomic-long.h \
  include/linux/prio_tree.h \
  include/linux/rbtree.h \
  include/linux/rwsem.h \
    $(wildcard include/config/rwsem/generic/spinlock.h) \
  include/linux/rwsem-spinlock.h \
  include/linux/completion.h \
  include/linux/wait.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/current.h \
  include/linux/cpumask.h \
    $(wildcard include/config/hotplug/cpu.h) \
    $(wildcard include/config/debug/per/cpu/maps.h) \
    $(wildcard include/config/disable/obsolete/cpumask/functions.h) \
  include/linux/bitmap.h \
  include/linux/string.h \
    $(wildcard include/config/binary/printf.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/string.h \
  include/linux/page-debug-flags.h \
    $(wildcard include/config/page/poisoning.h) \
    $(wildcard include/config/page/debug/something/else.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/page.h \
    $(wildcard include/config/cpu/copy/v3.h) \
    $(wildcard include/config/cpu/copy/v4wt.h) \
    $(wildcard include/config/cpu/copy/v4wb.h) \
    $(wildcard include/config/cpu/copy/feroceon.h) \
    $(wildcard include/config/cpu/copy/fa.h) \
    $(wildcard include/config/cpu/xscale.h) \
    $(wildcard include/config/cpu/copy/v6.h) \
    $(wildcard include/config/have/arch/pfn/valid.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/glue.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/memory.h \
    $(wildcard include/config/page/offset.h) \
    $(wildcard include/config/highmem.h) \
    $(wildcard include/config/dram/size.h) \
    $(wildcard include/config/dram/base.h) \
    $(wildcard include/config/have/tcm.h) \
    $(wildcard include/config/arm/patch/phys/virt.h) \
    $(wildcard include/config/arm/patch/phys/virt/16bit.h) \
  arch/arm/mach-omap2/include/mach/memory.h \
  arch/arm/plat-omap/include/plat/memory.h \
    $(wildcard include/config/arch/omap1.h) \
    $(wildcard include/config/arch/omap15xx.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/sizes.h \
  include/asm-generic/sizes.h \
  include/asm-generic/memory_model.h \
    $(wildcard include/config/flatmem.h) \
    $(wildcard include/config/discontigmem.h) \
    $(wildcard include/config/sparsemem/vmemmap.h) \
    $(wildcard include/config/sparsemem.h) \
  include/asm-generic/getorder.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/mmu.h \
    $(wildcard include/config/cpu/has/asid.h) \
  include/linux/time.h \
    $(wildcard include/config/arch/uses/gettimeoffset.h) \
  include/linux/cache.h \
    $(wildcard include/config/arch/has/cache/line/size.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/cache.h \
    $(wildcard include/config/arm/l1/cache/shift.h) \
    $(wildcard include/config/aeabi.h) \
  include/linux/seqlock.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/math64.h \
  include/linux/math64.h \
  include/linux/net.h \
  include/linux/random.h \
    $(wildcard include/config/arch/random.h) \
  include/linux/ioctl.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/ioctl.h \
  include/asm-generic/ioctl.h \
  include/linux/irqnr.h \
    $(wildcard include/config/generic/hardirqs.h) \
  include/linux/fcntl.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/fcntl.h \
  include/asm-generic/fcntl.h \
  include/linux/rcupdate.h \
    $(wildcard include/config/rcu/torture/test.h) \
    $(wildcard include/config/tree/rcu.h) \
    $(wildcard include/config/tree/preempt/rcu.h) \
    $(wildcard include/config/preempt/rcu.h) \
    $(wildcard include/config/no/hz.h) \
    $(wildcard include/config/tiny/rcu.h) \
    $(wildcard include/config/tiny/preempt/rcu.h) \
    $(wildcard include/config/debug/objects/rcu/head.h) \
    $(wildcard include/config/preempt/rt.h) \
  include/linux/debugobjects.h \
    $(wildcard include/config/debug/objects.h) \
    $(wildcard include/config/debug/objects/free.h) \
  include/linux/rcutree.h \
  include/linux/textsearch.h \
  include/linux/module.h \
    $(wildcard include/config/symbol/prefix.h) \
    $(wildcard include/config/sysfs.h) \
    $(wildcard include/config/modversions.h) \
    $(wildcard include/config/unused/symbols.h) \
    $(wildcard include/config/kallsyms.h) \
    $(wildcard include/config/tracepoints.h) \
    $(wildcard include/config/event/tracing.h) \
    $(wildcard include/config/module/unload.h) \
    $(wildcard include/config/constructors.h) \
    $(wildcard include/config/debug/set/module/ronx.h) \
  include/linux/stat.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/stat.h \
  include/linux/kmod.h \
  include/linux/gfp.h \
    $(wildcard include/config/zone/dma.h) \
    $(wildcard include/config/zone/dma32.h) \
  include/linux/mmzone.h \
    $(wildcard include/config/force/max/zoneorder.h) \
    $(wildcard include/config/memory/hotplug.h) \
    $(wildcard include/config/arch/populates/node/map.h) \
    $(wildcard include/config/flat/node/mem/map.h) \
    $(wildcard include/config/cgroup/mem/res/ctlr.h) \
    $(wildcard include/config/no/bootmem.h) \
    $(wildcard include/config/have/memory/present.h) \
    $(wildcard include/config/have/memoryless/nodes.h) \
    $(wildcard include/config/need/node/memmap/size.h) \
    $(wildcard include/config/need/multiple/nodes.h) \
    $(wildcard include/config/have/arch/early/pfn/to/nid.h) \
    $(wildcard include/config/sparsemem/extreme.h) \
    $(wildcard include/config/nodes/span/other/nodes.h) \
    $(wildcard include/config/holes/in/zone.h) \
    $(wildcard include/config/arch/has/holes/memorymodel.h) \
  include/linux/numa.h \
    $(wildcard include/config/nodes/shift.h) \
  include/linux/nodemask.h \
  include/linux/pageblock-flags.h \
    $(wildcard include/config/hugetlb/page.h) \
    $(wildcard include/config/hugetlb/page/size/variable.h) \
  include/generated/bounds.h \
  include/linux/memory_hotplug.h \
    $(wildcard include/config/memory/hotremove.h) \
    $(wildcard include/config/have/arch/nodedata/extension.h) \
  include/linux/notifier.h \
  include/linux/errno.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/errno.h \
  include/asm-generic/errno.h \
  include/asm-generic/errno-base.h \
  include/linux/mutex.h \
    $(wildcard include/config/debug/mutexes.h) \
    $(wildcard include/config/have/arch/mutex/cpu/relax.h) \
  include/linux/srcu.h \
  include/linux/topology.h \
    $(wildcard include/config/sched/smt.h) \
    $(wildcard include/config/sched/mc.h) \
    $(wildcard include/config/sched/book.h) \
    $(wildcard include/config/use/percpu/numa/node/id.h) \
  include/linux/smp.h \
    $(wildcard include/config/use/generic/smp/helpers.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/smp.h \
  include/linux/percpu.h \
    $(wildcard include/config/need/per/cpu/embed/first/chunk.h) \
    $(wildcard include/config/need/per/cpu/page/first/chunk.h) \
    $(wildcard include/config/have/setup/per/cpu/area.h) \
  include/linux/pfn.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/percpu.h \
  include/asm-generic/percpu.h \
  include/linux/percpu-defs.h \
    $(wildcard include/config/debug/force/weak/per/cpu.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/topology.h \
  include/asm-generic/topology.h \
  include/linux/mmdebug.h \
    $(wildcard include/config/debug/vm.h) \
    $(wildcard include/config/debug/virtual.h) \
  include/linux/workqueue.h \
    $(wildcard include/config/debug/objects/work.h) \
    $(wildcard include/config/freezer.h) \
  include/linux/timer.h \
    $(wildcard include/config/timer/stats.h) \
    $(wildcard include/config/debug/objects/timers.h) \
  include/linux/ktime.h \
    $(wildcard include/config/ktime/scalar.h) \
  include/linux/jiffies.h \
  include/linux/timex.h \
  include/linux/param.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/param.h \
    $(wildcard include/config/hz.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/timex.h \
  arch/arm/mach-omap2/include/mach/timex.h \
  arch/arm/plat-omap/include/plat/timex.h \
    $(wildcard include/config/omap/32k/timer.h) \
    $(wildcard include/config/omap/32k/timer/hz.h) \
  include/linux/sysctl.h \
  include/linux/elf.h \
  include/linux/elf-em.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/elf.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/user.h \
  include/linux/kobject.h \
  include/linux/sysfs.h \
  include/linux/kobject_ns.h \
  include/linux/kref.h \
  include/linux/moduleparam.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/tracepoint.h \
  include/linux/tracepoint.h \
  include/linux/jump_label.h \
    $(wildcard include/config/jump/label.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/module.h \
    $(wildcard include/config/arm/unwind.h) \
  include/trace/events/module.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/trace/define_trace.h \
  include/trace/define_trace.h \
  include/linux/err.h \
  include/linux/slab.h \
    $(wildcard include/config/slab/debug.h) \
    $(wildcard include/config/failslab.h) \
    $(wildcard include/config/slub.h) \
    $(wildcard include/config/slob.h) \
    $(wildcard include/config/debug/slab.h) \
    $(wildcard include/config/slab.h) \
  include/linux/slub_def.h \
    $(wildcard include/config/slub/stats.h) \
    $(wildcard include/config/slub/debug.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/kmemleak.h \
  include/linux/kmemleak.h \
    $(wildcard include/config/debug/kmemleak.h) \
  include/net/checksum.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/uaccess.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/unified.h \
    $(wildcard include/config/arm/asm/unified.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/checksum.h \
  include/linux/in6.h \
  include/linux/dmaengine.h \
    $(wildcard include/config/async/tx/enable/channel/switch.h) \
    $(wildcard include/config/dma/engine.h) \
    $(wildcard include/config/async/tx/dma.h) \
  include/linux/device.h \
    $(wildcard include/config/debug/devres.h) \
    $(wildcard include/config/devtmpfs.h) \
    $(wildcard include/config/sysfs/deprecated.h) \
  include/linux/ioport.h \
  include/linux/klist.h \
  include/linux/pm.h \
    $(wildcard include/config/pm.h) \
    $(wildcard include/config/pm/runtime.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/device.h \
    $(wildcard include/config/dmabounce.h) \
  include/linux/pm_wakeup.h \
  include/linux/dma-mapping.h \
    $(wildcard include/config/has/dma.h) \
    $(wildcard include/config/have/dma/attrs.h) \
    $(wildcard include/config/need/dma/map/state.h) \
  include/linux/dma-attrs.h \
  include/linux/bug.h \
  include/linux/scatterlist.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/scatterlist.h \
  include/asm-generic/scatterlist.h \
    $(wildcard include/config/need/sg/dma/length.h) \
  include/linux/mm.h \
    $(wildcard include/config/sysctl.h) \
    $(wildcard include/config/stack/growsup.h) \
    $(wildcard include/config/ksm.h) \
    $(wildcard include/config/debug/pagealloc.h) \
    $(wildcard include/config/hibernation.h) \
    $(wildcard include/config/hugetlbfs.h) \
  include/linux/debug_locks.h \
    $(wildcard include/config/debug/locking/api/selftests.h) \
  include/linux/range.h \
  include/linux/bit_spinlock.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/pgtable.h \
    $(wildcard include/config/highpte.h) \
  include/asm-generic/4level-fixup.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/proc-fns.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/glue-proc.h \
    $(wildcard include/config/cpu/arm610.h) \
    $(wildcard include/config/cpu/arm7tdmi.h) \
    $(wildcard include/config/cpu/arm710.h) \
    $(wildcard include/config/cpu/arm720t.h) \
    $(wildcard include/config/cpu/arm740t.h) \
    $(wildcard include/config/cpu/arm9tdmi.h) \
    $(wildcard include/config/cpu/arm920t.h) \
    $(wildcard include/config/cpu/arm922t.h) \
    $(wildcard include/config/cpu/arm925t.h) \
    $(wildcard include/config/cpu/arm926t.h) \
    $(wildcard include/config/cpu/arm940t.h) \
    $(wildcard include/config/cpu/arm946e.h) \
    $(wildcard include/config/cpu/arm1020.h) \
    $(wildcard include/config/cpu/arm1020e.h) \
    $(wildcard include/config/cpu/arm1022.h) \
    $(wildcard include/config/cpu/arm1026.h) \
    $(wildcard include/config/cpu/mohawk.h) \
    $(wildcard include/config/cpu/feroceon.h) \
    $(wildcard include/config/cpu/v6k.h) \
    $(wildcard include/config/cpu/v7.h) \
  arch/arm/mach-omap2/include/mach/vmalloc.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/pgtable-hwdef.h \
  include/asm-generic/pgtable.h \
  include/linux/page-flags.h \
    $(wildcard include/config/pageflags/extended.h) \
    $(wildcard include/config/arch/uses/pg/uncached.h) \
    $(wildcard include/config/memory/failure.h) \
    $(wildcard include/config/swap.h) \
  include/linux/huge_mm.h \
  include/linux/vmstat.h \
    $(wildcard include/config/vm/event/counters.h) \
  include/linux/vm_event_item.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/io.h \
  arch/arm/mach-omap2/include/mach/io.h \
  arch/arm/plat-omap/include/plat/io.h \
    $(wildcard include/config/soc/omap2420.h) \
    $(wildcard include/config/soc/omap2430.h) \
    $(wildcard include/config/arch/omap3.h) \
    $(wildcard include/config/soc/omapti816x.h) \
  arch/arm/mach-omap2/include/mach/hardware.h \
  arch/arm/plat-omap/include/plat/hardware.h \
    $(wildcard include/config/reg/base.h) \
  arch/arm/plat-omap/include/plat/cpu.h \
    $(wildcard include/config/arch/omap730.h) \
    $(wildcard include/config/arch/omap850.h) \
    $(wildcard include/config/arch/omap16xx.h) \
    $(wildcard include/config/arch/omap2.h) \
    $(wildcard include/config/soc/omap3430.h) \
  arch/arm/plat-omap/include/plat/multi.h \
    $(wildcard include/config/arch/omap2plus.h) \
  arch/arm/plat-omap/include/plat/serial.h \
  arch/arm/plat-omap/include/plat/omap7xx.h \
    $(wildcard include/config/base.h) \
  arch/arm/plat-omap/include/plat/omap1510.h \
  arch/arm/plat-omap/include/plat/omap16xx.h \
  arch/arm/plat-omap/include/plat/omap24xx.h \
  arch/arm/plat-omap/include/plat/omap34xx.h \
  arch/arm/plat-omap/include/plat/omap44xx.h \
  arch/arm/plat-omap/include/plat/ti816x.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/dma-mapping.h \
  include/linux/dma-debug.h \
    $(wildcard include/config/dma/api/debug.h) \
  include/asm-generic/dma-coherent.h \
    $(wildcard include/config/have/generic/dma/coherent.h) \
  include/linux/hrtimer.h \
    $(wildcard include/config/high/res/timers.h) \
    $(wildcard include/config/timerfd.h) \
  include/linux/timerqueue.h \
  include/linux/if_packet.h \
  include/linux/if_link.h \
  include/linux/netlink.h \
  include/linux/capability.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/pm_qos_params.h \
  include/linux/pm_qos_params.h \
  include/linux/plist.h \
    $(wildcard include/config/debug/pi/list.h) \
  include/linux/miscdevice.h \
  include/linux/major.h \
  include/linux/delay.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/delay.h \
  include/linux/rculist.h \
  include/linux/ethtool.h \
  include/linux/compat.h \
    $(wildcard include/config/nfsd.h) \
    $(wildcard include/config/nfsd/deprecated.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/net/net_namespace.h \
  include/net/net_namespace.h \
    $(wildcard include/config/ipv6.h) \
    $(wildcard include/config/ip/dccp.h) \
    $(wildcard include/config/netfilter.h) \
    $(wildcard include/config/wext/core.h) \
  include/net/netns/core.h \
  include/net/netns/mib.h \
    $(wildcard include/config/xfrm/statistics.h) \
  include/net/snmp.h \
  include/linux/snmp.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/u64_stats_sync.h \
  include/net/netns/unix.h \
  include/net/netns/packet.h \
  include/net/netns/ipv4.h \
    $(wildcard include/config/ip/multiple/tables.h) \
    $(wildcard include/config/security.h) \
    $(wildcard include/config/ip/mroute.h) \
    $(wildcard include/config/ip/mroute/multiple/tables.h) \
  include/net/inet_frag.h \
  include/net/netns/ipv6.h \
    $(wildcard include/config/ipv6/multiple/tables.h) \
    $(wildcard include/config/ipv6/mroute.h) \
    $(wildcard include/config/ipv6/mroute/multiple/tables.h) \
  include/net/dst_ops.h \
  include/linux/percpu_counter.h \
  include/net/netns/dccp.h \
  include/net/netns/x_tables.h \
    $(wildcard include/config/bridge/nf/ebtables.h) \
  include/linux/netfilter.h \
    $(wildcard include/config/netfilter/debug.h) \
    $(wildcard include/config/nf/nat/needed.h) \
  include/linux/in.h \
  include/net/flow.h \
  include/linux/proc_fs.h \
    $(wildcard include/config/proc/devicetree.h) \
    $(wildcard include/config/proc/kcore.h) \
  include/linux/fs.h \
    $(wildcard include/config/quota.h) \
    $(wildcard include/config/fsnotify.h) \
    $(wildcard include/config/ima.h) \
    $(wildcard include/config/fs/posix/acl.h) \
    $(wildcard include/config/epoll.h) \
    $(wildcard include/config/debug/writecount.h) \
    $(wildcard include/config/file/locking.h) \
    $(wildcard include/config/auditsyscall.h) \
    $(wildcard include/config/block.h) \
    $(wildcard include/config/fs/xip.h) \
    $(wildcard include/config/migration.h) \
  include/linux/limits.h \
  include/linux/blk_types.h \
    $(wildcard include/config/blk/dev/integrity.h) \
  include/linux/kdev_t.h \
  include/linux/dcache.h \
  include/linux/rculist_bl.h \
  include/linux/list_bl.h \
  include/linux/path.h \
  include/linux/radix-tree.h \
  include/linux/pid.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/semaphore.h \
  include/linux/semaphore.h \
  include/linux/fiemap.h \
  include/linux/quota.h \
    $(wildcard include/config/quota/netlink/interface.h) \
  include/linux/dqblk_xfs.h \
  include/linux/dqblk_v1.h \
  include/linux/dqblk_v2.h \
  include/linux/dqblk_qtree.h \
  include/linux/nfs_fs_i.h \
  include/linux/nfs.h \
  include/linux/sunrpc/msg_prot.h \
  include/linux/inet.h \
  include/linux/magic.h \
  include/net/netns/conntrack.h \
  include/linux/list_nulls.h \
  include/net/netns/xfrm.h \
  include/linux/xfrm.h \
  include/linux/seq_file_net.h \
  include/linux/seq_file.h \
  include/net/dsa.h \
  include/linux/interrupt.h \
    $(wildcard include/config/irq/forced/threading.h) \
    $(wildcard include/config/generic/irq/probe.h) \
  include/linux/irqreturn.h \
  include/linux/hardirq.h \
    $(wildcard include/config/virt/cpu/accounting.h) \
    $(wildcard include/config/irq/time/accounting.h) \
  include/linux/ftrace_irq.h \
    $(wildcard include/config/ftrace/nmi/enter.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/hardirq.h \
    $(wildcard include/config/local/timers.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/irq.h \
  arch/arm/mach-omap2/include/mach/irqs.h \
  arch/arm/plat-omap/include/plat/irqs.h \
    $(wildcard include/config/mach/omap/innovator.h) \
    $(wildcard include/config/twl4030/core.h) \
    $(wildcard include/config/gpio/twl4030.h) \
    $(wildcard include/config/twl6040/codec.h) \
    $(wildcard include/config/fiq.h) \
  arch/arm/plat-omap/include/plat/irqs-44xx.h \
  include/linux/irq_cpustat.h \
  include/trace/events/irq.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.32.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.30.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.31.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.33.h \
    $(wildcard include/config/pccard.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.34.h \
    $(wildcard include/config/preempt/desktop.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.35.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.36.h \
    $(wildcard include/config/lock/kernel.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.37.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.38.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-2.6.39.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.0.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.1.h \
    $(wildcard include/config/booger.h) \
    $(wildcard include/config/foo.h) \
  include/linux/security.h \
    $(wildcard include/config/security/path.h) \
    $(wildcard include/config/security/network.h) \
    $(wildcard include/config/security/network/xfrm.h) \
    $(wildcard include/config/keys.h) \
    $(wildcard include/config/audit.h) \
    $(wildcard include/config/securityfs.h) \
  include/linux/fsnotify.h \
  include/linux/fsnotify_backend.h \
    $(wildcard include/config/inotify/user.h) \
    $(wildcard include/config/fanotify.h) \
    $(wildcard include/config/fanotify/access/permissions.h) \
  include/linux/idr.h \
  include/linux/audit.h \
    $(wildcard include/config/change.h) \
  include/linux/sched.h \
    $(wildcard include/config/sched/debug.h) \
    $(wildcard include/config/lockup/detector.h) \
    $(wildcard include/config/detect/hung/task.h) \
    $(wildcard include/config/core/dump/default/elf/headers.h) \
    $(wildcard include/config/sched/autogroup.h) \
    $(wildcard include/config/bsd/process/acct.h) \
    $(wildcard include/config/taskstats.h) \
    $(wildcard include/config/cgroups.h) \
    $(wildcard include/config/posix/mqueue.h) \
    $(wildcard include/config/perf/events.h) \
    $(wildcard include/config/schedstats.h) \
    $(wildcard include/config/task/delay/acct.h) \
    $(wildcard include/config/fair/group/sched.h) \
    $(wildcard include/config/rt/group/sched.h) \
    $(wildcard include/config/blk/dev/io/trace.h) \
    $(wildcard include/config/rcu/boost.h) \
    $(wildcard include/config/compat/brk.h) \
    $(wildcard include/config/cc/stackprotector.h) \
    $(wildcard include/config/sysvipc.h) \
    $(wildcard include/config/rt/mutexes.h) \
    $(wildcard include/config/task/xacct.h) \
    $(wildcard include/config/cpusets.h) \
    $(wildcard include/config/futex.h) \
    $(wildcard include/config/fault/injection.h) \
    $(wildcard include/config/latencytop.h) \
    $(wildcard include/config/have/unstable/sched/clock.h) \
    $(wildcard include/config/debug/stack/usage.h) \
    $(wildcard include/config/cgroup/sched.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/cputime.h \
  include/asm-generic/cputime.h \
  include/linux/sem.h \
  include/linux/ipc.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/ipcbuf.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/sembuf.h \
  include/linux/signal.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/signal.h \
  include/asm-generic/signal-defs.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/sigcontext.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/siginfo.h \
  include/asm-generic/siginfo.h \
  include/linux/proportions.h \
  include/linux/seccomp.h \
    $(wildcard include/config/seccomp.h) \
  include/linux/rtmutex.h \
    $(wildcard include/config/debug/rt/mutexes.h) \
  include/linux/resource.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/resource.h \
  include/asm-generic/resource.h \
  include/linux/task_io_accounting.h \
    $(wildcard include/config/task/io/accounting.h) \
  include/linux/latencytop.h \
  include/linux/cred.h \
    $(wildcard include/config/debug/credentials.h) \
    $(wildcard include/config/user/ns.h) \
  include/linux/key.h \
  include/linux/selinux.h \
    $(wildcard include/config/security/selinux.h) \
  include/linux/aio.h \
  include/linux/aio_abi.h \
  include/linux/binfmts.h \
  include/linux/shm.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/shmparam.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/shmbuf.h \
  include/linux/msg.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/msgbuf.h \
  include/net/ip.h \
    $(wildcard include/config/inet.h) \
  include/linux/ip.h \
  include/net/inet_sock.h \
  include/linux/jhash.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/unaligned/packed_struct.h \
  include/net/sock.h \
  include/linux/uaccess.h \
  include/linux/filter.h \
    $(wildcard include/config/bpf/jit.h) \
  include/linux/rculist_nulls.h \
  include/linux/poll.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/poll.h \
  include/asm-generic/poll.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/atomic.h \
  include/linux/atomic.h \
    $(wildcard include/config/arch/has/atomic/or.h) \
  include/net/dst.h \
    $(wildcard include/config/ip/route/classid.h) \
  include/linux/rtnetlink.h \
  include/linux/if_addr.h \
  include/linux/neighbour.h \
  include/net/neighbour.h \
  include/net/rtnetlink.h \
  include/net/netlink.h \
  include/net/request_sock.h \
  include/net/netns/hash.h \
  include/linux/ipv6.h \
    $(wildcard include/config/ipv6/privacy.h) \
    $(wildcard include/config/ipv6/router/pref.h) \
    $(wildcard include/config/ipv6/route/info.h) \
    $(wildcard include/config/ipv6/optimistic/dad.h) \
    $(wildcard include/config/ipv6/mip6.h) \
    $(wildcard include/config/ipv6/subtrees.h) \
  include/linux/icmpv6.h \
  include/linux/tcp.h \
    $(wildcard include/config/tcp/md5sig.h) \
  include/net/inet_connection_sock.h \
  include/net/inet_timewait_sock.h \
  include/net/tcp_states.h \
  include/net/timewait_sock.h \
  include/linux/udp.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.2.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.3.h \
  include/linux/pci_regs.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/nl80211.h \
  include/net/sch_generic.h \
  include/linux/pkt_sched.h \
  include/linux/pkt_cls.h \
    $(wildcard include/config/net/cls/ind.h) \
  include/net/gen_stats.h \
  include/linux/gen_stats.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.4.h \
    $(wildcard include/config/x86/x32/abi.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.5.h \
  include/linux/etherdevice.h \
    $(wildcard include/config/have/efficient/unaligned/access.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/unaligned.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/unaligned/le_byteshift.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/unaligned/be_byteshift.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/unaligned/generic.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/vga_switcheroo.h \
  include/linux/vga_switcheroo.h \
    $(wildcard include/config/vga/switcheroo.h) \
  include/linux/fb.h \
    $(wildcard include/config/fb/backlight.h) \
    $(wildcard include/config/fb/deferred/io.h) \
    $(wildcard include/config/fb/tileblitting.h) \
    $(wildcard include/config/fb/foreign/endian.h) \
    $(wildcard include/config/fb/both/endian.h) \
    $(wildcard include/config/fb/big/endian.h) \
    $(wildcard include/config/fb/little/endian.h) \
  include/linux/i2c.h \
    $(wildcard include/config/i2c.h) \
    $(wildcard include/config/i2c/boardinfo.h) \
  include/linux/mod_devicetable.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/of.h \
    $(wildcard include/config/of.h) \
  include/linux/of.h \
    $(wildcard include/config/of/dynamic.h) \
  include/linux/kgdb.h \
    $(wildcard include/config/have/arch/kgdb.h) \
    $(wildcard include/config/kgdb.h) \
  include/linux/serial_8250.h \
  include/linux/serial_core.h \
    $(wildcard include/config/console/poll.h) \
    $(wildcard include/config/type.h) \
    $(wildcard include/config/irq.h) \
    $(wildcard include/config/serial/core/console.h) \
    $(wildcard include/config/hard/pps.h) \
  include/linux/serial.h \
  include/linux/circ_buf.h \
  include/linux/tty.h \
  include/linux/termios.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/termios.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/termbits.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/ioctls.h \
  include/asm-generic/ioctls.h \
  include/linux/tty_driver.h \
  include/linux/cdev.h \
  include/linux/tty_ldisc.h \
  include/linux/pps_kernel.h \
    $(wildcard include/config/ntp/pps.h) \
  include/linux/pps.h \
  include/linux/sysrq.h \
    $(wildcard include/config/magic/sysrq.h) \
  include/linux/tty_flip.h \
  include/linux/platform_device.h \
    $(wildcard include/config/suspend.h) \
    $(wildcard include/config/hibernate/callbacks.h) \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/kgdb.h \
  include/linux/ptrace.h \
  include/linux/backlight.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.6.h \
  include/linux/usb.h \
    $(wildcard include/config/usb/devicefs.h) \
    $(wildcard include/config/usb/mon.h) \
    $(wildcard include/config/usb/device/class.h) \
    $(wildcard include/config/usb/suspend.h) \
  include/linux/usb/ch9.h \
    $(wildcard include/config/size.h) \
    $(wildcard include/config/att/one.h) \
    $(wildcard include/config/att/selfpower.h) \
    $(wildcard include/config/att/wakeup.h) \
    $(wildcard include/config/att/battery.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/pm_runtime.h \
  include/linux/pm_runtime.h \
    $(wildcard include/config/pm/runtime/clk.h) \
    $(wildcard include/config/have/clk.h) \
  include/net/genetlink.h \
  include/linux/genetlink.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/compat-3.7.h \
  include/linux/pci.h \
    $(wildcard include/config/pci/iov.h) \
    $(wildcard include/config/pcieaspm.h) \
    $(wildcard include/config/pci/msi.h) \
    $(wildcard include/config/pcieportbus.h) \
    $(wildcard include/config/pcieaer.h) \
    $(wildcard include/config/pcie/ecrc.h) \
    $(wildcard include/config/ht/irq.h) \
    $(wildcard include/config/pci/domains.h) \
    $(wildcard include/config/pci/quirks.h) \
    $(wildcard include/config/pci/mmconfig.h) \
    $(wildcard include/config/hotplug/pci.h) \
  include/linux/io.h \
    $(wildcard include/config/has/ioport.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/pci_ids.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/pci.h \
    $(wildcard include/config/pci/host/ite8152.h) \
  include/asm-generic/pci-dma-compat.h \
  /home/owner/android-wmon/core/galaxynexus-cm10-kernel/arch/arm/include/asm/mach/pci.h \
  drivers/net/wireless/bcmdhd/include/typedefs.h \
  drivers/net/wireless/bcmdhd/include/bcmdefs.h \
  drivers/net/wireless/bcmdhd/include/bcmdevs.h \
  drivers/net/wireless/bcmdhd/include/bcmendian.h \
  drivers/net/wireless/bcmdhd/include/bcmutils.h \
  drivers/net/wireless/bcmdhd/include/osl.h \
  drivers/net/wireless/bcmdhd/include/linux_osl.h \
  drivers/net/wireless/bcmdhd/include/bcmsdh.h \
  drivers/net/wireless/bcmdhd/include/linuxver.h \
    $(wildcard include/config/net/radio.h) \
    $(wildcard include/config/rfkill/input.h) \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/net/lib80211.h \
  /home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/include/linux/ieee80211.h \
  drivers/net/wireless/bcmdhd/include/sdio.h \
  drivers/net/wireless/bcmdhd/include/sdioh.h \
  drivers/net/wireless/bcmdhd/include/bcmsdbus.h \
  drivers/net/wireless/bcmdhd/include/sdiovar.h \
  drivers/net/wireless/bcmdhd/include/packed_section_start.h \
  drivers/net/wireless/bcmdhd/include/packed_section_end.h \
  include/linux/mmc/core.h \
  include/linux/mmc/card.h \
  include/linux/mmc/sdio_func.h \
  include/linux/mmc/pm.h \
  include/linux/mmc/sdio_ids.h \
  drivers/net/wireless/bcmdhd/dngl_stats.h \
  drivers/net/wireless/bcmdhd/dhd.h \
    $(wildcard include/config/has/wakelock.h) \
  include/linux/wakelock.h \
    $(wildcard include/config/wakelock/stat.h) \
  drivers/net/wireless/bcmdhd/include/wlioctl.h \
    $(wildcard include/config/item.h) \
    $(wildcard include/config/usbrndis/retail.h) \
  drivers/net/wireless/bcmdhd/include/proto/ethernet.h \
  drivers/net/wireless/bcmdhd/include/proto/bcmeth.h \
  drivers/net/wireless/bcmdhd/include/proto/bcmevent.h \
  drivers/net/wireless/bcmdhd/include/proto/802.11.h \
  drivers/net/wireless/bcmdhd/include/proto/wpa.h \
  drivers/net/wireless/bcmdhd/include/bcmwifi.h \
  drivers/net/wireless/bcmdhd/include/bcmcdc.h \
  include/linux/suspend.h \
    $(wildcard include/config/vt.h) \
    $(wildcard include/config/vt/console.h) \
  include/linux/swap.h \
    $(wildcard include/config/cgroup/mem/res/ctlr/swap.h) \
  include/linux/memcontrol.h \
    $(wildcard include/config/cgroup/mem/cont.h) \
  include/linux/cgroup.h \
  include/linux/cgroupstats.h \
  include/linux/taskstats.h \
  include/linux/prio_heap.h \
  include/linux/cgroup_subsys.h \
    $(wildcard include/config/cgroup/debug.h) \
    $(wildcard include/config/cgroup/cpuacct.h) \
    $(wildcard include/config/cgroup/device.h) \
    $(wildcard include/config/cgroup/freezer.h) \
    $(wildcard include/config/net/cls/cgroup.h) \
    $(wildcard include/config/blk/cgroup.h) \
    $(wildcard include/config/cgroup/perf.h) \
  include/linux/node.h \
    $(wildcard include/config/memory/hotplug/sparse.h) \
  include/linux/sysdev.h \
  drivers/net/wireless/bcmdhd/include/bcmsdh_sdmmc.h \

/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o: $(deps_/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o)

$(deps_/home/owner/android-wmon/core/compat-wireless-3.6-rc7-1/drivers/net/wireless/bcmdhd/bcmsdh_sdmmc.o):
