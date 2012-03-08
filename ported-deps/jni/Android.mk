LOCAL_PATH := $(call my-dir)
subdirs := $(addprefix $(LOCAL_PATH)/,$(addsuffix /Android.mk, \
	libgpg-error \
	libgcrypt \
	libnl \
	libpcap \
	libglib \
))
include $(subdirs)
