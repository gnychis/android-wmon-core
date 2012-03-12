#!/bin/bash
#
# $Id: win64-setup.sh 36616 2011-04-13 04:47:38Z etxrab $

# 64-bit wrapper for win-setup.sh.

export DOWNLOAD_TAG="2011-04-13"
export WIRESHARK_TARGET_PLATFORM="win64"

WIN_SETUP=`echo $0 | sed -e s/win64/win/`

exec $WIN_SETUP $@
