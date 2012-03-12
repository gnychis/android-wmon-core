$Id: README.txt 23484 2007-11-18 10:20:26Z gal $

U3
==

What is U3? See http://en.wikipedia.org/wiki/U3 and http://www.u3.com

U3 Packaging
============

This directory contains the scripts to build a U3 Package (wireshark.u3p) that can be loaded onto a U3 device. This will allow Wireshark to be run from any Windows machine the U3 device is plugged into, without having to install Wireshark directly. For more details about U3 devices, see http://www.u3.com/.

The U3 package is basically a zip file with a manifest file (wireshark.u3i), a small utility to manage the shutdown of Wireshark when the device is removed, and the Wireshark application files. The package contains all the standard Wireshark components (e.g. tshark.exe), even though they cannot be directly accessed. However, with a suitable additional script (setting the U3 environment variables), the would meet the "wireshark-as-a-zip" wish.

You will need the cygwin zip archive package to build the package itself. Once you have the package you can load the package using "Add Programs"/"Install from My Computer" from the U3 LaunchPad.

A few minor changes have been made to Wireshark itself:
1) Wireshark will write a <pid>.pid file while running. This allows the utility to close down Wireshark when the device is removed.
2) filesystem.c has been changed to take advantage of the U3 "datafile_dir" and "persconffile_dir". Personal settings are then stored on the device.
3) The files in the 'recent' file are written in a form that allows the U3 device path to change.

There is a [self-]certification process for U3 packages which could be undertaken if there is sufficient interest for this package format. Wireshark could then be placed on Software Central - http://software.u3.com/SoftwareCentral.aspx?skip=1.

UPX
===

If the Ultimate Packer for eXecutables (UPX) (http://upx.sourceforge.net) is downloaded and configured in config.nmake, the packaging process will pack all of the dll and exes before putting them into the U3 pacakage. This can significantly reduce the size of the U3 package - by about 40%.

Known Issues:
=============

1) The U3 package tries to install WinPcap if it is not already installed when it is first run. It will be automatically removed when the device is removed. But this is not the best approach.
2) The distribution of the files across the U3 host and U3 device needs to be verified for all protocols.
3) The list of files should be derived from a common source (e.g. nsis/wireshark.nsi)
4) Wireshark does not close down cleanly when a dialog is up.
5) If Wireshark is uninstalled from the U3 stick, all personal settings are gone. This is unlike the "normal" WS package, but seems to be common for U3 programs.