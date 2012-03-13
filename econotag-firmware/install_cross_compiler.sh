#!/bin/bash
wget http://www.codesourcery.com/sgpp/lite/arm/portal/package3688/public/arm-none-eabi/arm-2008q3-66-arm-none-eabi.bin

echo ""
echo "--------------------------"
echo " Choose Minimal Install"
echo "--------------------------"
echo ""

sh arm-2008q3-66-arm-none-eabi.bin

echo ""
echo "--------------------------"
echo " Do not forget to update PATH with /your/path/to/CodeSourcery/Sourcery_G++_Lite/bin"
echo "--------------------------"
echo ""
