#!/bin/bash

platform=$(./tools/android list sdk | grep "SDK Platform Android" | head -n 1 | awk -F'-' '{print $1}' | sed 's/^ *//g')
gapis=$(./tools/android list sdk | grep "Google APIs" | head -n 1 | awk -F'-' '{print $1}' | sed 's/^ *//g')

tools/android update sdk --no-ui --filter 1,2,$platform,$gapis
