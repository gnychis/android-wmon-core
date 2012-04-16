#!/bin/bash

platform=$(./tools/android list sdk | grep "SDK Platform Android 4.0.3, API 15" | awk -F'-' '{print $1}')
gapis=$(./tools/android list sdk | grep "Google APIs, Android API 15" | awk -F'-' '{print $1}')

tools/android update sdk --no-ui --filter 1,2,$platform,$gapis
